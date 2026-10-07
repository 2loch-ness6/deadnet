"""
DeadNet engine — U5: discovery producers (Scan & Select engine side).

Populates the known_scents master store (``DB_KNOWN_SCENTS``) via the
Arbiter (U2 / ``RowReaderArbiter``). Two producers:

  * ``Finder``     — one-shot phased scan: P1_SMELL (cheap subnet inventory,
    the important phase), P2_FINGERPRINT (optional SYN-scan enrichment,
    delegated to the U10 portscan module if present), P3_SMART_X (stub).
  * ``NetFetcher`` — background "Mac-Vacuum": periodically re-reads the
    kernel neighbour table (+ a light re-ping of already-known hosts) to
    keep known_scents fresh as DHCP leases rotate. Can be scoped to a set
    of networks-of-interest via ``set_focus_nets`` for cheap focused
    rediscovery.

All privileged reads go through ``su -c "<cmd>"`` (matches
``apk/engine/iface.py``'s ``_su`` pattern). The record-extraction logic is a
pure function, ``parse_neigh_table``, so it is unit-testable without a
device.

Stdlib only: threading, ipaddress, time, re. Privileged shell-outs go through
the shared persistent root shell (engine.rootshell) — one su for the whole app.
"""
from __future__ import annotations

import os
import re
import sys
import time
import threading
import ipaddress
from typing import Callable, List, Optional, Sequence, Tuple

# Make `import engine.*` work whether this module is imported as part of the
# app (apk/ already on sys.path per CONTRACTS.md) or run standalone as
# `python3 engine/finder.py` from inside apk/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.contracts import (  # noqa: E402
    ScentRecord, NetInfo, ScanPhase, DB_KNOWN_SCENTS, now_ms,
)
from engine import rootshell as _root  # noqa: E402  (one persistent su)
from engine import oui as _oui  # noqa: E402

try:
    from kivy.logger import Logger
except Exception:  # pragma: no cover - off-device / bare test env
    class _StubLogger:
        def info(self, *a, **k):
            pass

        def error(self, *a, **k):
            pass

        def warning(self, *a, **k):
            pass

    Logger = _StubLogger()

DEADNET_PREF = "DeadNet"


def _log(msg: str) -> None:
    Logger.info(f"{DEADNET_PREF}: finder: {msg}")


# ----------------------------------------------------------------------------
# Privileged shell-out (matches apk/utils/net_utils.py / engine/iface.py's su
# pattern). Kept private to this unit per CONTRACTS.md rule #5.
# ----------------------------------------------------------------------------
def _su(cmd: str, timeout: float = 5.0) -> str:
    """Run `cmd` as root through the shared PERSISTENT root shell (one su for
    the whole app — no per-call su fork). Returns merged stdout+stderr, or ""
    on failure/timeout (rc == -1)."""
    rc, out = _root.su_rc(cmd, timeout)
    if rc != 0 and not out:
        Logger.error(f"{DEADNET_PREF}: finder._su rc={rc} for {cmd!r}")
    return out


# ----------------------------------------------------------------------------
# Pure parser — no I/O, unit-testable without a device
# ----------------------------------------------------------------------------
_MAC_RE = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_LLADDR_RE = re.compile(rf"lladdr\s+({_MAC_RE})")


def parse_neigh_table(
    text: str,
    net_id: str = "",
    oui_classify: Optional[Callable[[str], str]] = None,
) -> List[ScentRecord]:
    """Parse `ip neigh show ...` output into ScentRecords.

    Only lines with a resolved `lladdr <mac>` become records — FAILED and
    INCOMPLETE entries (no lladdr, or `lladdr` present but with nothing
    after it) are skipped, matching the kernel's own "unresolved" states.

    Pure function: no subprocess calls, no Arbiter writes. `oui_classify`
    defaults to a lambda returning "" so this is usable with no device and
    no oui.csv present.
    """
    if oui_classify is None:
        oui_classify = lambda _mac: ""  # noqa: E731

    records: List[ScentRecord] = []
    ts = now_ms()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        ip = parts[0]
        mac_m = _LLADDR_RE.search(line)
        if not mac_m:
            continue  # FAILED, or INCOMPLETE/empty lladdr
        mac = mac_m.group(1).lower()
        records.append(
            ScentRecord(
                mac=mac,
                ip=ip,
                vendor=oui_classify(mac),
                is_station=True,
                net_id=net_id,
                first_seen_ms=ts,
                last_seen_ms=ts,
            )
        )
    return records


# ----------------------------------------------------------------------------
# Arbiter write helper — shared by Finder and NetFetcher
# ----------------------------------------------------------------------------
def upsert_scent(arbiter, rec: ScentRecord) -> None:
    """INSERT ... ON CONFLICT(mac) DO UPDATE the given ScentRecord into
    known_scents. Refreshes ip/vendor/net_id/is_station/last_seen/lease on
    conflict; preserves the original first_seen_ms."""
    arbiter.write(
        DB_KNOWN_SCENTS,
        """
        INSERT INTO scents(mac, ip, vendor, ssid, ap_bssid, channel, signal_dbm,
                            is_station, net_id, first_seen_ms, last_seen_ms,
                            lease_expiry_ms)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(mac) DO UPDATE SET
            ip=excluded.ip,
            vendor=excluded.vendor,
            is_station=excluded.is_station,
            net_id=excluded.net_id,
            last_seen_ms=excluded.last_seen_ms,
            lease_expiry_ms=excluded.lease_expiry_ms
        """,
        (
            rec.mac, rec.ip, rec.vendor, rec.ssid, rec.ap_bssid, rec.channel,
            rec.signal_dbm, 1 if rec.is_station else 0, rec.net_id,
            rec.first_seen_ms, rec.last_seen_ms, rec.lease_expiry_ms,
        ),
    )


# ----------------------------------------------------------------------------
# Finder — one-shot phased scan
# ----------------------------------------------------------------------------
class Finder:
    """Phased discovery producer for one seized/associated card.

    `net` is this card's NetInfo (from U1's `discover_iface_net`). All
    writes go through the Arbiter into DB_KNOWN_SCENTS.
    """

    # Smaller chunks = more progress ticks so the n/254 counter visibly climbs.
    # Each chunk is still ONE su round-trip (its hosts ping in parallel), so this
    # does NOT bring back the per-host su-fork storm — it just reports finer.
    PING_CHUNK = 16            # hosts pinged in parallel per su round-trip
    PING_CHUNK_TIMEOUT = 8.0   # seconds to let one chunk's pings finish

    def __init__(self, arbiter, iface: str, net: NetInfo, on_progress=None):
        self.arbiter = arbiter
        self.iface = iface
        self.net = net
        self.on_progress = on_progress

    # -------------------------------------------------------------- helpers
    def _progress(self, phase: ScanPhase, done: int, total: int) -> None:
        if self.on_progress is None:
            return
        try:
            self.on_progress(phase, done, total)
        except Exception as exc:  # noqa: BLE001 - progress cb must never kill a scan
            _log(f"on_progress callback raised: {exc}")

    def _subnet_targets(self) -> List[str]:
        """Hosts to probe: every address in net.subnet_cidr except the
        network/broadcast addresses, our own device_ip, and the gateway."""
        if not self.net.subnet_cidr:
            return []
        try:
            network = ipaddress.ip_network(self.net.subnet_cidr, strict=False)
        except ValueError as exc:
            _log(f"bad subnet_cidr {self.net.subnet_cidr!r}: {exc}")
            return []

        skip = {self.net.device_ip, self.net.gateway_ipv4,
                str(network.network_address), str(network.broadcast_address)}
        return [str(h) for h in network.hosts() if str(h) not in skip]

    def _read_neigh(self) -> str:
        return _su(f"ip neigh show dev {self.iface}")

    def _upsert_all(self, records: Sequence[ScentRecord]) -> None:
        for rec in records:
            try:
                upsert_scent(self.arbiter, rec)
            except Exception as exc:  # noqa: BLE001
                _log(f"upsert failed for {rec.mac}: {exc}")

    # --------------------------------------------------------------- phases
    def phase1_smell(self) -> List[ScentRecord]:
        """Signal smelling: cheap full inventory of the connected subnet.

        1. Seed from the existing ARP/ND cache (`ip neigh`).
        2. Prime the cache by pinging every host on the subnet, batched through
           the PERSISTENT root shell: each chunk is ONE round-trip that pings
           its whole batch in parallel (`ping -c1 -W1 & ... wait`). No per-host
           su fork — the old 254×`su -c` storm was the "massive overhead".
        3. Re-read `ip neigh` and upsert everything learned.
        """
        # Step 1: seed from whatever the kernel already knows.
        seed_records = parse_neigh_table(self._read_neigh(), self.net.iface, _oui.classify)
        self._upsert_all(seed_records)

        targets = self._subnet_targets()
        total = len(targets) + 1  # +1 for the final re-read/upsert step
        self._progress(ScanPhase.P1_SMELL, 0, max(total, 1))

        # Step 2: batched ping sweep through the one su (chunked for a smooth
        # progress bar; each chunk pings in parallel inside a single round-trip).
        done = 0
        for i in range(0, len(targets), self.PING_CHUNK):
            batch = targets[i:i + self.PING_CHUNK]
            _root.ping_sweep(batch, chunk=len(batch), timeout=self.PING_CHUNK_TIMEOUT)
            done += len(batch)
            self._progress(ScanPhase.P1_SMELL, done, total)

        # Step 3: re-read the now-primed neigh table, upsert everything.
        final_records = parse_neigh_table(self._read_neigh(), self.net.iface, _oui.classify)
        self._upsert_all(final_records)
        self._progress(ScanPhase.P1_SMELL, total, total)

        _log(f"phase1_smell: {len(final_records)} electronics on {self.net.subnet_cidr}")
        return final_records

    def _fingerprint_targets(self, macs: Optional[Sequence[str]]) -> List[Tuple[str, str]]:
        rows = self.arbiter.read(
            DB_KNOWN_SCENTS, "SELECT mac, ip FROM scents WHERE net_id=?", (self.net.iface,)
        )
        if macs is not None:
            want = {m.lower() for m in macs}
            rows = [r for r in rows if r[0].lower() in want]
        return [(r[0], r[1]) for r in rows if r[1]]

    def phase2_fingerprint(self, macs: Optional[Sequence[str]] = None) -> None:
        """Optional enrichment: delegates to the U10 portscan module's
        `syn_scan` if it is importable. This unit stands alone without it."""
        try:
            from engine.portscan import syn_scan  # type: ignore
        except Exception as exc:  # ImportError or anything else U10 might raise
            _log(f"P2 unavailable ({exc}); skipping fingerprint phase")
            return

        targets = self._fingerprint_targets(macs)
        total = len(targets)
        self._progress(ScanPhase.P2_FINGERPRINT, 0, max(total, 1))
        for i, (mac, ip) in enumerate(targets, start=1):
            try:
                result = syn_scan(ip)
                _log(f"P2 syn_scan({ip}) [{mac}] -> {result}")
            except Exception as exc:  # noqa: BLE001
                _log(f"P2 syn_scan failed for {ip} [{mac}]: {exc}")
            self._progress(ScanPhase.P2_FINGERPRINT, i, total)

    def phase3_smart_x(self) -> None:
        """STUB — owner-supplied smart-X scan. Not yet implemented."""
        _log("P3 smart-X scan not yet implemented (owner-supplied)")
        return

    # ----------------------------------------------------------------- run
    def run(self, up_to_phase: ScanPhase = ScanPhase.P1_SMELL) -> None:
        """Run phases serially up to (and including) `up_to_phase`."""
        self.phase1_smell()
        if up_to_phase >= ScanPhase.P2_FINGERPRINT:
            self.phase2_fingerprint()
        if up_to_phase >= ScanPhase.P3_SMART_X:
            self.phase3_smart_x()


# ----------------------------------------------------------------------------
# NetFetcher — background "Mac-Vacuum" subnet observer
# ----------------------------------------------------------------------------
class NetFetcher:
    """Background thread that keeps known_scents fresh for one net/iface.

    Every `interval_ms`, lightly re-pings the hosts already known for this
    net (not a full subnet sweep — that's Finder's job) and re-reads
    `ip neigh`, upserting whatever is learned. `set_focus_nets` can scope
    the whole tick on/off depending on whether this NetFetcher's net is
    currently "in focus" (cheap focused rediscovery across many net/iface
    instances sharing one BirdObserver-driven focus set).
    """

    def __init__(self, arbiter, iface: str, net: NetInfo, interval_ms: int):
        self.arbiter = arbiter
        self.iface = iface
        self.net = net
        self.interval_ms = interval_ms

        self._lock = threading.Lock()
        self._focus_nets: Optional[set] = None  # None = unrestricted (always run)
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------- control
    def set_focus_nets(self, net_ids: Optional[Sequence[str]]) -> None:
        """Restrict ticks to when self.net.iface is in `net_ids`. None/empty
        clears the restriction (always run)."""
        with self._lock:
            self._focus_nets = set(net_ids) if net_ids else None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_evt.clear()
            self._thread = threading.Thread(
                target=self._loop, name=f"netfetcher-{self.iface}", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        t = self._thread
        if t is not None:
            t.join(timeout=5.0)

    # --------------------------------------------------------------- loop
    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self._tick()
            except Exception as exc:  # noqa: BLE001 - never raise out of the loop
                _log(f"NetFetcher tick failed: {exc}")
            self._stop_evt.wait(max(self.interval_ms, 0) / 1000.0)

    def _in_focus(self) -> bool:
        with self._lock:
            focus = self._focus_nets
        return focus is None or self.net.iface in focus

    def _known_ips(self) -> List[str]:
        rows = self.arbiter.read(
            DB_KNOWN_SCENTS,
            "SELECT ip FROM scents WHERE net_id=? AND ip != ''",
            (self.net.iface,),
        )
        return [r[0] for r in rows]

    def _tick(self) -> None:
        if not self._in_focus():
            return  # this net isn't in the focus set this cycle; skip entirely

        # Light re-ping of KNOWN hosts only (not a subnet sweep), batched into
        # ONE persistent-shell round-trip instead of one su per host — this
        # loop ran every mac_vacuum_interval_ms (default 1s), so per-host su
        # forks here were a steady background drain.
        _root.ping_sweep(self._known_ips(), chunk=64, timeout=6.0)

        # Re-read the neigh table and refresh last_seen/ip/lease fields.
        records = parse_neigh_table(_su(f"ip neigh show dev {self.iface}"),
                                     self.net.iface, _oui.classify)
        for rec in records:
            try:
                upsert_scent(self.arbiter, rec)
            except Exception as exc:  # noqa: BLE001
                _log(f"NetFetcher upsert failed for {rec.mac}: {exc}")


# ===========================================================================
# Self-test (no device / no root). cd apk && python3 engine/finder.py
# ===========================================================================
_SAMPLE_NEIGH = """\
192.168.1.6 lladdr 24:3f:75:10:ae:1b STALE
192.168.1.1 lladdr 7c:db:98:64:54:9d REACHABLE
192.168.1.105  FAILED
192.168.1.77 lladdr  INCOMPLETE
"""


def _fake_classify(mac: str) -> str:
    return {
        "24:3f:75:10:ae:1b": "VendorA",
        "7c:db:98:64:54:9d": "VendorB",
    }.get(mac, "")


def _self_test() -> None:
    import tempfile

    # 1. parse_neigh_table: only lladdr-bearing entries become ScentRecords.
    records = parse_neigh_table(_SAMPLE_NEIGH, net_id="wlan0", oui_classify=_fake_classify)
    assert len(records) == 2, f"expected 2 records, got {len(records)}: {records}"

    by_mac = {r.mac: r for r in records}
    assert set(by_mac) == {"24:3f:75:10:ae:1b", "7c:db:98:64:54:9d"}, by_mac

    stale = by_mac["24:3f:75:10:ae:1b"]
    assert stale.ip == "192.168.1.6", stale
    assert stale.vendor == "VendorA", stale
    assert stale.net_id == "wlan0", stale
    assert stale.is_station is True, stale

    reachable = by_mac["7c:db:98:64:54:9d"]
    assert reachable.ip == "192.168.1.1", reachable
    assert reachable.vendor == "VendorB", reachable

    # FAILED (no lladdr at all) and INCOMPLETE (lladdr token present but no
    # mac value) must both be skipped.
    assert "192.168.1.105" not in {r.ip for r in records}
    assert "192.168.1.77" not in {r.ip for r in records}
    print("  [1] parse_neigh_table: 2 of 4 lines kept, FAILED/INCOMPLETE skipped  ok")

    # Default classifier (no oui table) must not blow up and returns "".
    default_records = parse_neigh_table(_SAMPLE_NEIGH, net_id="wlan0")
    assert all(r.vendor == "" for r in default_records), default_records
    print("  [2] default oui_classify (no device/table) -> vendor=''  ok")

    # 2. Arbiter round-trip: upsert, read back, and verify a second upsert
    #    of the same mac with a new ip UPDATES rather than duplicating.
    from engine.arbiter import RowReaderArbiter

    tmp = tempfile.mkdtemp(prefix="finder_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    try:
        for rec in records:
            upsert_scent(arb, rec)

        rows = arb.read(DB_KNOWN_SCENTS, "SELECT mac, ip, vendor FROM scents ORDER BY mac")
        assert len(rows) == 2, rows
        print(f"  [3] upserted {len(rows)} ScentRecords into known_scents  ok")

        moved = ScentRecord(
            mac="24:3f:75:10:ae:1b", ip="192.168.1.200", vendor="VendorA",
            net_id="wlan0", first_seen_ms=now_ms(), last_seen_ms=now_ms(),
        )
        upsert_scent(arb, moved)

        rows2 = arb.read(DB_KNOWN_SCENTS, "SELECT mac, ip FROM scents ORDER BY mac")
        assert len(rows2) == 2, f"expected still 2 rows after re-upsert, got {rows2}"
        ip_by_mac = dict(rows2)
        assert ip_by_mac["24:3f:75:10:ae:1b"] == "192.168.1.200", ip_by_mac
        print("  [4] re-upsert of same mac with new ip UPDATED, no duplicate  ok")
    finally:
        arb.close()
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass

    print("U5 PASS")


if __name__ == "__main__":
    _self_test()
