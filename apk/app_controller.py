"""
AppController — the brain behind the 2-preset single-radio UI. Bridges the Kivy
screens to the engine layer (arbiter / radio / finders / emission / birdobserver)
and enforces the single-radio lifecycle so the two presets can never fight over
the one RF chain.

Two presets (owner-confirmed, single internal radio on phy0):
  * RECON & RECORD  -> radio in MONITOR (via RadioController), FinderAir sniffs
    802.11 off mon0 into known_scents while it channel-hops. Passive discovery.
  * LOCK & LEVEL    -> radio handed back to Android + associated (MANAGED), a wired
    Finder smells the subnet into known_scents; owner selects targets; FIRE launches
    the native emitter (focused ARP/RA poison) with the BirdObserver airborne and the
    100 ms rehydrator feeding the survival gauges.

Release-back to Android is guaranteed by RadioController (atexit + signals); this
controller additionally tears everything down on `shutdown()`.

Headless-safe: the Kivy Logger import is guarded and every device call is funnelled
through the engine modules, so this file imports and its state machine self-tests
off-device. Stdlib + engine only.
"""
from __future__ import annotations

import enum
import threading
from typing import Callable, List, Optional

try:
    from kivy.logger import Logger
except Exception:  # off-device
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

from engine.contracts import (
    DB_KNOWN_SCENTS, DB_ATTENTION, DB_STATE,
    Knobs, EmitMode, ScanPhase, CardState,
    NetInfo, AttentionEntry, now_ms,
)
from engine.arbiter import RowReaderArbiter
from engine.radio import RadioController
from engine.toolbroker import ToolBroker

DEADNET_PREF = "DeadNet"


class Preset(enum.Enum):
    NONE = "none"
    RECON = "recon"          # Recon & Record
    LOCK = "lock"            # Lock & Level


class Mode(enum.Enum):
    IDLE = "idle"            # radio with Android, nothing running
    RECON = "recon"          # monitor + FinderAir
    LOCKED = "locked"        # managed + wired Finder, ready to fire
    FIRING = "firing"        # emitter airborne


class AppController:
    def __init__(self, appdir: str, managed_iface: str = "wlan0",
                 on_event: Optional[Callable[[str, dict], None]] = None):
        self.appdir = appdir
        self.managed_iface = managed_iface
        self._emit = on_event or (lambda kind, data: None)

        self.knobs = Knobs()
        self.preset = Preset.NONE
        self.mode = Mode.IDLE
        self.net: Optional[NetInfo] = None

        # Detect→Select→Connect flow state: routers the owner picked (max 2)
        # from the monitor smell, and the dual-STA ("ADHD") request flag.
        self.target_aps: List[str] = []     # selected AP BSSIDs
        self.adhd: bool = False             # True => request a 2nd STA link
        self.links: dict = {}               # post-connect link summary

        self.arbiter = RowReaderArbiter(appdir)
        self.radio = RadioController(managed_iface)
        self.toolbroker = ToolBroker(appdir)

        # lazily-built engine services (device-touching)
        self._finder_air = None
        self._finder = None
        self._netfetcher = None
        self._emission = None
        self._rsm = None
        self._bird = None

        self._lock = threading.RLock()

    # -- event helper -------------------------------------------------------
    def emit(self, kind: str, **data) -> None:
        try:
            self._emit(kind, data)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: on_event({kind}) raised {exc}")

    # -- capability snapshot (for §1 Detect & Connect) ----------------------
    def capabilities(self) -> dict:
        caps = self.toolbroker.capabilities()
        return {
            "state": self.radio.state.value,
            "associated": self.radio.is_associated(),
            "tools": {k: bool(v) for k, v in caps.items()},
            "magisk": self.toolbroker.magisk_module_installed(),
        }

    # =======================================================================
    # DETECT & SELECT  (phase 1: seize radio -> monitor -> smell ROUTERS)
    # =======================================================================
    def detect_and_select(self, hop_both_bands: bool = True) -> bool:
        """Owner hits 'Detect & Select': take the radio into monitor and
        channel-hop across 2.4+5 GHz so FinderAir smells every ROUTER in the
        air. Routers are offered via routers(); the owner picks 1-2 before any
        focused electronic-smelling happens (that waits for connect())."""
        chans = [1, 6, 11] + ([36, 40, 44, 149, 157] if hop_both_bands else [])
        ok = self.start_recon(channel=chans[0], hop=False)
        if not ok:
            return False
        # wide hop so we see routers on both bands, not just the social 2.4 set
        self.radio.start_hopping(
            channels=chans,
            dwell_s=max(0.15, self.knobs.finder_air_hop_dwell_ms / 1000.0))
        self.emit("detecting")
        return True

    def routers(self) -> List[dict]:
        """APs smelled during Detect & Select (is_station=0, named SSID),
        strongest signal first — the selectable target list."""
        aps = [s for s in self.scents()
               if not s.get("is_station") and (s.get("ssid") or "").strip()]
        aps.sort(key=lambda s: (s.get("signal_dbm") or -999), reverse=True)
        return aps

    def select_ap(self, bssid: str) -> bool:
        """Pick a router as an attack target. Capped at 2 (double-guns/ADHD)."""
        bssid = (bssid or "").lower()
        if bssid in self.target_aps:
            return True
        if len(self.target_aps) >= 2:
            self.emit("error", msg="at most 2 networks (double-guns / ADHD)")
            return False
        self.target_aps.append(bssid)
        self.emit("ap_selected", bssid=bssid, count=len(self.target_aps))
        return True

    def deselect_ap(self, bssid: str) -> None:
        bssid = (bssid or "").lower()
        if bssid in self.target_aps:
            self.target_aps.remove(bssid)
            self.emit("ap_selected", bssid=bssid, count=len(self.target_aps))

    def clear_aps(self) -> None:
        self.target_aps = []
        self.emit("ap_selected", bssid="", count=0)

    def selected_routers(self) -> List[dict]:
        """Full scent rows for the currently-picked target BSSIDs."""
        by_bssid = {s.get("mac"): s for s in self.routers()}
        return [by_bssid[b] for b in self.target_aps if b in by_bssid]

    # =======================================================================
    # CONNECT  (phase 2: release monitor -> associate -> focused smelling)
    # =======================================================================
    def connect(self, adhd: Optional[bool] = None) -> bool:
        """Transition Detect->Attack. Releases the monitor, hands wlan0 back so
        it re-associates to the network the owner joined in Android, scopes the
        focused electronic-smelling to that subnet, and (if ADHD / 2 targets and
        allowed) requests a 2nd STA. Empirical constraint: a monitor cannot run
        beside the associated link, so smelling here is subnet/ARP-based, phased
        after association — never a parallel monitor vif."""
        with self._lock:
            self.adhd = self.adhd if adhd is None else bool(adhd)
            # tear down the discovery monitor first (mon+managed can't coexist)
            if self.mode == Mode.RECON:
                self._stop_recon()
            # best-effort: permit the 2nd STA before association if ADHD wanted
            want_second = self.adhd and len(self.target_aps) >= 2
            if want_second:
                try:
                    self.radio.set_dual_sta(True)
                except Exception:  # noqa: BLE001
                    pass
            if not self.radio.ensure_managed():
                self.emit("error", msg="radio did not associate")
                return False
            from engine.iface import discover_iface_net
            try:
                self.net = discover_iface_net(self.managed_iface)
            except Exception as exc:  # noqa: BLE001
                self.emit("error", msg=f"net discovery failed: {exc}")
                return False
            self._start_wired_finder()
            self.links = self._link_summary(want_second)
            self.preset = Preset.LOCK
            self.mode = Mode.LOCKED
            self.emit("connected", links=self.links, net=self._net_summary())
            self.emit("mode", mode=self.mode.value, preset=self.preset.value,
                      net=self._net_summary())
            return True

    def _link_summary(self, wanted_second: bool) -> dict:
        """Describe the associated link(s) and which mode we actually got."""
        ssid = self.radio.current_ssid()
        bssid = self.radio.is_associated() or ""
        second = self.radio.secondary_iface()
        if second is not None:
            mode = "adhd" if wanted_second else "double_guns"
        else:
            mode = "single"
        return {
            "wlan0": {"ssid": ssid, "bssid": bssid},
            "wlan1": ({"iface": second} if second else None),
            "mode": mode,
            "wanted_second": wanted_second,
        }

    # =======================================================================
    # PRESET: RECON & RECORD  (monitor discovery)
    # =======================================================================
    def start_recon(self, channel: int = 6, hop: bool = True) -> bool:
        with self._lock:
            if self.mode == Mode.FIRING:
                self.cease()
            if self.mode == Mode.LOCKED:
                self._stop_wired_finder()
            if not self.radio.start_recon(channel):
                self.emit("error", msg="could not seize radio into monitor")
                return False
            if hop:
                dwell = max(0.05, self.knobs.finder_air_hop_dwell_ms / 1000.0)
                self.radio.start_hopping(dwell_s=dwell)
            # FinderAir sniffs mon0 into known_scents
            from engine.finder_air import FinderAir
            self._finder_air = FinderAir(
                self.arbiter, self.radio.mon_iface, net_id="air",
                on_scent=lambda rec: self.emit("scent", mac=rec.mac))
            self._finder_air.start()
            self.preset = Preset.RECON
            self.mode = Mode.RECON
            self.emit("mode", mode=self.mode.value, preset=self.preset.value)
            return True

    def _stop_recon(self) -> None:
        if self._finder_air is not None:
            try:
                self._finder_air.stop()
            except Exception:  # noqa: BLE001
                pass
            self._finder_air = None
        self.radio.stop_hopping()

    # =======================================================================
    # PRESET: LOCK & LEVEL  (associate + wired discovery + fire)
    # =======================================================================
    def start_lock_level(self) -> bool:
        with self._lock:
            if self.mode == Mode.RECON:
                self._stop_recon()
            if not self.radio.ensure_managed():
                self.emit("error", msg="radio did not associate")
                return False
            from engine.iface import discover_iface_net
            try:
                self.net = discover_iface_net(self.managed_iface)
            except Exception as exc:  # noqa: BLE001
                self.emit("error", msg=f"net discovery failed: {exc}")
                return False
            self._start_wired_finder()
            self.preset = Preset.LOCK
            self.mode = Mode.LOCKED
            self.emit("mode", mode=self.mode.value, preset=self.preset.value,
                      net=self._net_summary())
            return True

    def _start_wired_finder(self) -> None:
        from engine.finder import Finder, NetFetcher
        self._finder = Finder(
            self.arbiter, self.managed_iface, self.net,
            on_progress=lambda ph, d, t: self.emit("scan", phase=int(ph.value), done=d, total=t))
        # P1 smell is the important pass; run it on a worker so the UI stays live.
        threading.Thread(target=self._run_scan, name="wired-finder", daemon=True).start()
        # Mac-Vacuum keeps the master store fresh as leases rotate.
        self._netfetcher = NetFetcher(
            self.arbiter, self.managed_iface, self.net,
            interval_ms=self.knobs.mac_vacuum_interval_ms)
        self._netfetcher.set_focus_nets([self.net.subnet_cidr or self.net.iface])
        self._netfetcher.start()

    def _run_scan(self) -> None:
        try:
            self._finder.phase1_smell()
            if self.knobs.scan_phases.value >= ScanPhase.P2_FINGERPRINT.value:
                self._finder.phase2_fingerprint()
            self.emit("scan_done")
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: scan failed {exc}")
            self.emit("error", msg=f"scan failed: {exc}")

    def _stop_wired_finder(self) -> None:
        if self._netfetcher is not None:
            try:
                self._netfetcher.stop()
            except Exception:  # noqa: BLE001
                pass
            self._netfetcher = None
        self._finder = None

    # =======================================================================
    # SCAN & SELECT  (station selection section)
    # =======================================================================
    def scents(self) -> List[dict]:
        rows = self.arbiter.read(
            DB_KNOWN_SCENTS,
            "SELECT mac, ip, vendor, ssid, ap_bssid, channel, signal_dbm, "
            "is_station, net_id, last_seen_ms FROM scents ORDER BY last_seen_ms DESC")
        cols = ("mac", "ip", "vendor", "ssid", "ap_bssid", "channel",
                "signal_dbm", "is_station", "net_id", "last_seen_ms")
        return [dict(zip(cols, r)) for r in rows]

    def selected(self) -> List[dict]:
        rows = self.arbiter.read(
            DB_ATTENTION, "SELECT mac, ip, net_id, weight, pinned FROM attention")
        return [dict(zip(("mac", "ip", "net_id", "weight", "pinned"), r)) for r in rows]

    def select(self, mac: str, weight: float = 1.0, pinned: bool = True) -> None:
        """'Select +' — pin a scent into the attention list for focused fire."""
        row = self.arbiter.read(
            DB_KNOWN_SCENTS, "SELECT ip, net_id FROM scents WHERE mac=?", (mac,))
        ip, net_id = (row[0] if row else ("", ""))
        self.arbiter.write(
            DB_ATTENTION,
            "INSERT OR REPLACE INTO attention(mac, ip, net_id, weight, pinned) "
            "VALUES(?,?,?,?,?)", (mac, ip, net_id, float(weight), 1 if pinned else 0))
        self.emit("selected", mac=mac)

    def deselect(self, mac: str) -> None:
        self.arbiter.write(DB_ATTENTION, "DELETE FROM attention WHERE mac=?", (mac,))
        self.emit("deselected", mac=mac)

    def clear_selection(self) -> None:
        self.arbiter.write(DB_ATTENTION, "DELETE FROM attention")
        self.emit("selection_cleared")

    # =======================================================================
    # CONFIGURE & TRIGGER  (fire the focused emitter)
    # =======================================================================
    def fire(self, on_stats=None) -> bool:
        """Launch the native emitter on the associated link, airborne BirdObserver
        + 100 ms rehydrator. Requires LOCK & LEVEL (an associated managed link)."""
        with self._lock:
            if self.mode != Mode.LOCKED:
                self.emit("error", msg="FIRE requires Lock & Level (associate first)")
                return False
            focused = len(self.selected()) > 0
            self.knobs.emit_mode = EmitMode.FOCUSED if focused else EmitMode.UNFOCUSED

            from engine.emission import EmissionController
            from engine.birdobserver import BirdObserver

            self._emission = EmissionController(self.arbiter, self.appdir, self.knobs)
            self._emission.add_transmitter(self.managed_iface, self.net)
            self._emission.start()  # also starts its own 100 ms rehydrator

            # feed the sniffer-sourced escaped-envelope counts into that rehydrator
            if on_stats is not None and getattr(self._emission, "_rehydrator", None):
                self._emission._rehydrator.set_escaped_source(on_stats)

            if self.knobs.bird_airborne:
                self._bird = BirdObserver(self.arbiter, self.knobs)
                self._bird.start()

            self.mode = Mode.FIRING
            self.emit("mode", mode=self.mode.value, preset=self.preset.value,
                      focused=focused)
            return True

    def state_metrics(self) -> dict:
        """Aggregate DB_STATE for the §3 gauges (polled on a Clock tick):
        total tx pkt/s we emit, total leaking pkt/s, and a CONFIRMED flag
        (nothing leaking across all tracked targets)."""
        rows = self.arbiter.read(
            DB_STATE, "SELECT tx_pps, escaped_pkts, compliant FROM metrics")
        tx = sum((r[0] or 0.0) for r in rows)
        leaking = sum(1 for r in rows if not r[2])
        evidence = sum((r[1] or 0) for r in rows)
        confirmed = bool(rows) and leaking == 0 and self.mode == Mode.FIRING
        return {"tx_ps": tx, "leaking": leaking, "evidence": evidence,
                "confirmed": confirmed, "targets": len(rows)}

    def cease(self) -> None:
        with self._lock:
            for svc in ("_bird", "_rsm", "_emission"):
                obj = getattr(self, svc, None)
                if obj is not None:
                    try:
                        obj.stop()
                    except Exception:  # noqa: BLE001
                        pass
                    setattr(self, svc, None)
            if self.mode == Mode.FIRING:
                self.mode = Mode.LOCKED
                self.emit("mode", mode=self.mode.value, preset=self.preset.value)

    # =======================================================================
    # RELEASE / SHUTDOWN
    # =======================================================================
    def release(self) -> None:
        """Give the radio back to Android and stop every service. Safe to re-call."""
        with self._lock:
            self.cease()
            self._stop_recon()
            self._stop_wired_finder()
            try:
                self.radio.release_to_android(wait_reconnect=False)
            except Exception:  # noqa: BLE001
                pass
            self.target_aps = []
            self.links = {}
            self.preset = Preset.NONE
            self.mode = Mode.IDLE
            self.emit("mode", mode=self.mode.value, preset=self.preset.value)

    def shutdown(self) -> None:
        self.release()
        try:
            self.arbiter.close()
        except Exception:  # noqa: BLE001
            pass

    # -- helpers ------------------------------------------------------------
    def _net_summary(self) -> dict:
        n = self.net
        if n is None:
            return {}
        return {"iface": n.iface, "device_ip": n.device_ip,
                "subnet": n.subnet_cidr, "gw4": n.gateway_ipv4,
                "gw6": n.gateway_ipv6, "gw_mac": n.gateway_mac}


if __name__ == "__main__":
    # Off-device state-machine self-test: the device-touching engine services are
    # stubbed; we verify the single-radio lifecycle transitions + select/fire gating.
    import tempfile

    events: List[tuple] = []
    ctl = AppController(tempfile.mkdtemp(),
                        on_event=lambda k, d: events.append((k, d)))

    # stub the radio + engine services so nothing touches a device
    class _FakeRadio:
        def __init__(self): self.state = CardState.ANDROID; self.mon_iface = "mon0"
        def start_recon(self, channel=6): self.state = CardState.MONITOR; return True
        def start_hopping(self, **k): pass
        def stop_hopping(self): pass
        def ensure_managed(self, **k): self.state = CardState.MANAGED; return True
        def is_associated(self): return "aa:bb:cc:dd:ee:ff"
        def release_to_android(self, **k): self.state = CardState.ANDROID; return True
        def current_ssid(self): return "HomeNet"
        def secondary_iface(self): return None
        def set_dual_sta(self, on): pass
    ctl.radio = _FakeRadio()

    class _FakeFinderAir:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass
    import engine.finder_air as _fa
    _fa.FinderAir = _FakeFinderAir

    _NET = NetInfo(iface="wlan0", device_ip="192.168.1.50", cidr=24,
                   subnet_cidr="192.168.1.0/24", gateway_ipv4="192.168.1.1",
                   gateway_ipv6="fe80::1", gateway_mac="aa:bb:cc:00:00:01")
    import engine.iface as _if
    _if.discover_iface_net = lambda iface: _NET

    class _FakeFinder:
        def __init__(self, *a, **k): pass
        def phase1_smell(self): return []
        def phase2_fingerprint(self, *a, **k): pass
    class _FakeNetFetcher:
        def __init__(self, *a, **k): pass
        def set_focus_nets(self, *a): pass
        def start(self): pass
        def stop(self): pass
    import engine.finder as _f
    _f.Finder = _FakeFinder
    _f.NetFetcher = _FakeNetFetcher

    class _FakeTx(list):
        pass
    class _FakeEmission:
        def __init__(self, *a, **k): self.transmitters = lambda: ["wlan0"]
        def add_transmitter(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass
    class _FakeRSM:
        def __init__(self, *a, **k): pass
        def set_escaped_source(self, fn): pass
        def start(self): pass
        def stop(self): pass
    class _FakeBird:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass
    import engine.emission as _em
    import engine.birdobserver as _bo
    _em.EmissionController = _FakeEmission
    _em.RehydrationStateMaintainer = _FakeRSM
    _bo.BirdObserver = _FakeBird

    # 1) Recon preset
    assert ctl.start_recon(channel=6) is True
    assert ctl.mode == Mode.RECON and ctl.preset == Preset.RECON

    # 2) FIRE must be refused while not locked
    assert ctl.fire() is False

    # 3) switch to Lock & Level (recon torn down, radio associated, net discovered)
    assert ctl.start_lock_level() is True
    assert ctl.mode == Mode.LOCKED and ctl.net.subnet_cidr == "192.168.1.0/24"

    # 4) seed a scent + select it -> focused fire
    ctl.arbiter.write(DB_KNOWN_SCENTS,
                      "INSERT OR REPLACE INTO scents(mac, ip, net_id, last_seen_ms) "
                      "VALUES(?,?,?,?)", ("de:ad:00:00:00:01", "192.168.1.77", "lan", now_ms()))
    assert len(ctl.scents()) == 1
    ctl.select("de:ad:00:00:00:01")
    assert len(ctl.selected()) == 1

    assert ctl.fire() is True
    assert ctl.mode == Mode.FIRING
    assert ctl.knobs.emit_mode == EmitMode.FOCUSED, "selected target -> focused mode"

    # 5) cease -> back to LOCKED; release -> IDLE + radio handed back
    ctl.cease()
    assert ctl.mode == Mode.LOCKED
    ctl.release()
    assert ctl.mode == Mode.IDLE and ctl.radio.state == CardState.ANDROID

    # 6) NEW FLOW: detect & select -> router list -> pick -> connect
    assert ctl.detect_and_select() is True
    assert ctl.mode == Mode.RECON
    ctl.arbiter.write(DB_KNOWN_SCENTS,
        "INSERT OR REPLACE INTO scents(mac, ssid, is_station, signal_dbm, last_seen_ms) "
        "VALUES(?,?,?,?,?)", ("7c:db:98:64:54:9a", "MySpectrum-2G", 0, -40, now_ms()))
    ctl.arbiter.write(DB_KNOWN_SCENTS,
        "INSERT OR REPLACE INTO scents(mac, ssid, is_station, signal_dbm, last_seen_ms) "
        "VALUES(?,?,?,?,?)", ("de:ad:be:ef:00:02", "FarAP", 0, -80, now_ms()))
    ctl.arbiter.write(DB_KNOWN_SCENTS,
        "INSERT OR REPLACE INTO scents(mac, ssid, is_station, last_seen_ms) "
        "VALUES(?,?,?,?)", ("00:00:00:00:00:99", "", 1, now_ms()))  # station, no ssid
    routers = ctl.routers()
    assert [r["mac"] for r in routers] == ["7c:db:98:64:54:9a", "de:ad:be:ef:00:02"], routers
    assert ctl.select_ap("7c:db:98:64:54:9a") is True
    assert ctl.select_ap("de:ad:be:ef:00:02") is True
    assert ctl.select_ap("aa:aa:aa:aa:aa:aa") is False  # capped at 2
    assert len(ctl.selected_routers()) == 2
    assert ctl.connect(adhd=True) is True
    assert ctl.mode == Mode.LOCKED and ctl.links["mode"] == "single"  # fake has no wlan1
    assert ctl.links["wlan0"]["ssid"] == "HomeNet"
    ctl.release()
    assert ctl.target_aps == [] and ctl.mode == Mode.IDLE

    kinds = [k for k, _ in events]
    assert "mode" in kinds and "selected" in kinds
    ctl.arbiter.close()
    print("modes seen:", [d.get("mode") for k, d in events if k == "mode"])
    print("U11/U12(AppController) PASS")
