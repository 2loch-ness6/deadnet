"""
AppController — the brain behind the associate-first DeadNet redesign. Bridges the
Kivy screens to the engine layer (arbiter / radio / finders / emission /
birdobserver).

New operating model (owner-revised: "there's nothing to monitor when you're not
focusing", so the monitor-mode router-discovery phase is GONE):

  DETECT   -> enumerate the Wi-Fi airspace(s) the phone is ALREADY associated to
              (wlan0, and wlan1 if the framework raised a 2nd STA). No radio seize,
              no monitor. Selection is IMPLICIT: whatever the owner joined in
              Android settings *is* the scope. You can only smell air you hold a
              key to — that is the safety model.

  SMELL    -> stay associated; a wired Finder sweeps the associated subnet(s) into
              known_scents (append-only master store), fuzzy-grouped by
              like-electronics (vendor/OUI). This is the full-space smell, scoped to
              the airspace(s) of interest.

  FIRE     -> one of two forks, both with the BirdObserver airborne:
                * UNFOCUSED : attention spread evenly across every electronic smelled
                              on the airspace. If one keeps mailing envelopes despite
                              the owner's transmissions, the bird hones attention onto
                              that non-compliant electronic.
                * FOCUSED   : identical, but the scope is limited up front to the
                              electronics the owner picked.
              Internally the native emitter always runs per-host (EmitMode.FOCUSED)
              so the bird can hone in BOTH forks; the fork only decides which hosts
              seed the attention set.

Release-back / "leave it how it was found": begin_smell() snapshots the clean Wi-Fi
baseline before touching any OEM knob; release() restores it. Because we never seize
the radio into monitor, release does NOT toggle Wi-Fi off/on (that would drop adb),
it only restores the dual-STA / multi-internet knobs to how they were found.

Headless-safe: the Kivy Logger import is guarded and every device call is funnelled
through the engine modules, so this file imports and its state machine self-tests
off-device. Stdlib + engine only.
"""
from __future__ import annotations

import enum
import re
import threading
import time
from typing import Callable, List, Optional, Tuple

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
    LOCK = "lock"            # associated + smelling (ready to fire)


class Mode(enum.Enum):
    IDLE = "idle"            # radio with Android, nothing running
    LOCKED = "locked"        # associated + wired Finder smelling, ready to fire
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

        # Detect/Smell flow state.
        self.airspaces_list: List[dict] = []   # associated airspaces last enumerated
        self.adhd: bool = False                # True => request a 2nd STA ("double guns")
        self.monitor_dwell_s: float = 20.0     # deep (monitor) smell sniff window
        self.focused: bool = False             # FIRE fork: True=picked-only, False=whole
        self.links: dict = {}                  # post-associate link summary

        self.arbiter = RowReaderArbiter(appdir)
        self.radio = RadioController(managed_iface)
        self.toolbroker = ToolBroker(appdir)

        # lazily-built engine services (device-touching)
        self._finder = None
        self._netfetcher = None
        self._emission = None
        self._rsm = None
        self._bird = None
        self._survival = None            # SurvivalMonitor (feeds the live gauges)
        self._survival_sample = None     # latest SurvivalSample
        self._passive = None             # PassiveFinder (ARP-listen discovery during fire)

        self._lock = threading.RLock()

    # -- event helper -------------------------------------------------------
    def emit(self, kind: str, **data) -> None:
        try:
            self._emit(kind, data)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: on_event({kind}) raised {exc}")

    # -- capability snapshot (for the Detect screen) ------------------------
    def capabilities(self) -> dict:
        caps = self.toolbroker.capabilities()
        return {
            "state": self.radio.state.value,
            "associated": self.radio.is_associated(),
            "tools": {k: bool(v) for k, v in caps.items()},
            "magisk": self.toolbroker.magisk_module_installed(),
        }

    # =======================================================================
    # DETECT  (enumerate the airspaces we are ALREADY associated to — no seize)
    # =======================================================================
    def detect(self) -> bool:
        """Owner hits 'Detect': read which Wi-Fi airspace(s) the phone is joined
        to right now. No radio seize, no monitor — selection is implicit in what
        the owner associated with in Android settings."""
        self.airspaces_list = self.airspaces()
        self.emit("detected", airspaces=self.airspaces_list)
        return True

    def airspaces(self) -> List[dict]:
        """The airspace(s) we are associated to: wlan0 always, wlan1 if the OEM
        dual-STA raised a 2nd link. Each is {iface, ssid, bssid}."""
        out: List[dict] = []
        ssid = self.radio.current_ssid()
        bssid = self.radio.is_associated() or ""
        if ssid or bssid:
            out.append({"iface": self.managed_iface, "ssid": ssid, "bssid": bssid})
        sec = self.radio.secondary_iface()
        if sec:
            out.append({"iface": sec, "ssid": "",
                        "bssid": (self.radio.link_bssid(sec) or "")})
        return out

    # =======================================================================
    # SMELL  (associate-ensure -> wired subnet sweep scoped to the airspace)
    # =======================================================================
    def begin_smell(self, adhd: Optional[bool] = None) -> bool:
        """Begin smelling the associated airspace. We stay associated (no monitor):
        snapshot the clean baseline, best-effort permit a 2nd STA if ADHD, confirm
        the managed link, discover the subnet, and start the wired Finder sweeping
        it into known_scents. Empirically a monitor cannot run beside the associated
        link, so smelling is subnet/ARP-based on the live association."""
        with self._lock:
            self.adhd = self.adhd if adhd is None else bool(adhd)
            want_second = self.adhd
            # snapshot "how it was found" before we touch any OEM knob
            try:
                self.radio.capture_baseline()
            except Exception:  # noqa: BLE001
                pass
            if want_second:
                try:
                    self.radio.set_dual_sta(True)
                except Exception:  # noqa: BLE001
                    pass
            if not self.radio.ensure_managed():
                self.emit("error", msg="not associated — join a Wi-Fi you own first")
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
            self.emit("smelling", links=self.links, net=self._net_summary())
            self.emit("mode", mode=self.mode.value, preset=self.preset.value,
                      net=self._net_summary())
            return True

    # back-compat alias (older callers / tests)
    def connect(self, adhd: Optional[bool] = None) -> bool:
        return self.begin_smell(adhd=adhd)

    # =======================================================================
    # DEEP SMELL  (monitor-mode sniff interlude — sees through client isolation)
    # =======================================================================
    def _assoc_channel(self) -> Optional[int]:
        """The channel wlan0 is currently associated on, parsed from `iw dev`.
        Needed to tune the monitor to the joined airspace (we lock, never hop)."""
        try:
            from engine import rootshell
            out = rootshell.su(f"iw dev {self.managed_iface} info") or ""
        except Exception:  # noqa: BLE001
            return None
        m = re.search(r"channel\s+(\d+)", out)
        return int(m.group(1)) if m else None

    def begin_monitor_smell(self, dwell_s: Optional[float] = None) -> bool:
        """Legacy monitor-mode "deep smell" — seized a monitor vif and ran the
        now-deleted engine.finder_air.FinderAir over it. Removed in the v3 M0
        teardown; monitor discovery is replaced by engine/recon.py (ReconScanner)
        running under PhyGuard RECON ownership."""
        # TODO(M4): rebuild as RECON mode — PhyGuard.own()/to_recon() + ReconScanner
        # populating the target store (see V3_PLAN §6, §15 wiring seams).
        raise NotImplementedError(
            "monitor deep-smell removed in v3 M0; rebuilt on engine/recon.py in M4")

    def _link_summary(self, wanted_second: bool) -> dict:
        """Describe the associated link(s) and which mode we actually got."""
        ssid = self.radio.current_ssid()
        bssid = self.radio.is_associated() or ""
        second = self.radio.secondary_iface()
        if second is not None:
            mode = "double_guns" if wanted_second else "two_links"
        else:
            mode = "single"
        return {
            "wlan0": {"ssid": ssid, "bssid": bssid},
            "wlan1": ({"iface": second} if second else None),
            "mode": mode,
            "wanted_second": wanted_second,
        }

    def _start_wired_finder(self) -> None:
        # TODO(M4): the legacy engine.finder subnet sweep + NetFetcher mac-vacuum
        # were removed in the v3 M0 teardown. v3 discovery is monitor-based
        # (engine/recon.py ReconScanner), not an associated L3 sweep. No-op so the
        # begin_smell() skeleton still runs; rewire to RECON in M4.
        return

    def _run_scan(self) -> None:
        # TODO(M4): legacy finder scan worker (engine.finder, removed in M0).
        return

    def _stop_wired_finder(self) -> None:
        if self._netfetcher is not None:
            try:
                self._netfetcher.stop()
            except Exception:  # noqa: BLE001
                pass
            self._netfetcher = None
        self._finder = None

    # =======================================================================
    # SMELL VIEW  (known_scents, fuzzy-grouped by like-electronics)
    # =======================================================================
    def scents(self) -> List[dict]:
        rows = self.arbiter.read(
            DB_KNOWN_SCENTS,
            "SELECT mac, ip, vendor, ssid, ap_bssid, channel, signal_dbm, "
            "is_station, net_id, last_seen_ms FROM scents ORDER BY last_seen_ms DESC")
        cols = ("mac", "ip", "vendor", "ssid", "ap_bssid", "channel",
                "signal_dbm", "is_station", "net_id", "last_seen_ms")
        return [dict(zip(cols, r)) for r in rows]

    def scent_groups(self) -> List[Tuple[str, List[dict]]]:
        """Fuzzy associator: the smelled electronics lined up by like-kind — all
        the Apple phones in one row, etc. Groups by OUI vendor (blank => 'unknown'),
        biggest family first. Append-only master store: nothing is pruned, only
        regrouped, so a device keeps its place across re-smells."""
        groups: dict = {}
        for s in self.scents():
            key = (s.get("vendor") or "").strip() or "unknown"
            groups.setdefault(key, []).append(s)
        return sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))

    def selected(self) -> List[dict]:
        rows = self.arbiter.read(
            DB_ATTENTION, "SELECT mac, ip, net_id, weight, pinned FROM attention")
        return [dict(zip(("mac", "ip", "net_id", "weight", "pinned"), r)) for r in rows]

    def select(self, mac: str, weight: float = 1.0, pinned: bool = True) -> None:
        """'Select +' — pin a scent into the attention list for a FOCUSED fire."""
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
    # CONFIGURE & TRIGGER  (fire the emitter; focused or unfocused fork)
    # =======================================================================
    def set_focused(self, focused: bool) -> None:
        self.focused = bool(focused)
        self.emit("fork", focused=self.focused)

    def fire(self, focused: Optional[bool] = None, on_stats=None) -> bool:
        """Legacy ARP FIRE — launched the native emitter (engine.emission) with the
        BirdObserver (engine.birdobserver), the SurvivalMonitor live gauges and the
        passive ARP finder. The whole ARP-poison transport was removed in the v3 M0
        teardown; v3 attacks with scheduled 802.11 mgmt-TX instead."""
        # TODO(M4): rebuild as ATTACK mode — select_spoof() over the recon target
        # store -> AttackController(mgmt_tx.send, ensure_attack=phyguard.to_attack)
        # with CapGate gating the patched cfg80211 (see V3_PLAN §6, §15).
        raise NotImplementedError(
            "ARP FIRE removed in v3 M0; rebuilt on engine/attack.py mgmt-TX in M4")

    def state_metrics(self) -> dict:
        """Metrics for the gauges (polled on a Clock tick). Preferred source is the
        live SurvivalMonitor sample (our ARP TX / surviving-leaks / evidence off the
        associated link); falls back to the DB_STATE rollup (emit.cpp native
        per-target stats) when no survival sample is in yet."""
        s = self._survival_sample
        if s is not None:
            return {"tx_ps": s.arp_tx_ps, "leaking": s.surv_ps,
                    "evidence": s.evidence_ps,
                    "confirmed": bool(s.confirmed) and self.mode == Mode.FIRING,
                    "targets": len(self.selected())}
        rows = self.arbiter.read(
            DB_STATE, "SELECT tx_pps, escaped_pkts, compliant FROM metrics")
        tx = sum((r[0] or 0.0) for r in rows)
        leaking = sum(1 for r in rows if not r[2])
        evidence = sum((r[1] or 0) for r in rows)
        confirmed = bool(rows) and leaking == 0 and self.mode == Mode.FIRING
        return {"tx_ps": tx, "leaking": leaking, "evidence": evidence,
                "confirmed": confirmed, "targets": len(rows)}

    def _attention_net_id(self) -> str:
        """The canonical net_id used for attention rows AND the transmitter's
        pump filter. It MUST match the convention the master store (scents) is
        keyed by — the Finder writes `scents.net_id = self.net.iface`, select()
        and the BirdObserver copy that through, and NetFetcher gates on
        `self.net.iface in focus`. So the whole pipeline keys on the iface, NOT
        subnet_cidr. Mixing the two silently drops rows from the emit focus set
        (the pump filters attention `WHERE net_id = tx.net_id`), which is why a
        focused fire used to leave the gauges flat — the picks carried the
        iface-style net_id while the transmitter filtered on subnet_cidr."""
        if self.net is None:
            return self.managed_iface
        return self.net.iface or self.managed_iface

    def _seed_targets(self, focused: bool) -> int:
        """Fill the attention/focus set so emit.cpp has something to aim at, and
        return the number of victim targets (excludes the gateway).

          * focused   : keep only the owner's picks (already pinned in attention via
                        select()); just make sure the gateway is present.
          * unfocused : add every smelled host on the connected subnet, evenly.
        The gateway is pinned + marked so emit can recover its IPv4 for the
        victim-side poison; emit never victimizes it. Our own device is skipped."""
        if self.net is None:
            return 0
        net_id = self._attention_net_id()
        our_ip = self.net.device_ip or ""
        gw_ip = self.net.gateway_ipv4 or ""
        gw_mac = self.net.gateway_mac or ""
        if gw_mac and gw_ip:
            self.arbiter.write(
                DB_ATTENTION,
                "INSERT OR REPLACE INTO attention(mac, ip, net_id, weight, pinned) "
                "VALUES(?,?,?,?,1)", (gw_mac, gw_ip, net_id, 1.0))
        if focused:
            # picks are already pinned in attention (sync, via select()). They
            # carry the scent's net_id; normalize EVERY attention row to the
            # transmitter's net_id so the emission pump's `WHERE net_id=?` filter
            # includes them — otherwise emit has nothing to poison and the
            # gauges read flat. One sync UPDATE at fire (not a hot path); all
            # attention here belongs to the single connected net.
            self.arbiter.write(
                DB_ATTENTION, "UPDATE attention SET net_id=? WHERE net_id != ?",
                (net_id, net_id))
            rows = self.arbiter.read(
                DB_ATTENTION, "SELECT mac FROM attention WHERE mac != ?", (gw_mac,))
            return len(rows)
        # unfocused: seed every smelled host so identified ones carry a real MAC
        # (cleaner unicast victim-poison) and the bird can hone them. The WHOLE
        # subnet is additionally blasted BLIND by the emission pump
        # (set_whole_subnet_blind in fire()), so the attack lands even on a
        # client-isolated LAN where smell sees almost nothing. Synchronous write
        # (one-shot at FIRE, not a hot path).
        rows = self.arbiter.read(
            DB_KNOWN_SCENTS,
            "SELECT mac, ip FROM scents WHERE mac != '' AND ip != ''")
        for mac, ip in rows:
            if ip in (our_ip, gw_ip) or mac == gw_mac:
                continue
            self.arbiter.write(
                DB_ATTENTION,
                "INSERT OR IGNORE INTO attention(mac, ip, net_id, weight, pinned) "
                "VALUES(?,?,?,1.0,0)", (mac, ip, net_id))
        # Target count = the whole subnet (blind blast), so FIRE never refuses
        # while associated even if nothing was smelled. Fall back to the smelled
        # count if the subnet CIDR is unknown.
        return self._subnet_host_count(our_ip, gw_ip) or len(rows)

    def _subnet_host_count(self, our_ip: str, gw_ip: str) -> int:
        cidr = self.net.subnet_cidr if self.net else ""
        if not cidr:
            return 0
        try:
            import ipaddress
            net = ipaddress.ip_network(cidr, strict=False)
            excl = {our_ip, gw_ip,
                    str(net.network_address), str(net.broadcast_address)}
            return sum(1 for h in net.hosts() if str(h) not in excl)
        except ValueError:
            return 0

    # -- live-gauge survival monitor ----------------------------------------
    def _iface_mac(self, iface: str) -> str:
        from engine import rootshell
        return rootshell.su(f"cat /sys/class/net/{iface}/address").strip()

    def _copy_sniff(self) -> Optional[str]:
        # TODO(M4): staged the now-deleted sniff.<arch> binary for the ARP
        # SurvivalMonitor (engine.emission._arch_suffix, removed in M0). The v3
        # live gauges come from mgmt-TX TXSTATUS instead. No-op.
        return None

    def _start_passive(self, our_mac: str = "") -> None:
        # TODO(M4): legacy ARP-listen passive finder (engine.finder_passive,
        # removed in M0). v3 discovery is monitor recon (engine/recon.py). No-op.
        return

    def _on_survival(self, sample) -> None:
        self._survival_sample = sample

    def _start_survival(self, our_mac: str) -> None:
        # TODO(M4): legacy ARP-survival live gauges (apk/survival_monitor.py,
        # removed in M0). v3 gauges come from mgmt_tx TXSTATUS acks. No-op.
        return

    def cease(self) -> None:
        with self._lock:
            for svc in ("_bird", "_rsm", "_emission", "_survival", "_passive"):
                obj = getattr(self, svc, None)
                if obj is not None:
                    try:
                        obj.stop()
                    except Exception:  # noqa: BLE001
                        pass
                    setattr(self, svc, None)
            self._survival_sample = None
            if self.mode == Mode.FIRING:
                self.mode = Mode.LOCKED
                self.emit("mode", mode=self.mode.value, preset=self.preset.value)

    # =======================================================================
    # RELEASE / SHUTDOWN
    # =======================================================================
    def release(self) -> None:
        """Give the radio back to Android and stop every service. Safe to re-call.
        Because we never seized monitor, this only restores the OEM dual-STA /
        multi-internet knobs to how they were found (no disruptive Wi-Fi toggle,
        so adb/tailscale on wlan0 survive)."""
        with self._lock:
            self.cease()
            self._stop_wired_finder()
            try:
                self.radio.release_to_android(wait_reconnect=False)
            except Exception:  # noqa: BLE001
                pass
            self.airspaces_list = []
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
    # NOTE: the full associate-first self-test was removed in the v3 M0 teardown —
    # it exercised the deleted finder / emission / birdobserver / survival engines
    # and the ARP FIRE / monitor deep-smell code paths, all now stubbed.
    # TODO(M4): rebuild as an ANDROID<->APP{RECON,ATTACK} state-machine self-test
    # driving PhyGuard / ReconScanner / AttackController / CapGate (V3_PLAN §15).
    # This minimal skeleton only confirms the controller still constructs and the
    # torn-out entry points fail loudly rather than silently half-run.
    import tempfile

    events: List[tuple] = []

    class _FakeRadio:
        mon_iface = "mon0"
        def __init__(self): self.state = CardState.ANDROID
        def ensure_managed(self, **k): self.state = CardState.MANAGED; return True
        def is_associated(self): return "aa:bb:cc:dd:ee:ff"
        def release_to_android(self, **k): self.state = CardState.ANDROID; return True
        def current_ssid(self): return "HomeNet"
        def secondary_iface(self): return None
        def link_bssid(self, iface): return None

    ctl = AppController(tempfile.mkdtemp(),
                        on_event=lambda k, d: events.append((k, d)))
    ctl.radio = _FakeRadio()

    # DETECT still works (no deleted deps): enumerate the associated airspace.
    assert ctl.detect() is True
    assert ctl.airspaces_list == [{"iface": "wlan0", "ssid": "HomeNet",
                                   "bssid": "aa:bb:cc:dd:ee:ff"}], ctl.airspaces_list
    assert ctl.mode == Mode.IDLE, "detect must not change mode"

    # The ARP FIRE and monitor deep-smell paths are torn out pending the M4 rewire.
    for call in (ctl.fire, ctl.begin_monitor_smell):
        try:
            call()
            raise AssertionError(f"{call.__name__} should raise NotImplementedError")
        except NotImplementedError:
            pass

    # RELEASE hands the radio back cleanly even with the services torn out.
    ctl.release()
    assert ctl.mode == Mode.IDLE and ctl.radio.state == CardState.ANDROID
    ctl.arbiter.close()
    print("AppController (v3 M0 skeleton) PASS")
