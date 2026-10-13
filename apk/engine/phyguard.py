"""
PhyGuard (v3) — the single authority over the OnePlus 12's one Wi-Fi PHY (phy0).

v3 replaces the associate-first/ARP model with **PHY ownership**: the app takes
exclusive control of the radio, locks Android out, and moves the PHY between
exactly two modes under that ownership:

    Ownership.ANDROID   the baseline; the framework owns the radio, app dormant
    Ownership.APP       the app owns the PHY and guards it from Android
        PhyMode.RECON   monitor vif (mon0)      — passive target detection
        PhyMode.ATTACK  managed vif (wlan0),    — mgmt-TX injection, no creds
                        UNASSOCIATED

Why the modes are cheap to swap: the patched cfg80211 (see
`op12/wifi-modem-seams.md`) accepts mgmt-TX from an *unassociated* managed wdev
with arbitrary SA/DA/BSSID and off-channel freq, so ATTACK needs no association,
no credentials, no DHCP — it is only a vif-type change while the guard stays up.

The proven seize/release command sequences live in `radio.py` (U6); PhyGuard
**composes** a RadioController (rather than re-deriving them) and adds the
ownership layer: the ATTACK transition, the Android lock-out guard loop, and a
guaranteed release. Every command still runs on-host under `su -c`. Stdlib only.
"""
from __future__ import annotations

import atexit
import signal
import threading
import time
from typing import List, Optional

try:  # off-device / bare test env
    from kivy.logger import Logger
except Exception:  # noqa: BLE001
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

try:
    from engine.contracts import Ownership, PhyMode
except Exception:  # running as a loose script
    from contracts import Ownership, PhyMode  # type: ignore

DEADNET_PREF = "DeadNet"
DEFAULT_MANAGED = "wlan0"
MON_IFACE = "mon0"
GUARD_INTERVAL_S = 2.0


def _su(cmd: str, timeout: float = 15.0):
    """Run as root through the shared persistent root shell (one su per app)."""
    from engine import rootshell as _root  # local import: avoid import cycles
    return _root.su_cp(cmd, timeout)


def _ok(cp) -> bool:
    return getattr(cp, "returncode", 1) == 0


class PhyGuard:
    """Owns the ANDROID<->APP ownership / RECON<->ATTACK mode machine for phy0."""

    def __init__(self, managed_iface: str = DEFAULT_MANAGED, mon_iface: str = MON_IFACE,
                 radio=None):
        if radio is None:
            from engine.radio import RadioController
            radio = RadioController(managed_iface, mon_iface)
        self.managed = managed_iface
        self.mon = mon_iface
        self.radio = radio          # proven seize/release primitives (U6)
        self.ownership: Ownership = Ownership.ANDROID
        self.mode: Optional[PhyMode] = None
        self.recon_channel: int = 0
        self._lock = threading.RLock()
        self._guard_thread: Optional[threading.Thread] = None
        self._guard_stop = threading.Event()
        self._guards_installed = False

    # -- state -------------------------------------------------------------
    def is_owned(self) -> bool:
        return self.ownership == Ownership.APP

    def status(self) -> dict:
        return {
            "ownership": self.ownership.value,
            "mode": self.mode.value if self.mode else "",
            "recon_channel": self.recon_channel,
            "radio_state": getattr(self.radio.state, "value", str(self.radio.state)),
        }

    # -- guaranteed release (mirrors radio.py's safety net) ----------------
    def _install_guards(self) -> None:
        if self._guards_installed:
            return
        atexit.register(self._emergency_release)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                prev = signal.getsignal(sig)

                def _handler(signum, frame, _prev=prev):
                    self._emergency_release()
                    if callable(_prev):
                        _prev(signum, frame)

                signal.signal(sig, _handler)
            except (ValueError, OSError):
                # not on the main thread — atexit + radio.py's guards still cover us
                pass
        self._guards_installed = True

    def _emergency_release(self) -> None:
        if self.ownership == Ownership.APP:
            Logger.warning(f"{DEADNET_PREF}: PHY emergency release-back")
            try:
                self.release(wait_reconnect=False)
            except Exception:  # noqa: BLE001
                # last-ditch: never strand the owner with Wi-Fi off / a mon vif
                _su(f"iw dev {self.mon} del")
                _su(f"ip link set {self.managed} up")
                _su("svc wifi enable")
                self.ownership = Ownership.ANDROID
                self.mode = None

    # -- OWNERSHIP: ANDROID -> APP/RECON -----------------------------------
    def own(self, channel: int = 6) -> bool:
        """Take the PHY. From ANDROID this seizes monitor; if already owned it is
        just a mode switch to RECON on `channel`. Android is locked out."""
        with self._lock:
            if self.ownership == Ownership.APP:
                return self.to_recon(channel)
            self._install_guards()
            # radio.start_recon captures the clean baseline, `svc wifi disable`s,
            # downs every sibling vif, adds mon0, ups it, and tunes — proven order B.
            if not self.radio.start_recon(channel):
                self.ownership = Ownership.ANDROID
                self.mode = None
                return False
            self.ownership = Ownership.APP
            self.mode = PhyMode.RECON
            self.recon_channel = int(channel)
            self._start_guard()
            Logger.info(f"{DEADNET_PREF}: PHY owned, RECON ch{channel}")
            return True

    # -- MODE: RECON <-> ATTACK --------------------------------------------
    def to_attack(self) -> bool:
        """APP/RECON -> APP/ATTACK: tear down mon0 and bring the managed vif UP
        UNASSOCIATED (Android Wi-Fi stays disabled + guarded). No credentials,
        no association — mgmt-TX carries its own freq per frame."""
        with self._lock:
            if self.ownership != Ownership.APP:
                Logger.warning(f"{DEADNET_PREF}: to_attack ignored (PHY not owned)")
                return False
            try:
                self.radio.stop_hopping()
            except Exception:  # noqa: BLE001
                pass
            _su(f"iw dev {self.mon} del")
            _su(f"ip link set {self.managed} up")
            self.mode = PhyMode.ATTACK
            Logger.info(f"{DEADNET_PREF}: PHY mode ATTACK ({self.managed} up, unassociated)")
            return True

    def to_recon(self, channel: Optional[int] = None) -> bool:
        """APP/ATTACK -> APP/RECON: free the RF chain (down the managed vif),
        (re)create the monitor vif and tune it. Stays owned + guarded."""
        with self._lock:
            if self.ownership != Ownership.APP:
                Logger.warning(f"{DEADNET_PREF}: to_recon ignored (PHY not owned)")
                return False
            ch = self.recon_channel if channel is None else int(channel)
            _su(f"ip link set {self.managed} down")   # release the RF chain first
            _su(f"iw dev {self.mon} del")
            phy = self.radio.phy()
            add = _su(f"iw phy {phy} interface add {self.mon} type monitor")
            if not _ok(add):
                Logger.error(f"{DEADNET_PREF}: to_recon add {self.mon} failed: "
                             f"{(getattr(add, 'stderr', '') or getattr(add, 'stdout', '')).strip()}")
                return False
            _su(f"ip link set {self.mon} up")
            if ch > 0 and not self.radio.set_channel(ch):
                Logger.error(f"{DEADNET_PREF}: to_recon could not tune ch{ch}")
                return False
            self.mode = PhyMode.RECON
            self.recon_channel = ch
            Logger.info(f"{DEADNET_PREF}: PHY mode RECON ch{ch}")
            return True

    # -- GUARD: keep Android off the PHY -----------------------------------
    def _active_vif(self) -> str:
        return self.mon if self.mode == PhyMode.RECON else self.managed

    def _sibling_vifs(self) -> List[str]:
        """Every wifi vif except our active one — p2p0 / wifi-aware0 / wlan0(mon
        mode) etc. On this single-RF-chain phy each of them holds the radio, so
        the lock-out must keep them downed."""
        names = self.radio._sibling_vifs()  # wlan0/p2p0/... (never our mon_iface)
        active = self._active_vif()
        out = [n for n in names if n != active]
        return out or []

    def guard(self) -> None:
        """Re-assert the Android lock-out: framework Wi-Fi stays disabled and
        any sibling vif that reappeared is downed. Idempotent / cheap."""
        if self.ownership != Ownership.APP:
            return
        _su("svc wifi disable")
        for vif in self._sibling_vifs():
            _su(f"ip link set {vif} down")

    def _start_guard(self) -> None:
        self._guard_stop.clear()
        if self._guard_thread and self._guard_thread.is_alive():
            return

        def _loop():
            while not self._guard_stop.wait(GUARD_INTERVAL_S):
                try:
                    self.guard()
                except Exception:  # noqa: BLE001
                    pass

        self._guard_thread = threading.Thread(target=_loop, name="phy-guard", daemon=True)
        self._guard_thread.start()

    def _stop_guard(self) -> None:
        self._guard_stop.set()
        t = self._guard_thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        self._guard_thread = None

    # -- RELEASE: APP -> ANDROID -------------------------------------------
    def release(self, wait_reconnect: bool = True) -> bool:
        """Give the PHY back to Android and restore the captured baseline. Safe
        to re-call. Delegates the proven release sequence to radio.py (del mon0
        -> vifs up -> Wi-Fi toggle -> restore baseline)."""
        with self._lock:
            self._stop_guard()
            if self.ownership == Ownership.ANDROID:
                return True
            ok = self.radio.release_to_android(wait_reconnect=wait_reconnect)
            self.ownership = Ownership.ANDROID
            self.mode = None
            self.recon_channel = 0
            Logger.info(f"{DEADNET_PREF}: PHY released to Android")
            return bool(ok)

    # -- context manager ---------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._emergency_release()
        return False


if __name__ == "__main__":
    # Off-device structural self-test: the proven radio sequences are exercised
    # with `_su` mocked, and we verify the ownership/mode machine + the guard.
    import subprocess

    log: List[str] = []

    def fake_su(cmd, timeout=15.0):
        log.append(cmd)
        out = ""
        if cmd.startswith("cat /sys/class/net"):
            out = "phy0\n"
        elif cmd.strip() == "iw dev":
            out = "Interface wlan0\nInterface p2p0\n"
        elif cmd.startswith("iw dev") and " link" in cmd:
            out = ("Connected to aa:bb:cc:dd:ee:ff (on wlan0)"
                   if any("svc wifi enable" in c for c in log) else "Not connected.")
        return subprocess.CompletedProcess(cmd, 0, out, "")

    import sys
    import engine.radio as _R
    # patch the module the test is actually running in (__main__ when invoked as
    # a script, engine.phyguard under pytest) — NOT a re-imported copy
    sys.modules[__name__]._su = fake_su
    _R._su = fake_su

    pg = PhyGuard()
    pg._install_guards = lambda: None          # no real signal handlers in test
    pg.radio._install_guards = lambda: None
    pg._start_guard = lambda: None             # the guard loop is verified via guard()

    # 1) own: ANDROID -> APP/RECON (proven order B reached through radio.py)
    assert pg.own(6) is True, pg.status()
    assert pg.ownership == Ownership.APP and pg.mode == PhyMode.RECON
    assert pg.recon_channel == 6
    assert "svc wifi disable" in log
    assert any("interface add mon0 type monitor" in c for c in log)
    assert any("set channel 6" in c for c in log)
    assert pg.is_owned()

    # 2) guard in RECON keeps Android out and downs the non-active siblings
    log.clear()
    pg.guard()
    assert "svc wifi disable" in log
    assert "ip link set p2p0 down" in log
    assert "ip link set wlan0 down" in log, "wlan0 must stay down while mon0 is active"

    # 3) RECON -> ATTACK: del mon0, managed vif up, NO association, stays guarded
    log.clear()
    assert pg.to_attack() is True
    assert pg.mode == PhyMode.ATTACK and pg.ownership == Ownership.APP
    assert "iw dev mon0 del" in log
    assert "ip link set wlan0 up" in log
    assert not any("svc wifi enable" in c for c in log), "attack must not re-enable Android Wi-Fi"

    # 4) guard in ATTACK must NOT down our active managed vif
    log.clear()
    pg.guard()
    assert "svc wifi disable" in log
    assert "ip link set p2p0 down" in log
    assert "ip link set wlan0 down" not in log, "wlan0 is the active ATTACK vif"

    # 5) ATTACK -> RECON on a new channel (re-add mon0, retune)
    log.clear()
    assert pg.to_recon(36) is True
    assert pg.mode == PhyMode.RECON and pg.recon_channel == 36
    assert "ip link set wlan0 down" in log
    assert any("interface add mon0 type monitor" in c for c in log)
    assert any("set channel 36" in c for c in log)

    # 6) release: APP -> ANDROID (del mon0, vifs up, Wi-Fi toggle, baseline)
    log.clear()
    assert pg.release(wait_reconnect=True) is True
    assert pg.ownership == Ownership.ANDROID and pg.mode is None
    assert "iw dev mon0 del" in log
    assert "svc wifi enable" in log
    assert pg.status()["ownership"] == "android"

    # 7) release is idempotent; own() again from ANDROID works
    assert pg.release() is True
    assert pg.own(11) is True and pg.mode == PhyMode.RECON
    pg.release()

    print("phyguard seq:", [c for c in log if c.startswith("svc wifi")])
    print("PHYGUARD PASS")
