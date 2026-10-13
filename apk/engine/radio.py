"""
RadioController (U6) — total, *proven* command over the OnePlus 12's single Wi-Fi
radio (phy0), for the two-preset single-radio build:

  * Recon & Record  -> MONITOR: free the radio, add a monitor vif, tune/hop channels.
  * Lock & Level    -> MANAGED: hand the radio back to Android, associate normally.

Hardware reality (empirically established on CPH2581 / Android 14 this session, NOT
guessed — owner directive "we can't guess"):

  phy0 has ONE RF chain. Valid interface combinations forbid monitor+managed together,
  so the radio is EITHER associated (attack/managed) OR sniffing (monitor) — never both.
  `iw dev wlan0 set type monitor` is rejected (-95). A monitor *vif* (`mon0`) can be
  added, but it cannot tune while wlan0 still claims the channel: `svc wifi disable`
  alone is NOT enough (wlan0 netdev lingers -> `set channel` fails -16 busy). The
  working sequence downs wlan0 first (airmon-ng style):

    RECON (monitor), PROVEN order "B":
      1. svc wifi disable
      2. ip link set wlan0 down
      3. iw phy <phy> interface add mon0 type monitor
      4. ip link set mon0 up
      5. iw dev mon0 set channel <N>        # 2.4 & 5 GHz both verified (1/6/36)
      -> tcpdump -i mon0 sees beacons + data; set channel re-runs to HOP.

    RELEASE-BACK (-> Android/managed), PROVEN:
      1. iw dev mon0 del
      2. ip link set wlan0 up
      3. svc wifi enable
      -> wlan0 re-associates on its own (confirm via `iw dev wlan0 link`).

RELEASE IS GUARANTEED: registered on atexit + SIGINT/SIGTERM, and idempotent, so the
owner's phone never gets stranded with Wi-Fi off / a dangling monitor vif.

Everything runs on-host under `su -c` (no chroot). Stdlib only.
"""
from __future__ import annotations

import atexit
import re
import signal
import subprocess
import threading
import time
from typing import List, Optional

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

try:
    from engine.contracts import CardState
except Exception:  # running as a loose script
    from contracts import CardState  # type: ignore

DEADNET_PREF = "DeadNet"
MON_IFACE = "mon0"            # the monitor vif we create
DEFAULT_MANAGED = "wlan0"     # Android's station iface / adb+tailscale control path


def _su(cmd: str, timeout: float = 15.0) -> subprocess.CompletedProcess:
    """Run a command as root through the shared PERSISTENT root shell (one su
    for the whole app — no per-call su fork). Never raises; returns a
    CompletedProcess whose stdout carries the merged stdout+stderr."""
    from engine import rootshell as _root  # local import: avoid import cycles
    return _root.su_cp(cmd, timeout)


def _ok(cp: subprocess.CompletedProcess) -> bool:
    return cp.returncode == 0


# ---------------------------------------------------------------------------
# pure helpers (unit-testable without a device)
# ---------------------------------------------------------------------------
def phy_for_iface(iface: str, sys_text: str) -> Optional[str]:
    """Parse `cat /sys/class/net/<iface>/phy80211/name` style output -> 'phy0'."""
    t = (sys_text or "").strip()
    return t if t.startswith("phy") else None


_LINK_CONNECTED = re.compile(r"Connected to ([0-9a-f:]{17})", re.I)


def parse_link(text: str) -> Optional[str]:
    """`iw dev wlan0 link` -> associated BSSID, or None if 'Not connected'."""
    m = _LINK_CONNECTED.search(text or "")
    return m.group(1).lower() if m else None


# Standard hop sets (2.4 GHz social channels first, then common 5 GHz).
CHANNELS_24 = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]


class RadioController:
    """Owns the seize/monitor/hop/release lifecycle for the single internal radio."""

    def __init__(self, managed_iface: str = DEFAULT_MANAGED, mon_iface: str = MON_IFACE):
        self.managed_iface = managed_iface
        self.mon_iface = mon_iface
        self._phy: Optional[str] = None
        self.state: CardState = CardState.ANDROID
        self._lock = threading.RLock()
        self._hop_thread: Optional[threading.Thread] = None
        self._hop_stop = threading.Event()
        self._guards_installed = False
        self._seized_vifs: List[str] = []   # sibling vifs downed for a monitor seize
        # Clean networking baseline captured the first time we seize the radio,
        # reproduced on release so the owner's phone is "left how it was found".
        self._baseline: Optional[dict] = None

    # -- discovery ----------------------------------------------------------
    def phy(self) -> str:
        if self._phy is None:
            self._phy = self._discover_phy()
        return self._phy

    def _discover_phy(self) -> str:
        """Resolve the wiphy name for our radio. Try, in order: the managed vif's
        sysfs phy link, the monitor vif's (it may be the only one up in con_mode=4),
        `iw dev` (the phy#N heading), and finally the sole entry in
        /sys/class/ieee80211/. Never silently assume 'phy0' — that masked a real
        bug on this device (the radio is phy6)."""
        for iface in (self.managed_iface, self.mon_iface):
            name = phy_for_iface(iface, _su(
                f"cat /sys/class/net/{iface}/phy80211/name 2>/dev/null").stdout)
            if name:
                return name
        # `iw dev` groups vifs under a `phy#N` heading
        m = re.search(r"phy#(\d+)", _su("iw dev").stdout or "")
        if m:
            return f"phy{m.group(1)}"
        # last resort: the single registered wiphy
        for line in (_su("ls /sys/class/ieee80211/ 2>/dev/null").stdout or "").split():
            if line.startswith("phy"):
                return line
        Logger.error(f"{DEADNET_PREF}: could not resolve wiphy name; defaulting phy0")
        return "phy0"

    def is_associated(self) -> Optional[str]:
        """Return the associated BSSID (lowercase) or None."""
        return parse_link(_su(f"iw dev {self.managed_iface} link").stdout)

    def link_bssid(self, iface: str) -> Optional[str]:
        """Associated BSSID (lowercase) for any iface, or None — used to read the
        2nd STA (wlan1) airspace when the framework has raised it."""
        return parse_link(_su(f"iw dev {iface} link").stdout)

    def current_ssid(self) -> str:
        """SSID wlan0 is currently associated to (via `cmd wifi status`), or ''."""
        out = _su("cmd wifi status").stdout or ""
        m = re.search(r'connected to "([^"]*)"', out, re.I)
        return m.group(1) if m else ""

    def secondary_iface(self) -> Optional[str]:
        """The on-demand secondary-STA vif if the framework has raised it."""
        out = _su("iw dev").stdout or ""
        return "wlan1" if re.search(r"\bwlan1\b", out) else None

    # -- clean baseline capture / restore -----------------------------------
    def capture_baseline(self) -> dict:
        """Snapshot the Android Wi-Fi state *before* we seize anything, so
        release() can put it back exactly how it was found. Captured once."""
        if self._baseline is not None:
            return self._baseline
        def _g(key: str) -> str:
            return (_su(f"settings get global {key}").stdout or "").strip()
        mm = _su("dumpsys wifi").stdout or ""
        mode_m = re.search(r"WifiMultiInternetMode (\d)", mm)
        self._baseline = {
            "wifi_on": _g("wifi_on"),
            "airplane": _g("airplane_mode_on"),
            "dual_sta": _g("dual_sta_switch_on"),
            "multi_mode": mode_m.group(1) if mode_m else "",
            "ssid": self.current_ssid(),
            "bssid": self.is_associated() or "",
        }
        Logger.info(f"{DEADNET_PREF}: radio baseline captured {self._baseline}")
        return self._baseline

    def restore_baseline(self) -> None:
        """Reproduce the captured clean baseline (dual-STA / multi-internet
        knobs). The svc wifi toggle that re-associates wlan0 is done by the
        caller (release_to_android); this only restores the OEM knobs."""
        b = self._baseline
        if not b:
            return
        if b.get("dual_sta") in ("0", "1"):
            _su(f"settings put global dual_sta_switch_on {b['dual_sta']}")
        if b.get("multi_mode") in ("0", "1", "2"):
            _su(f"cmd wifi set-multi-internet-mode {b['multi_mode']}")
        Logger.info(f"{DEADNET_PREF}: radio baseline restored (dual_sta="
                    f"{b.get('dual_sta')}, multi_mode={b.get('multi_mode')})")

    # -- dual-STA / multi-internet control (best-effort; framework-gated) ---
    def set_dual_sta(self, on: bool) -> None:
        """Permit/deny the OEM 'dual Wi-Fi acceleration' second STA. NB: this
        only *permits* wlan1 — the framework raises it on a multi-internet
        network request (an app-side ConnectivityManager API), not from here."""
        _su(f"settings put global dual_sta_switch_on {1 if on else 0}")
        _su(f"cmd wifi set-multi-internet-mode {2 if on else 0}")

    # -- guaranteed restore -------------------------------------------------
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
                # not on the main thread (e.g. inside Kivy worker) — atexit still covers us
                pass
        self._guards_installed = True

    def _emergency_release(self) -> None:
        if self.state in (CardState.MONITOR, CardState.SEIZING):
            Logger.warning(f"{DEADNET_PREF}: radio emergency release-back")
            try:
                self.release_to_android(wait_reconnect=False)
            except Exception:  # noqa: BLE001
                # last-ditch: always try to give Wi-Fi back to the owner
                _su(f"iw dev {self.mon_iface} del")
                _su(f"ip link set {self.managed_iface} up")
                _su("svc wifi disable")
                _su("svc wifi enable")

    # -- RECON (monitor) ----------------------------------------------------
    def _sibling_vifs(self) -> List[str]:
        """Every wifi vif currently present (wlan0 / p2p0 / wifi-aware0 / ...),
        excluding our own monitor vif. On this single-RF-chain phy a monitor
        cannot coexist with ANY of them, so they must all be downed before the
        monitor can tune (proven on CPH: `svc wifi disable` leaves p2p0 + NAN up
        and the tune fails -16 busy until they are explicitly `ip link set down`)."""
        try:
            out = _su("iw dev")
            names = re.findall(r"Interface\s+(\S+)", out.stdout or "")
        except Exception:  # noqa: BLE001
            names = []
        seen = []
        for n in names:
            if n != self.mon_iface and n not in seen:
                seen.append(n)
        return seen or [self.managed_iface]

    def start_recon(self, channel: int = 6) -> bool:
        """Seize the radio into monitor mode on `channel`. PROVEN order 'B'."""
        with self._lock:
            self._install_guards()
            if self.state == CardState.MONITOR:
                return self.set_channel(channel)
            self.capture_baseline()           # snapshot "how it was found" first
            self.state = CardState.SEIZING
            phy = self.phy()
            self._seized_vifs = self._sibling_vifs()   # remember to restore on release
            _su("svc wifi disable")
            time.sleep(2.0)                                    # let framework drop the link
            # Clear the whole RF chain: down EVERY sibling vif, not just wlan0 —
            # p2p0 (managed) + wifi-aware0 (NAN) otherwise hold the radio and the
            # monitor cannot tune (-16 busy). This is why mon mode regressed once
            # the OEM dual-STA / Wi-Fi-Aware vifs became active.
            for vif in self._seized_vifs:
                _su(f"ip link set {vif} down")
            _su(f"ip link set {self.managed_iface} down")      # belt-and-suspenders
            # fresh vif: delete any stale one first (idempotent)
            _su(f"iw dev {self.mon_iface} del")
            add = _su(f"iw phy {phy} interface add {self.mon_iface} type monitor")
            if not _ok(add):
                Logger.error(f"{DEADNET_PREF}: radio add {self.mon_iface} failed: {(add.stderr or add.stdout).strip()}")
                self.state = CardState.ERROR
                self.release_to_android()
                return False
            _su(f"ip link set {self.mon_iface} up")
            ok = self.set_channel(channel)
            if not ok:
                Logger.error(f"{DEADNET_PREF}: radio could not tune {self.mon_iface} (busy?)")
                self.state = CardState.ERROR
                self.release_to_android()
                return False
            self.state = CardState.MONITOR
            Logger.info(f"{DEADNET_PREF}: radio MONITOR on {self.mon_iface} ch{channel} ({phy})")
            return True

    def set_channel(self, channel: int) -> bool:
        cp = _su(f"iw dev {self.mon_iface} set channel {channel}")
        if not _ok(cp):
            # stderr is merged into stdout by the persistent root shell, so read both
            Logger.warning(f"{DEADNET_PREF}: set channel {channel} failed: "
                           f"{(cp.stderr or cp.stdout).strip()!r}")
        return _ok(cp)

    def start_hopping(self, channels: Optional[List[int]] = None, dwell_s: float = 0.25) -> None:
        """Background channel hop while in MONITOR. No-op if not seized."""
        with self._lock:
            if self.state != CardState.MONITOR:
                Logger.warning(f"{DEADNET_PREF}: start_hopping ignored (state={self.state})")
                return
            self.stop_hopping()
            chans = channels or CHANNELS_24
            self._hop_stop.clear()

            def _loop():
                i = 0
                while not self._hop_stop.is_set():
                    self.set_channel(chans[i % len(chans)])
                    i += 1
                    self._hop_stop.wait(dwell_s)

            self._hop_thread = threading.Thread(target=_loop, name="radio-hop", daemon=True)
            self._hop_thread.start()
            Logger.info(f"{DEADNET_PREF}: radio hopping {chans} dwell={dwell_s}s")

    def stop_hopping(self) -> None:
        self._hop_stop.set()
        t = self._hop_thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        self._hop_thread = None

    # -- RELEASE-BACK (-> Android / managed) --------------------------------
    def release_to_android(self, wait_reconnect: bool = True, timeout_s: float = 25.0) -> bool:
        """Tear down monitor and hand the radio back to Android. PROVEN + idempotent."""
        with self._lock:
            self.stop_hopping()
            # Did we actually seize the radio into monitor? Only then must we
            # toggle Wi-Fi to force re-association. In the associate-first flow we
            # never leave MANAGED, so we skip the toggle and keep adb/tailscale on
            # wlan0 alive — "leave it how it was found" without the disruption.
            was_seized = self.state in (CardState.MONITOR, CardState.SEIZING)
            if self.state not in (CardState.ERROR, CardState.ANDROID):
                self.state = CardState.RELEASING
            _su(f"iw dev {self.mon_iface} del")
            _su(f"ip link set {self.managed_iface} up")
            # Bring the sibling vifs we downed for the seize back up, else the
            # framework can be left with a DORMANT/NO-CARRIER wlan0 that never
            # re-associates after a monitor interlude.
            for vif in self._seized_vifs:
                _su(f"ip link set {vif} up")
            self._seized_vifs = []
            if was_seized:
                # Force a disable->enable toggle: after recon the framework can still
                # read wifi_on=1, so a bare `svc wifi enable` is a no-op and wlan0 never
                # re-associates. Toggling guarantees the framework re-kicks association.
                # (Proven on-device: bare enable left wlan0 "Not connected"; toggle fixed it.)
                _su("svc wifi disable")
                _su("svc wifi enable")
            # put the OEM dual-STA / multi-internet knobs back how we found them
            self.restore_baseline()
            self.state = CardState.ANDROID
            Logger.info(f"{DEADNET_PREF}: radio released to Android "
                        f"(wifi toggle={'yes' if was_seized else 'no'})")
        if not wait_reconnect:
            return True
        return self.wait_associated(timeout_s)

    # -- LOCK & LEVEL (managed/attack) --------------------------------------
    def ensure_managed(self, timeout_s: float = 25.0) -> bool:
        """Guarantee the radio is associated (attack needs an associated link)."""
        with self._lock:
            if self.state == CardState.MONITOR:
                self.release_to_android(wait_reconnect=False)
            if self.is_associated():
                self.state = CardState.MANAGED
                return True
            _su("svc wifi enable")
        if self.wait_associated(timeout_s):
            self.state = CardState.MANAGED
            return True
        return False

    def wait_associated(self, timeout_s: float = 25.0) -> bool:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            bssid = self.is_associated()
            if bssid:
                Logger.info(f"{DEADNET_PREF}: radio associated -> {bssid}")
                return True
            time.sleep(2.0)
        Logger.warning(f"{DEADNET_PREF}: radio did not re-associate within {timeout_s}s")
        return False

    # -- context manager ----------------------------------------------------
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._emergency_release()
        return False


if __name__ == "__main__":
    # Off-device structural self-test (pure helpers + state machine with _su mocked).
    assert phy_for_iface("wlan0", "phy0\n") == "phy0"
    assert phy_for_iface("wlan0", "") is None
    assert parse_link("Connected to 7c:db:98:64:54:9a (on wlan0)") == "7c:db:98:64:54:9a"
    assert parse_link("Not connected.") is None

    log: List[str] = []

    def fake_su(cmd, timeout=15.0):
        log.append(cmd)
        out = ""
        if cmd.startswith("cat /sys/class/net"):
            out = "phy0\n"
        elif "link" in cmd and cmd.startswith("iw dev"):
            # associated only after svc wifi enable has been issued
            out = "Connected to aa:bb:cc:dd:ee:ff (on wlan0)" if any("svc wifi enable" in c for c in log) else "Not connected."
        return subprocess.CompletedProcess(cmd, 0, out, "")

    globals()["_su"] = fake_su

    rc = RadioController()
    rc._install_guards = lambda: None  # don't register real signal handlers in test

    assert rc.start_recon(channel=6) is True, rc.state
    assert rc.state == CardState.MONITOR
    # proven order B present and correctly sequenced
    joined = " || ".join(log)
    assert log.index("svc wifi disable") < log.index("ip link set wlan0 down")
    assert any("interface add mon0 type monitor" in c for c in log)
    assert log.index("ip link set wlan0 down") < next(i for i, c in enumerate(log) if "interface add mon0" in c)
    assert any("set channel 6" in c for c in log)

    assert rc.set_channel(36) is True
    log.clear()
    assert rc.release_to_android(wait_reconnect=True) is True
    assert rc.state == CardState.ANDROID
    # proven release order: del mon0 -> wlan0 up -> svc wifi enable
    assert log.index("iw dev mon0 del") < log.index("ip link set wlan0 up") < log.index("svc wifi enable")

    assert rc.ensure_managed(timeout_s=1) is True
    assert rc.state == CardState.MANAGED

    print("recon seq:", [c for c in ["svc wifi disable", "ip link set wlan0 down"]])
    print("U6(RadioController) PASS")
