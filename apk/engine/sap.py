"""
SapController — SoftAP (SAP) channel-context provider for unassociated mgmt
injection on OP12 (WCN7850 / kiwi_v2).

The cfg80211 patch widens the host-side gates, but the firmware only radiates
mgmt frames on a vdev that holds channel context. An idle STA has none, so
unassociated injection needs a SoftAP vdev beaconing on the target channel; the
driver's `inject_mgmt` sysfs node then fires raw frames on that vdev. This
module owns the hostapd lifecycle + SELinux flip + sysfs write for that path.

Usage:
    sap = SapController(iface="wlan0")
    sap.start(channel=6)            # hostapd up, beacons on ch6
    ok, _ = sap.send("c000...")     # echo "0 <hex>" > inject_mgmt
    sap.stop()                      # kill hostapd, restore SELinux

Stdlib only. Headless-safe: importing spawns nothing.
"""
from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import time
from typing import Callable, Optional, Tuple

try:
    from kivy.logger import Logger
except Exception:  # noqa: BLE001
    class _L:  # noqa: D101
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

DEADNET_PREF = "DeadNet"

HOSTAPD_BIN = "/vendor/bin/hw/hostapd"
HOSTAPD_CONF = "/data/vendor/wifi/hostapd/deadnet_sap.conf"
CTRL_DIR = "/data/vendor/wifi/hostapd/ctrl"


def _root():
    from engine import rootshell
    return rootshell


class SapController:
    def __init__(self, iface: str = "wlan0", appdir: Optional[str] = None,
                 hostapd_bin: str = HOSTAPD_BIN):
        self.iface = iface
        self.appdir = appdir or "/data/local/tmp"
        self.hostapd_bin = hostapd_bin
        self.channel: int = 0
        self._active: bool = False
        self._selinux_was_enforcing: bool = False
        self._conf_path: str = HOSTAPD_CONF

    # -- lifecycle ---------------------------------------------------------
    def is_active(self) -> bool:
        return self._active

    def start(self, channel: int, ssid: str = "TestAP",
             passphrase: str = "test12345", wait: float = 2.0) -> bool:
        """Bring up a SoftAP on `channel`. Returns True if hostapd is running."""
        try:
            ch = int(channel)
        except (TypeError, ValueError):
            return False
        if ch <= 0:
            return False
        # remember SELinux state, then go permissive (hostapd needs it here)
        try:
            out = _root().su("getenforce", timeout=3).strip().lower()
            self._selinux_was_enforcing = (out == "enforcing")
        except Exception:  # noqa: BLE001
            self._selinux_was_enforcing = False
        if self._selinux_was_enforcing:
            _root().su("setenforce 0", timeout=3)
        # write a minimal hostapd config
        conf = (
            "interface=%s\n"
            "driver=nl80211\n"
            "ssid=%s\n"
            "hw_mode=g\n"
            "channel=%d\n"
            "wpa=2\n"
            "wpa_passphrase=%s\n"
            "wpa_key_mgmt=WPA-PSK\n"
            "rsn_pairwise=CCMP\n"
            "ctrl_interface=%s\n"
        ) % (self.iface, ssid, ch, passphrase, CTRL_DIR)
        # write via a root shell heredoc
        rc, _ = _root().su_rc(
            "mkdir -p %s && cat > %s <<'EOF'\n%sEOF"
            % (os.path.dirname(self._conf_path), self._conf_path, conf), timeout=5)
        if rc != 0:
            Logger.error(f"{DEADNET_PREF}: sap conf write failed rc={rc}")
            return False
        # kill any stale hostapd, then start fresh
        _root().su("pkill hostapd 2>/dev/null; sleep 0.2", timeout=3)
        rc, out = _root().su_rc("%s -B %s" % (self.hostapd_bin, self._conf_path),
                                timeout=5)
        if rc != 0:
            Logger.error(f"{DEADNET_PREF}: hostapd start failed rc={rc} {out!r}")
            return False
        self.channel = ch
        time.sleep(wait)
        self._active = True
        Logger.info(f"{DEADNET_PREF}: SAP up on {self.iface} ch{ch}")
        return True

    def stop(self) -> None:
        """Tear down the SoftAP and restore SELinux."""
        try:
            _root().su("pkill hostapd 2>/dev/null", timeout=5)
        except Exception:  # noqa: BLE001
            pass
        if self._selinux_was_enforcing:
            try:
                _root().su("setenforce 1", timeout=3)
            except Exception:  # noqa: BLE001
                pass
        self._active = False
        self.channel = 0

    # -- transmit ----------------------------------------------------------
    def send(self, hexframe: str) -> Tuple[bool, bool]:
        """Fire one raw mgmt frame via the driver's `inject_mgmt` sysfs node.
        freq is always 0 (vdev home channel) — explicit freq makes FW drop it."""
        if not self._active:
            return False, False
        hh = "".join(hexframe.split()).lower()
        rc, out = _root().su_rc(
            'echo "0 %s" > /sys/class/net/%s/inject_mgmt' % (hh, self.iface),
            timeout=5)
        if rc != 0:
            Logger.error(f"{DEADNET_PREF}: inject_mgmt write failed rc={rc} {out!r}")
            return False, False
        return True, False

    def close(self) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Self-test (no device / no root).   cd apk && python3 engine/sap.py
# ---------------------------------------------------------------------------
def _selftest() -> None:
    fails = []

    def check(name, cond):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    # monkeypatch rootshell
    import types
    calls = {"cmds": []}

    class _RS:
        def su(self, cmd, timeout=5.0):
            calls["cmds"].append(cmd)
            if cmd.strip() == "getenforce":
                return "Enforcing\n"
            return ""
        def su_rc(self, cmd, timeout=5.0):
            calls["cmds"].append(cmd)
            if "hostapd -B" in cmd:
                return 0, ""
            if "inject_mgmt" in cmd:
                return 0, ""
            if cmd.startswith("mkdir") or "cat >" in cmd:
                return 0, ""
            return 0, ""

    import engine.rootshell as rs
    inst = _RS()
    orig_root = rs.root
    rs.root = lambda: inst
    globals()["_root"] = lambda: inst

    try:
        sap = SapController(iface="wlan0", channel_dummy=0) if False else SapController(iface="wlan0")
        check("inactive initially", not sap.is_active())
        ok = sap.start(6, wait=0)
        check("start ok", ok is True and sap.is_active() and sap.channel == 6)
        # SELinux was enforcing -> flipped
        assert any("setenforce 0" in c for c in calls["cmds"])
        # sysfs send
        a, b = sap.send("c000" + "00" * 23)
        check("send ok", a is True)
        # stop restores
        sap.stop()
        check("stopped", not sap.is_active())
        assert any("setenforce 1" in c for c in calls["cmds"])
        assert any("pkill hostapd" in c for c in calls["cmds"])
        # bad channel
        sap2 = SapController(iface="wlan0")
        check("bad channel", sap2.start(0) is False and not sap2.is_active())
        # send while inactive
        check("send inactive", SapController().send("aa") == (False, False))
    finally:
        rs.root = orig_root

    print("---")
    if fails:
        print("SAP: %d FAILURES: %s" % (len(fails), fails))
        raise SystemExit(1)
    print("SAP PASS")


if __name__ == "__main__":
    _selftest()
