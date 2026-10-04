"""
ToolBroker — resolve external tool binaries while staying in the Android namespace.

Owner directive: NO chroot. Everything runs on-host. Tools we need but Android lacks
(e.g. wpa_supplicant, a dhcp client) are delivered by a Magisk module (see apk/magisk/)
that drops them into a system path. This broker resolves each tool in a fixed order and
reports honestly when a capability is unavailable, so the UI can stub the action with a
clear message instead of failing obscurely.

Resolution order for a tool name:
  1. host PATH (/system/bin, /vendor/bin, /system/xbin ...)   -- e.g. iw, ip, tcpdump, wpa_cli
  2. Magisk module bin dir (/data/adb/modules/deadnet/system/bin)
  3. our app-bundled engine copied next to the other native binaries (emit/sniff/synscan)

Everything is executed under `su -c` to match the rest of the app.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional, Dict, List

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

DEADNET_PREF = "DeadNet"

# Where the Magisk module lands once installed.
MAGISK_MODULE_ID = "deadnet"
MAGISK_BIN_DIR = f"/data/adb/modules/{MAGISK_MODULE_ID}/system/bin"

# Standard on-device search locations (host namespace only — no chroot paths).
HOST_BIN_DIRS = ("/system/bin", "/system/xbin", "/vendor/bin", "/odm/bin", MAGISK_BIN_DIR)

# Logical capabilities -> candidate binary names (first found wins).
CAPABILITY_TOOLS: Dict[str, List[str]] = {
    "iw": ["iw"],
    "ip": ["ip"],
    "tcpdump": ["tcpdump"],
    "rfkill": ["rfkill"],
    "wpa_cli": ["wpa_cli"],
    "wpa_supplicant": ["wpa_supplicant"],
    "dhcp": ["dhcpcd", "dhclient", "udhcpc", "dhcptool"],
    "ping": ["ping"],
}


def _su(cmd: str, timeout: float = 6.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["su", "-c", cmd], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: toolbroker _su error {e}")
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


class ToolBroker:
    def __init__(self, app_native_dir: Optional[str] = None):
        # where the app copies its own bundled engines (emit/sniff/synscan/...)
        self.app_native_dir = app_native_dir
        self._cache: Dict[str, Optional[str]] = {}

    # -- resolution ---------------------------------------------------------
    def _which_host(self, name: str) -> Optional[str]:
        # try `command -v` under su first (honours the device's real PATH), then fixed dirs
        r = _su(f"command -v {name} 2>/dev/null")
        path = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
        if path and self._exists(path):
            return path
        for d in HOST_BIN_DIRS:
            cand = f"{d}/{name}"
            if self._exists(cand):
                return cand
        return None

    def _which_bundled(self, name: str) -> Optional[str]:
        if not self.app_native_dir:
            return None
        cand = os.path.join(self.app_native_dir, name)
        return cand if os.path.exists(cand) else None

    @staticmethod
    def _exists(path: str) -> bool:
        return _su(f"[ -e {path} ] && echo 1 || echo 0").stdout.strip().endswith("1")

    def resolve(self, capability: str) -> Optional[str]:
        """Return an executable path for a logical capability, or None if unavailable."""
        if capability in self._cache:
            return self._cache[capability]
        names = CAPABILITY_TOOLS.get(capability, [capability])
        found: Optional[str] = None
        for name in names:
            found = self._which_host(name) or self._which_bundled(name)
            if found:
                break
        if found is None:
            Logger.warning(f"{DEADNET_PREF}: toolbroker capability '{capability}' UNAVAILABLE "
                           f"(tried {names}); UI should stub the action")
        else:
            Logger.info(f"{DEADNET_PREF}: toolbroker '{capability}' -> {found}")
        self._cache[capability] = found
        return found

    def available(self, capability: str) -> bool:
        return self.resolve(capability) is not None

    def capabilities(self) -> Dict[str, Optional[str]]:
        """Snapshot of every known capability -> resolved path (or None)."""
        return {cap: self.resolve(cap) for cap in CAPABILITY_TOOLS}

    def magisk_module_installed(self) -> bool:
        return self._exists(f"/data/adb/modules/{MAGISK_MODULE_ID}")


if __name__ == "__main__":
    # Off-device structural self-test: resolution ORDER + unavailable handling, with _su mocked.
    import types

    tb = ToolBroker(app_native_dir="/tmp/nonexistent_native")

    calls = {"host": {}, "exists": set()}

    def fake_su(cmd, timeout=6.0):
        # emulate: iw/ip/tcpdump/wpa_cli exist on host; wpa_supplicant & dhcp do NOT.
        out = ""
        if cmd.startswith("command -v "):
            name = cmd.split()[2]
            host_have = {"iw": "/system/bin/iw", "ip": "/system/bin/ip",
                         "tcpdump": "/system/bin/tcpdump", "wpa_cli": "/vendor/bin/wpa_cli",
                         "ping": "/system/bin/ping"}
            out = host_have.get(name, "")
        elif cmd.startswith("[ -e "):
            path = cmd.split()[2]
            present = {"/system/bin/iw", "/system/bin/ip", "/system/bin/tcpdump",
                       "/vendor/bin/wpa_cli", "/system/bin/ping"}
            out = "1" if path in present else "0"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    globals()["_su"] = fake_su  # patch the module-global _su the methods call

    assert tb.resolve("iw") == "/system/bin/iw", tb.resolve("iw")
    assert tb.resolve("wpa_cli") == "/vendor/bin/wpa_cli"
    assert tb.available("tcpdump") is True
    assert tb.resolve("wpa_supplicant") is None, "should be unavailable -> None"
    assert tb.available("dhcp") is False
    caps = tb.capabilities()
    assert caps["iw"] and caps["wpa_supplicant"] is None
    print("resolved:", {k: v for k, v in caps.items() if v})
    print("unavailable:", [k for k, v in caps.items() if v is None])
    print("U7(ToolBroker) PASS")
