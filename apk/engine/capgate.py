"""
CapGate (v3 M3) — refuse to attack unless the patched cfg80211 is live.

v3's attack core is 802.11 mgmt-TX through the **patched** cfg80211 (three
injection gates neutralised; see `op12/wifi-modem-seams.md`). On stock the same
frames are rejected (`-EINVAL` at the SA anti-spoof / TX-subtype-mask gates), so
the app must not pretend an attack is running. CapGate decides "can I attack?"
two ways:

  1. **probe** (definitive, needs a radio): send one inert frame with a SPOOFED
     source address to bogus addresses. Stock rejects it, the patch accepts it.
     Non-disruptive — nothing real is affected.
  2. **vermagic** (cheap fallback): the patched module's vermagic carries a
     `dirty`/`maybe-dirty` marker. A hint only; the probe is authoritative.

The gate never blocks RECON — only ATTACK. Stdlib only.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.mgmt_tx import BC, DEFAULT_FREQ, fr  # noqa: E402

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:  # noqa: D101
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

DEADNET_PREF = "DeadNet"

CFG80211_KO = "/vendor_dlkm/lib/modules/cfg80211.ko"
DIRTY_MARKERS = ("maybe-dirty", "-dirty", "dirty")
# inert spoofed-SA probe: public action (cat 04) from a bogus SA to bogus addrs.
# Stock cfg80211 rejects the spoofed SA (EINVAL @ mlme.c:822); the patch accepts.
PROBE_FRAME = fr("d000", BC, "021122334455", "aabbccddeeff", "0400")


def _su(cmd: str, timeout: float = 10.0) -> Tuple[int, str]:
    from engine import rootshell as _root  # local import: avoid import cycles
    return _root.su_rc(cmd, timeout)


def vermagic_patched(v: str) -> bool:
    """True if a cfg80211 vermagic string carries a patched-build marker."""
    s = (v or "").lower()
    return any(m in s for m in DIRTY_MARKERS)


@dataclass
class CapResult:
    patched: bool = False
    decided_by: str = "none"          # "probe" | "vermagic" | "none"
    reason: str = ""
    detail: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.patched


class CapGate:
    """Decides whether the patched cfg80211 is in effect (probe > vermagic)."""

    def __init__(self, iface: str = "wlan0", tx_send: Optional[Callable] = None,
                 freq: int = DEFAULT_FREQ):
        self.iface = iface
        self.tx_send = tx_send
        self.freq = freq

    # -- cheap checks ------------------------------------------------------
    def vermagic(self) -> str:
        _, out = _su(f"modinfo {CFG80211_KO} 2>/dev/null | grep -m1 vermagic")
        s = (out or "").strip()
        if s:
            return s.split("vermagic:", 1)[-1].strip()
        # sysfs fallback (often empty on this kernel)
        try:
            with open("/sys/module/cfg80211/vermagic", errors="replace") as f:
                return f.read().strip()
        except OSError:
            return ""

    def loaded(self) -> bool:
        """Is cfg80211 actually loaded? (cheap, no radio)."""
        _, out = _su("lsmod 2>/dev/null | grep -w cfg80211")
        if out and "cfg80211" in out:
            return True
        return os.path.isdir("/sys/module/cfg80211")

    # -- definitive check --------------------------------------------------
    def probe(self) -> bool:
        """Send one inert spoofed-SA frame; True iff the kernel accepts it."""
        if self.tx_send is None:
            return False
        try:
            ok, _ = self.tx_send(self.iface, self.freq, PROBE_FRAME, False)
            return bool(ok)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: capgate probe failed: {exc}")
            return False

    def check(self, allow_probe: bool = True) -> CapResult:
        """Return the gate decision. Probe is authoritative when a tx path and
        `allow_probe` are available; otherwise fall back to the vermagic hint."""
        vm = self.vermagic()
        detail = {"vermagic": vm, "loaded": self.loaded(), "iface": self.iface}
        if allow_probe and self.tx_send is not None:
            patched = self.probe()
            detail["probe"] = patched
            if patched:
                return CapResult(True, "probe",
                                 "patched cfg80211 confirmed (spoofed-SA accepted)", detail)
            return CapResult(False, "probe",
                             "attack rejected — stock cfg80211 in effect (SA/subtype gate)",
                             detail)
        if vermagic_patched(vm):
            return CapResult(True, "vermagic",
                             f"patched cfg80211 inferred from vermagic ({vm})", detail)
        return CapResult(False, "vermagic",
                         "no patched-cfg80211 marker and no probe available", detail)


if __name__ == "__main__":
    # Off-device self-test (no device / no root).
    import sys as _sys
    log = []

    def fake_su(cmd, timeout=10.0):
        log.append(cmd)
        if "modinfo" in cmd:
            return (0, "vermagic: 6.1.118-android14-11-o-maybe-dirty SMP preempt aarch64\n")
        if "lsmod" in cmd:
            return (0, "cfg80211 1081344 2 qca_cld3_kiwi_v2,mac80211\n")
        return (0, "")

    _sys.modules[__name__]._su = fake_su

    assert vermagic_patched("6.1.118-...-maybe-dirty SMP") is True
    assert vermagic_patched("6.1.118-...-o-g818f2506c9e7") is False
    print("  [1] vermagic_patched markers  ok")

    # probe decides when a tx path is present
    g = CapGate(tx_send=lambda i, f, h, fa: (True, False))
    r = g.check()
    assert r.patched and r.decided_by == "probe" and r.detail["vermagic"].endswith("aarch64"), r
    print("  [2] probe accept -> patched  ok")

    g2 = CapGate(tx_send=lambda i, f, h, fa: (False, False))
    r2 = g2.check()
    assert (not r2.patched) and r2.decided_by == "probe", r2
    print("  [3] probe reject -> not patched (stock)  ok")

    # no tx path -> vermagic fallback
    g3 = CapGate(tx_send=None)
    r3 = g3.check()
    assert r3.patched and r3.decided_by == "vermagic" and r3.detail["loaded"] is True, r3
    print("  [4] vermagic fallback (loaded, dirty marker)  ok")

    print("CAPGATE PASS")
