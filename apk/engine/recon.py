"""
Recon (v3 M2) — monitor-mode target discovery for the own-the-PHY app.

While the PHY is owned in `PhyMode.RECON` (see `engine/phyguard.py`), Recon
turns the monitor iface's 802.11 stream into a live **target inventory**: the
access points on air and the stations talking through them — including stations
hidden by client isolation, which an associated/L3 sweep can never see.

This module is deliberately standalone (it does NOT reuse the retired
`finder_air.py`): it owns its frame-line parser, its `Target` model and its
`TargetStore`. Capture is `tcpdump -e -nn` under `su -c` (the pattern proven by
the app's earlier air finder); the pure parser and store are unit-testable
off-device, and the capture command can be overridden for tests.

A native radiotap parser (`src/recon.cpp`) is a planned optimisation (M2
follow-up) — `capture_cmd()` is the single seam where it would slot in.

Stdlib only: re, subprocess, threading, dataclasses.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from kivy.logger import Logger
except Exception:  # off-device / bare test env
    class _L:  # noqa: D101
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    Logger = _L()

try:
    from engine.contracts import now_ms
    from engine import oui as _oui
except Exception:  # loose-script fallback
    import time as _time
    def now_ms() -> int:  # type: ignore
        return int(_time.time() * 1000)
    _oui = None  # type: ignore

DEADNET_PREF = "DeadNet"
KIND_AP = "ap"
KIND_STA = "station"

# social 2.4 GHz first, then common 5 GHz — the recon hop order
CHANNELS_24 = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
DEFAULT_CHANNELS = CHANNELS_24 + CHANNELS_5


# ---------------------------------------------------------------------------
# pure helpers (no I/O — unit-testable without a device)
# ---------------------------------------------------------------------------
def freq_to_channel(mhz: int) -> int:
    """2.4GHz: 2412->1 .. 2472->13, 2484->14. 5GHz: (mhz-5000)/5.
    6GHz (Wi-Fi 6E, 5955->1 .. 7115->233): (mhz-5950)/5. Unknown -> 0."""
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return 1 + (mhz - 2412) // 5
    if 5925 <= mhz <= 7125:                 # 6 GHz band (own numbering)
        return (mhz - 5950) // 5
    if mhz >= 5000:
        return (mhz - 5000) // 5
    return 0


def channel_to_freq(ch: int) -> int:
    """Inverse of freq_to_channel for the channels we hop."""
    ch = int(ch)
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if ch >= 32:
        return 5000 + ch * 5
    return 0


_MAC_RE = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_MHZ_RE = re.compile(r"(\d+)\s*MHz")
_DB_RE = re.compile(r"(-\d+)\s*dBm?\b")
_ADDR_RE = re.compile(rf"\b(SA|DA|TA|RA|BSSID):({_MAC_RE})")
_SSID_RE = re.compile(r"(?:Beacon|Probe Response|Probe Request)\s*\(([^)]*)\)")


def mac_skip(mac: str) -> bool:
    """True for empty/broadcast/multicast/all-zero addresses we never store."""
    if not mac:
        return True
    m = mac.lower()
    if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return True
    try:
        first = int(m.split(":")[0], 16)
    except ValueError:
        return True
    return bool(first & 0x01)  # multicast/broadcast bit


@dataclass
class Target:
    """One detected electronic: an AP (kind=ap) or a station (kind=station)."""
    mac: str
    kind: str = KIND_AP
    ssid: str = ""
    channel: int = 0
    freq: int = 0
    rssi: int = 0
    ap_bssid: str = ""          # for stations: the AP they talk through
    vendor: str = ""
    first_seen_ms: int = 0
    last_seen_ms: int = 0

    def as_dict(self) -> dict:
        return asdict(self)


def parse_80211_line(line: str, oui_classify: Optional[Callable[[str], str]] = None,
                     ts: Optional[int] = None) -> List[Target]:
    """Parse ONE `tcpdump -e -nn` monitor line into 0+ Targets.

    Pure function. Beacons / Probe Responses -> an AP Target keyed by BSSID.
    Data / QoS Data -> a station Target for every non-broadcast SA/DA/TA/RA that
    isn't the BSSID itself. Broadcast/multicast addrs are dropped.
    """
    out: List[Target] = []
    s = (line or "").strip()
    if not s:
        return out
    ts = now_ms() if ts is None else ts
    oui_classify = oui_classify or (lambda _m: "")

    mhz_m = _MHZ_RE.search(s)
    freq = int(mhz_m.group(1)) if mhz_m else 0
    channel = freq_to_channel(freq) if freq else 0
    db_m = _DB_RE.search(s)
    rssi = int(db_m.group(1)) if db_m else 0

    addrs: Dict[str, str] = {}
    for m in _ADDR_RE.finditer(s):
        addrs.setdefault(m.group(1), m.group(2).lower())
    bssid = addrs.get("BSSID", "")

    is_ap_frame = ("Beacon" in s) or ("Probe Response" in s)
    if is_ap_frame and bssid and not mac_skip(bssid):
        ssid_m = _SSID_RE.search(s)
        out.append(Target(mac=bssid, kind=KIND_AP,
                          ssid=(ssid_m.group(1) if ssid_m else ""),
                          channel=channel, freq=freq, rssi=rssi,
                          ap_bssid=bssid, vendor=oui_classify(bssid),
                          first_seen_ms=ts, last_seen_ms=ts))
        return out

    # Probe Request: a station looking for a network (client-side discovery)
    if "Probe Request" in s:
        sa = addrs.get("SA", "")
        if sa and not mac_skip(sa):
            out.append(Target(mac=sa, kind=KIND_STA, channel=channel, freq=freq,
                              rssi=rssi, ap_bssid=bssid, vendor=oui_classify(sa),
                              first_seen_ms=ts, last_seen_ms=ts))
        return out

    for kind in ("SA", "DA", "TA", "RA"):
        mac = addrs.get(kind)
        if not mac or mac_skip(mac) or (bssid and mac == bssid):
            continue
        out.append(Target(mac=mac, kind=KIND_STA, channel=channel, freq=freq,
                          rssi=rssi, ap_bssid=bssid, vendor=oui_classify(mac),
                          first_seen_ms=ts, last_seen_ms=ts))
    return out


# ---------------------------------------------------------------------------
# Android-scan parser — `cmd wifi list-scan-results` (con_mode=0, no monitor)
# ---------------------------------------------------------------------------
# This device's qca driver can't make a concurrent monitor vif (-EINVAL) and its
# only monitor is global con_mode=4, which is crash-prone at boot and conflicts
# with the con_mode=0 mgmt-TX ATTACK path. So RECON reads the framework's own
# scan instead. APs only (beacons/probe-resps); stations aren't visible without
# monitor — the accepted trade for a robust, no-seize recon.
_SCAN_HDR_RE = re.compile(r"^\s*BSSID\b", re.I)
_RSSI_LEAD_RE = re.compile(r"^(-?\d+)")
_MAC_FULL_RE = re.compile(rf"^{_MAC_RE}$")


def parse_scan_results(text: str, oui_classify: Optional[Callable[[str], str]] = None,
                       ts: Optional[int] = None) -> List[Target]:
    """Parse `cmd wifi list-scan-results` output into AP Targets.

    Row shape (OxygenOS 15):
        BSSID              Frequency  RSSI              Age(sec)  SSID        Flags
        0a:72:be:f4:51:63  5220       -32(0:-33/1:-35)  72.547    Work Net    [WPA2-...][ESS]

    The first four columns never contain spaces; the SSID may ("Spectrum
    Mobile") and Flags always begin at the first '[', so SSID is the text
    between the age column and that bracket. Hidden SSIDs parse as "".
    """
    out: List[Target] = []
    ts = now_ms() if ts is None else ts
    oui_classify = oui_classify or (lambda _m: "")
    for raw in (text or "").splitlines():
        s = raw.strip()
        if not s or _SCAN_HDR_RE.match(s):
            continue
        parts = s.split(None, 4)            # bssid, freq, rssi, age, rest(SSID+flags)
        if len(parts) < 4:
            continue
        bssid = parts[0].lower()
        if not _MAC_FULL_RE.match(bssid) or mac_skip(bssid):
            continue
        try:
            freq = int(parts[1])
        except ValueError:
            continue
        m = _RSSI_LEAD_RE.match(parts[2])
        rssi = int(m.group(1)) if m else 0
        rest = parts[4] if len(parts) >= 5 else ""
        br = rest.find("[")
        ssid = (rest[:br] if br >= 0 else rest).strip()
        out.append(Target(mac=bssid, kind=KIND_AP, ssid=ssid,
                          channel=freq_to_channel(freq), freq=freq, rssi=rssi,
                          ap_bssid=bssid, vendor=oui_classify(bssid),
                          first_seen_ms=ts, last_seen_ms=ts))
    return out


# ---------------------------------------------------------------------------
# TargetStore — thread-safe inventory, merged by MAC (AP/station never demoted)
# ---------------------------------------------------------------------------
class TargetStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._by_mac: Dict[str, Target] = {}

    def upsert(self, t: Target) -> Target:
        with self._lock:
            cur = self._by_mac.get(t.mac)
            if cur is None:
                self._by_mac[t.mac] = t
                return t
            # never demote a known AP to a station
            if cur.kind == KIND_AP and t.kind == KIND_STA:
                t.kind = KIND_AP
                t.ssid = t.ssid or cur.ssid
            cur.kind = t.kind or cur.kind
            cur.ssid = t.ssid or cur.ssid
            cur.channel = t.channel or cur.channel
            cur.freq = t.freq or cur.freq
            cur.rssi = t.rssi or cur.rssi          # freshest non-zero reading
            cur.ap_bssid = t.ap_bssid or cur.ap_bssid
            cur.vendor = t.vendor or cur.vendor
            cur.last_seen_ms = t.last_seen_ms or now_ms()
            return cur

    def snapshot(self, kind: Optional[str] = None) -> List[Target]:
        with self._lock:
            vals = list(self._by_mac.values())
        if kind is not None:
            vals = [t for t in vals if t.kind == kind]
        return sorted(vals, key=lambda t: (-t.rssi, t.mac))

    def count(self, kind: Optional[str] = None) -> int:
        with self._lock:
            if kind is None:
                return len(self._by_mac)
            return sum(1 for t in self._by_mac.values() if t.kind == kind)

    def clear(self) -> None:
        with self._lock:
            self._by_mac.clear()


# ---------------------------------------------------------------------------
# ReconScanner — capture + parse + store (thin; hopping delegated)
# ---------------------------------------------------------------------------
class ReconScanner:
    """Captures 802.11 off an already-up monitor iface, parses each line into
    Targets, and updates the store. Channel hopping is delegated to `set_channel`
    (normally PhyGuard/radio) so this stays device-agnostic and testable."""

    def __init__(self, mon_iface: str = "mon0", store: Optional[TargetStore] = None,
                 on_target: Optional[Callable[[Target], None]] = None,
                 set_channel: Optional[Callable[[int], object]] = None,
                 channels: Optional[List[int]] = None, dwell_s: float = 0.25,
                 capture_cmd: Optional[str] = None, popen=None):
        self.mon_iface = mon_iface
        self.store = store if store is not None else TargetStore()
        self.on_target = on_target
        self.set_channel = set_channel
        self.channels = channels or list(DEFAULT_CHANNELS)
        self.dwell_s = dwell_s
        self._capture_cmd = capture_cmd
        self._popen = popen or subprocess.Popen
        self.scent_oui = _oui.classify if _oui is not None else (lambda _m: "")

        self._proc = None
        self._thread = None
        self._hop_thread = None
        self._stop_evt = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    def capture_cmd(self) -> str:
        return self._capture_cmd or (
            f"tcpdump -i {self.mon_iface} -e -nn -s 256 -l")

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop_evt.clear()
            cmd = self.capture_cmd()
            try:
                proc = self._popen(["su", "-c", cmd], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True,
                                   bufsize=1, start_new_session=True)
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: recon capture failed to start: {exc}")
                return
            self._proc = proc
            self._running = True
            self._thread = threading.Thread(target=self._read_loop,
                                            name=f"recon-{self.mon_iface}", daemon=True)
            self._thread.start()
            if self.set_channel is not None and self.channels:
                self._hop_thread = threading.Thread(target=self._hop_loop,
                                                    name="recon-hop", daemon=True)
                self._hop_thread.start()
            Logger.info(f"{DEADNET_PREF}: recon started on {self.mon_iface} ({cmd})")

    def _hop_loop(self) -> None:
        i = 0
        while not self._stop_evt.wait(self.dwell_s):
            try:
                self.set_channel(self.channels[i % len(self.channels)])
            except Exception:  # noqa: BLE001
                pass
            i += 1

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                if self._stop_evt.is_set():
                    break
                try:
                    targets = parse_80211_line(line, oui_classify=self.scent_oui)
                except Exception as exc:  # noqa: BLE001
                    Logger.error(f"{DEADNET_PREF}: recon parse error: {exc}")
                    continue
                for t in targets:
                    try:
                        merged = self.store.upsert(t)
                    except Exception as exc:  # noqa: BLE001
                        Logger.error(f"{DEADNET_PREF}: recon upsert failed {t.mac}: {exc}")
                        continue
                    if self.on_target is not None:
                        try:
                            self.on_target(merged)
                        except Exception as exc:  # noqa: BLE001
                            Logger.error(f"{DEADNET_PREF}: recon on_target error: {exc}")
        except Exception as exc:  # noqa: BLE001 - never raise out of the loop
            Logger.error(f"{DEADNET_PREF}: recon read loop error: {exc}")

    def stop(self) -> None:
        with self._lock:
            if not self._running and self._proc is None:
                return
            self._running = False
            self._stop_evt.set()
            proc, self._proc = self._proc, None

        if proc is not None:
            pid = proc.pid
            try:
                subprocess.run(["su", "-c", f'pkill -f "tcpdump -i {self.mon_iface}"'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                subprocess.run(["su", "-c", f"kill -9 {pid}"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                proc.wait(timeout=3)
            except Exception as exc:  # noqa: BLE001
                Logger.warning(f"{DEADNET_PREF}: recon stop error: {exc}")

        for t in (self._hop_thread, self._thread):
            if t is not None:
                t.join(timeout=3.0)
        self._hop_thread = None
        self._thread = None
        Logger.info(f"{DEADNET_PREF}: recon stopped on {self.mon_iface}")


# ---------------------------------------------------------------------------
# ScanScanner — Android-scan recon loop (no monitor, no PHY seize)
# ---------------------------------------------------------------------------
def _default_scan_run(cmd: str, timeout: float = 12.0) -> str:
    """Run a shell command as root through the shared persistent su shell,
    returning merged stdout (empty on failure). Used for `cmd wifi …`."""
    from engine import rootshell as _root
    cp = _root.su_cp(cmd, timeout)
    return getattr(cp, "stdout", "") or ""


class ScanScanner:
    """RECON without monitor: repeatedly trigger an Android Wi-Fi scan and fold
    `cmd wifi list-scan-results` into the TargetStore. The radio stays with the
    framework (con_mode=0, associated) — nothing is seized, so there is no WiFi
    disruption and ATTACK's associated mgmt-TX path is left intact.

    `run(cmd) -> stdout` is injectable so the loop is testable without a device.
    """

    def __init__(self, store: Optional[TargetStore] = None,
                 on_target: Optional[Callable[[Target], None]] = None,
                 interval_s: float = 4.0, settle_s: float = 2.5,
                 run: Optional[Callable[[str], str]] = None,
                 scan_cmd: str = "cmd wifi start-scan",
                 results_cmd: str = "cmd wifi list-scan-results"):
        self.store = store if store is not None else TargetStore()
        self.on_target = on_target
        self.interval_s = interval_s
        self.settle_s = settle_s
        self._run = run or _default_scan_run
        self.scan_cmd = scan_cmd
        self.results_cmd = results_cmd
        self.scan_oui = _oui.classify if _oui is not None else (lambda _m: "")
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop_evt.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, name="recon-scan",
                                            daemon=True)
            self._thread.start()
            Logger.info(f"{DEADNET_PREF}: recon (Android scan) started")

    def scan_once(self) -> int:
        """One scan cycle: trigger, read, fold into the store. Returns # parsed.
        Also the loop body, so it is unit-testable on its own."""
        try:
            self._run(self.scan_cmd)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: start-scan failed: {exc}")
        if self._stop_evt.wait(self.settle_s):
            return 0
        try:
            text = self._run(self.results_cmd)
        except Exception as exc:  # noqa: BLE001
            Logger.error(f"{DEADNET_PREF}: list-scan-results failed: {exc}")
            return 0
        n = 0
        for t in parse_scan_results(text, oui_classify=self.scan_oui):
            try:
                merged = self.store.upsert(t)
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: recon upsert failed {t.mac}: {exc}")
                continue
            n += 1
            if self.on_target is not None:
                try:
                    self.on_target(merged)
                except Exception as exc:  # noqa: BLE001
                    Logger.error(f"{DEADNET_PREF}: recon on_target error: {exc}")
        return n

    def _loop(self) -> None:
        while not self._stop_evt.is_set():
            try:
                self.scan_once()
            except Exception as exc:  # noqa: BLE001 - never raise out of the loop
                Logger.error(f"{DEADNET_PREF}: recon scan loop error: {exc}")
            if self._stop_evt.wait(self.interval_s):
                break

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            self._stop_evt.set()
            t, self._thread = self._thread, None
        if t is not None:
            t.join(timeout=3.0)
        Logger.info(f"{DEADNET_PREF}: recon (Android scan) stopped")


# ---------------------------------------------------------------------------
# Self-test (no device / no root)  cd apk && python3 engine/recon.py
# ---------------------------------------------------------------------------
_SAMPLE = [
    "13:12:01.100 1.0 Mb/s 2412 MHz 11b -42dB BSSID:aa:bb:cc:00:11:22 "
    "SA:aa:bb:cc:00:11:22 Beacon (HomeNet) [1.0*]",
    "13:12:01.150 1.0 Mb/s 5180 MHz 11a -55dB BSSID:10:20:30:40:50:60 "
    "SA:10:20:30:40:50:60 Probe Response (Cafe) [1.0*]",
    "13:12:01.250 6.0 Mb/s 2437 MHz 11g -55dB BSSID:aa:bb:cc:00:11:22 "
    "DA:24:3f:75:10:ae:1b SA:aa:bb:cc:00:11:22 QoS Data",
    "13:12:01.260 6.0 Mb/s 2437 MHz 11g -60dB BSSID:aa:bb:cc:00:11:22 "
    "SA:24:3f:75:10:ae:1b DA:aa:bb:cc:00:11:22 QoS Data",
    "13:12:01.300 1.0 Mb/s 2462 MHz 11b -70dB BSSID:ff:ff:ff:ff:ff:ff "
    "DA:ff:ff:ff:ff:ff:ff SA:01:00:5e:00:00:fb Data",
    "13:12:01.400 1.0 Mb/s 2412 MHz 11b -50dB BSSID:aa:bb:cc:00:11:22 "
    "DA:ff:ff:ff:ff:ff:ff SA:de:ad:be:ef:00:01 Probe Request (HomeNet)",
]


def _self_test() -> None:
    assert freq_to_channel(2412) == 1 and freq_to_channel(5180) == 36
    assert channel_to_freq(1) == 2412 and channel_to_freq(36) == 5180
    assert channel_to_freq(14) == 2484

    targets = [t for line in _SAMPLE for t in parse_80211_line(line)]
    by_mac: Dict[str, Target] = {}
    for t in targets:
        by_mac.setdefault(t.mac, t)

    ap = by_mac["aa:bb:cc:00:11:22"]
    assert ap.kind == KIND_AP and ap.ssid == "HomeNet" and ap.channel == 1 and ap.rssi == -42, ap
    cafe = by_mac["10:20:30:40:50:60"]
    assert cafe.kind == KIND_AP and cafe.ssid == "Cafe" and cafe.channel == 36, cafe

    sta = by_mac["24:3f:75:10:ae:1b"]
    assert sta.kind == KIND_STA and sta.ap_bssid == "aa:bb:cc:00:11:22", sta

    # probe-request station is discovered (client-side recon)
    pr = by_mac["de:ad:be:ef:00:01"]
    assert pr.kind == KIND_STA, pr

    # broadcast/multicast dropped
    assert "ff:ff:ff:ff:ff:ff" not in by_mac
    assert "01:00:5e:00:00:fb" not in by_mac
    print("  [1] parser: APs (beacon+probe-resp), station, probe-req seen; bcast dropped  ok")

    # store: merge, no AP->station demotion, kind filtering, rssi refresh
    st = TargetStore()
    for t in targets:
        st.upsert(t)
    assert st.count() == 4, st.count()
    assert st.count(KIND_AP) == 2 and st.count(KIND_STA) == 2
    # a later station sighting of the AP mac must not demote it
    st.upsert(Target(mac="aa:bb:cc:00:11:22", kind=KIND_STA, rssi=-80,
                     ap_bssid="x", last_seen_ms=now_ms()))
    ap2 = [t for t in st.snapshot() if t.mac == "aa:bb:cc:00:11:22"][0]
    assert ap2.kind == KIND_AP, ap2
    assert ap2.rssi == -80, "fresh non-zero rssi should refresh"
    print("  [2] store: merge, no demotion, kind filter, rssi refresh  ok")

    # scanner: capture + parse + store with a fake tcpdump process
    class _FakeStdout:
        def __init__(self, lines): self.lines = list(lines)
        def __iter__(self): return iter(self.lines)
    class _FakeProc:
        def __init__(self, lines): self.stdout = _FakeStdout(lines); self.pid = 4242
        def wait(self, timeout=None): return 0
    seen = []
    sc = ReconScanner(mon_iface="mon0", on_target=seen.append,
                      capture_cmd="fake", popen=lambda *a, **k: _FakeProc(_SAMPLE))
    sc.start()
    sc._thread.join(timeout=3.0)
    sc.stop()
    assert sc.store.count() == 4, sc.store.count()
    assert len(seen) >= 4, len(seen)
    print("  [3] scanner: capture->parse->store, on_target fired  ok")

    # scan parser: real OxygenOS `cmd wifi list-scan-results` output
    scan_text = (
        "    BSSID              Frequency      RSSI           Age(sec)     SSID                                 Flags\n"
        "  0a:72:be:f4:51:63       5220    -32(0:-33/1:-35)    72.547    WorkforceTravel                   [WPA2-PSK-CCMP-128][RSN-PSK-CCMP-128][ESS]\n"
        "  0a:72:be:f4:51:67       5220    -32(0:-33/1:-35)    72.545    Spectrum Mobile                   [WPA2-EAP/SHA256-CCMP-128][ESS][MFPR][PASSPOINT]\n"
        "  0a:aa:be:ae:88:9b       5220    -72(0:-78/1:-73)    72.565    Not an FBI Van                    [WPA2-PSK-CCMP-128][ESS]\n"
        "  ff:ff:ff:ff:ff:ff       2412    -50               1.0        BcastShouldDrop                   [ESS]\n"
        "  88:33:74:04:f5:e0       2462    -72(0:-76/1:-75)    72.332                                      [WPA2-PSK-CCMP-128][ESS]\n")
    aps = parse_scan_results(scan_text)
    by = {t.mac: t for t in aps}
    assert len(aps) == 4, (len(aps), [t.mac for t in aps])          # broadcast dropped
    w = by["0a:72:be:f4:51:63"]
    assert w.kind == KIND_AP and w.ssid == "WorkforceTravel" and w.freq == 5220
    assert w.channel == 44 and w.rssi == -32, w                     # 5220 -> ch44, leading RSSI
    assert by["0a:72:be:f4:51:67"].ssid == "Spectrum Mobile", "SSID with a space"
    assert by["0a:aa:be:ae:88:9b"].ssid == "Not an FBI Van", "SSID with spaces"
    assert by["88:33:74:04:f5:e0"].ssid == "", "hidden/blank SSID -> empty"
    assert "ff:ff:ff:ff:ff:ff" not in by
    print("  [4] scan parser: APs, spaced SSIDs, hidden SSID, bcast dropped  ok")

    # ScanScanner: trigger->read->store loop with a fake `run`
    calls = []
    def fake_run(cmd, timeout=12.0):
        calls.append(cmd)
        return scan_text if "list-scan-results" in cmd else ""
    seen2 = []
    ss = ScanScanner(on_target=seen2.append, run=fake_run)
    got = ss.scan_once()
    assert got == 4 and ss.store.count() == 4, (got, ss.store.count())
    assert calls[0] == "cmd wifi start-scan" and "list-scan-results" in calls[1]
    assert len(seen2) == 4
    print("  [5] scan scanner: start-scan + list-scan-results -> store  ok")

    print("RECON PASS")


if __name__ == "__main__":
    _self_test()
