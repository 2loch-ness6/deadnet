"""
DeadNet engine — U5b: Finder-Air (monitor-mode 802.11 discovery, the AIR
sibling of U5's Finder-Wire in ``engine/finder.py``).

Populates the known_scents master store (``DB_KNOWN_SCENTS``) via the
Arbiter (U2 / ``RowReaderArbiter``) by capturing raw 802.11 management and
data frames off a monitor-mode interface. Interface seizure + channel
hopping is owned elsewhere (``engine/radio.py``); this unit only consumes
an already-up monitor iface name and turns tcpdump's `-e -nn` text stream
into ``ScentRecord`` rows:

  * Beacon / Probe Response frames carry an AP's BSSID + SSID -> an AP
    ScentRecord (``is_station=False``).
  * Data / QoS Data frames carry SA/DA (+ TA/RA) around a BSSID -> each
    non-broadcast, non-multicast address that isn't the BSSID itself is a
    STATION ScentRecord (``is_station=True``, ``ap_bssid=BSSID``).

The frame-text parser (``parse_tcpdump_80211``) is a pure function — no
subprocess calls, no Arbiter writes — so it is unit-testable without a
device. Capture + storage lives in ``FinderAir``, which spawns `tcpdump`
under root (matching the `su -c` pattern used throughout this app) and
reads its stdout on a background thread, mirroring ``SurvivalMonitor``
(``apk/survival_monitor.py``) and ``finder.py``'s own upsert style.

Stdlib only: re, subprocess, threading.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import subprocess
from typing import Callable, Dict, List, Optional

# Make `import engine.*` work whether this module is imported as part of the
# app (apk/ already on sys.path per CONTRACTS.md) or run standalone as
# `python3 engine/finder_air.py` from inside apk/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.contracts import ScentRecord, DB_KNOWN_SCENTS, now_ms  # noqa: E402
from engine import oui as _oui  # noqa: E402
from engine.finder import upsert_scent  # noqa: E402 - mirror U5's helper, don't redefine it

try:
    from kivy.logger import Logger
except Exception:  # pragma: no cover - off-device / bare test env
    class _StubLogger:
        def info(self, *a, **k):
            pass

        def error(self, *a, **k):
            pass

        def warning(self, *a, **k):
            pass

    Logger = _StubLogger()

DEADNET_PREF = "DeadNet"


def _log(msg: str) -> None:
    Logger.info(f"{DEADNET_PREF}: finder_air: {msg}")


# ----------------------------------------------------------------------------
# Pure helpers — no I/O, unit-testable without a device
# ----------------------------------------------------------------------------
def freq_to_channel(mhz: int) -> int:
    """2.4GHz: 2412->1 .. 2472->13, 2484->14. 5GHz: (mhz-5000)/5. Unknown -> 0."""
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return 1 + (mhz - 2412) // 5
    if mhz >= 5000:
        return (mhz - 5000) // 5
    return 0


_MAC_RE = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_MHZ_RE = re.compile(r"(\d+)\s*MHz")
_DB_RE = re.compile(r"(-\d+)\s*dBm?\b")
_ADDR_RE = re.compile(rf"\b(SA|DA|TA|RA|BSSID):({_MAC_RE})")
_SSID_RE = re.compile(r"(?:Beacon|Probe Response)\s*\(([^)]*)\)")


def _mac_skip(mac: str) -> bool:
    """True for empty/broadcast/multicast/all-zero addresses we never store."""
    if not mac:
        return True
    m = mac.lower()
    if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return True
    try:
        first_octet = int(m.split(":")[0], 16)
    except ValueError:
        return True
    return bool(first_octet & 0x01)  # multicast/broadcast bit


def parse_tcpdump_80211(
    lines,
    oui_classify: Optional[Callable[[str], str]] = None,
) -> List[ScentRecord]:
    """Parse `tcpdump -i <mon> -e -nn -s 256 -l` text lines into deduped
    ScentRecords, merged by mac.

    Pure function: no subprocess calls, no Arbiter writes. `oui_classify`
    defaults to a lambda returning "" so this is usable with no device and
    no oui.csv present.
    """
    if oui_classify is None:
        oui_classify = lambda _mac: ""  # noqa: E731

    ts = now_ms()
    records: Dict[str, ScentRecord] = {}

    def _get_or_create(mac: str, is_station: bool) -> ScentRecord:
        rec = records.get(mac)
        if rec is None:
            rec = ScentRecord(
                mac=mac,
                vendor=oui_classify(mac),
                is_station=is_station,
                first_seen_ms=ts,
                last_seen_ms=ts,
            )
            records[mac] = rec
        else:
            rec.last_seen_ms = ts
        return rec

    for raw in lines:
        line = raw.strip() if raw else ""
        if not line:
            continue

        mhz_m = _MHZ_RE.search(line)
        channel = freq_to_channel(int(mhz_m.group(1))) if mhz_m else 0

        db_m = _DB_RE.search(line)
        signal = int(db_m.group(1)) if db_m else 0

        addrs: Dict[str, str] = {}
        for m in _ADDR_RE.finditer(line):
            kind, mac = m.group(1), m.group(2).lower()
            addrs.setdefault(kind, mac)

        bssid = addrs.get("BSSID", "")
        is_ap_frame = "Beacon" in line or "Probe Response" in line

        if is_ap_frame and bssid and not _mac_skip(bssid):
            ssid_m = _SSID_RE.search(line)
            ssid = ssid_m.group(1) if ssid_m else ""

            rec = _get_or_create(bssid, is_station=False)
            rec.is_station = False
            rec.ssid = ssid or rec.ssid
            rec.ap_bssid = bssid
            if channel:
                rec.channel = channel
            if signal:
                rec.signal_dbm = signal
            continue

        # Data / QoS Data: any non-broadcast/multicast SA/DA/TA/RA that isn't
        # the BSSID itself is a station associated with that BSSID.
        for kind in ("SA", "DA", "TA", "RA"):
            mac = addrs.get(kind)
            if not mac or _mac_skip(mac):
                continue
            if bssid and mac == bssid:
                continue
            existing = records.get(mac)
            if existing is not None and existing.is_station is False:
                continue  # never demote an already-known AP

            rec = _get_or_create(mac, is_station=True)
            if bssid:
                rec.ap_bssid = bssid
            if channel:
                rec.channel = channel
            if signal:
                rec.signal_dbm = signal

    return list(records.values())


# ----------------------------------------------------------------------------
# FinderAir — monitor-mode capture producer
# ----------------------------------------------------------------------------
class FinderAir:
    """Captures 802.11 frames off an already-up monitor iface via `tcpdump`
    (under root), parses them, and upserts ScentRecords into known_scents.

    `mon_iface` is handed to us already in monitor mode and channel-hopping
    (owned by engine/radio.py). We only capture + parse + store.
    """

    def __init__(self, arbiter, mon_iface: str, net_id: str = "air", on_scent=None,
                 bssid_filter: Optional[str] = None):
        self.arbiter = arbiter
        self.mon_iface = mon_iface
        self.net_id = net_id
        self.on_scent = on_scent
        # When set, keep ONLY records belonging to this BSSID (the airspace we
        # joined): our own AP (mac==bssid) and any station whose ap_bssid==bssid.
        # Foreign APs/stations heard on the same channel are dropped so the
        # master store stays scoped to "air we hold a key to".
        self.bssid_filter = bssid_filter.lower() if bssid_filter else None

        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    def _in_airspace(self, rec) -> bool:
        """True if `rec` belongs to the joined airspace (or no filter is set).
        Our AP's beacons set ap_bssid to its own BSSID and each station carries
        the BSSID it talks through, so a single ap_bssid==filter test covers both."""
        if self.bssid_filter is None:
            return True
        return (rec.ap_bssid or "").lower() == self.bssid_filter

    # ------------------------------------------------------------- control
    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop_evt.clear()
            cmd = f"tcpdump -i {self.mon_iface} -e -nn -s 256 -l"
            try:
                proc = subprocess.Popen(
                    ["su", "-c", cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
            except Exception as exc:  # noqa: BLE001
                _log(f"failed to start tcpdump on {self.mon_iface}: {exc}")
                return

            self._proc = proc
            self._running = True
            self._thread = threading.Thread(
                target=self._read_loop, name=f"finderair-{self.mon_iface}", daemon=True
            )
            self._thread.start()
            _log(f"started tcpdump on {self.mon_iface} (pid {proc.pid})")

    def stop(self) -> None:
        with self._lock:
            if not self._running and self._proc is None:
                return
            self._running = False
            self._stop_evt.set()
            proc = self._proc
            self._proc = None

        if proc is not None:
            pid = proc.pid
            try:
                # toybox-safe: pkill by command-line match, then a belt-and-
                # suspenders kill -9 by pid (matches SurvivalMonitor.stop()).
                subprocess.run(
                    ["su", "-c", f'pkill -f "tcpdump -i {self.mon_iface}"'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                subprocess.run(
                    ["su", "-c", f"kill -9 {pid}"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                proc.wait(timeout=3)
            except Exception as exc:  # noqa: BLE001
                _log(f"stop error: {exc}")
            _log(f"stopped tcpdump on {self.mon_iface} (pid {pid})")

        t = self._thread
        self._thread = None
        if t is not None:
            t.join(timeout=3.0)

    # --------------------------------------------------------------- loop
    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                if self._stop_evt.is_set():
                    break
                try:
                    recs = parse_tcpdump_80211([line], oui_classify=_oui.classify)
                except Exception as exc:  # noqa: BLE001
                    _log(f"parse error: {exc}")
                    continue
                for rec in recs:
                    if not self._in_airspace(rec):
                        continue  # outside the joined airspace — skip
                    rec.net_id = self.net_id
                    try:
                        upsert_scent(self.arbiter, rec)
                    except Exception as exc:  # noqa: BLE001
                        _log(f"upsert failed for {rec.mac}: {exc}")
                        continue
                    if self.on_scent is not None:
                        try:
                            self.on_scent(rec)
                        except Exception as exc:  # noqa: BLE001
                            _log(f"on_scent callback error: {exc}")
        except Exception as exc:  # noqa: BLE001 - never raise out of the loop
            _log(f"read loop error: {exc}")


# ===========================================================================
# Self-test (no device / no root). cd apk && python3 engine/finder_air.py
# ===========================================================================
_SAMPLE_LINES = [
    "13:12:01.100 1.0 Mb/s 2412 MHz 11b -42dB BSSID:aa:bb:cc:00:11:22 "
    "SA:aa:bb:cc:00:11:22 Beacon (HomeNet) [1.0*]",
    "13:12:01.250 6.0 Mb/s 2437 MHz 11g -55dB BSSID:aa:bb:cc:00:11:22 "
    "DA:24:3f:75:10:ae:1b SA:aa:bb:cc:00:11:22 QoS Data",
    "13:12:01.260 6.0 Mb/s 2437 MHz 11g -60dB BSSID:aa:bb:cc:00:11:22 "
    "SA:24:3f:75:10:ae:1b DA:aa:bb:cc:00:11:22 QoS Data",
    "13:12:01.300 1.0 Mb/s 2462 MHz 11b -70dB BSSID:ff:ff:ff:ff:ff:ff "
    "DA:ff:ff:ff:ff:ff:ff SA:01:00:5e:00:00:fb Data",
]


def _self_test() -> None:
    import tempfile

    # 1. freq_to_channel -----------------------------------------------------
    assert freq_to_channel(2412) == 1, freq_to_channel(2412)
    assert freq_to_channel(2472) == 13, freq_to_channel(2472)
    assert freq_to_channel(2484) == 14, freq_to_channel(2484)
    assert freq_to_channel(5180) == 36, freq_to_channel(5180)
    print("  [1] freq_to_channel: 2412->1, 2472->13, 2484->14, 5180->36  ok")

    # 2. parse_tcpdump_80211 --------------------------------------------------
    records = parse_tcpdump_80211(_SAMPLE_LINES)
    by_mac = {r.mac: r for r in records}

    assert "aa:bb:cc:00:11:22" in by_mac, by_mac
    ap = by_mac["aa:bb:cc:00:11:22"]
    assert ap.ssid == "HomeNet", ap
    assert ap.is_station is False, ap
    assert ap.channel == 1, ap          # from the beacon's 2412 MHz
    assert ap.signal_dbm == -42, ap
    assert ap.ap_bssid == "aa:bb:cc:00:11:22", ap

    assert "24:3f:75:10:ae:1b" in by_mac, by_mac
    sta = by_mac["24:3f:75:10:ae:1b"]
    assert sta.is_station is True, sta
    assert sta.ap_bssid == "aa:bb:cc:00:11:22", sta

    # broadcast/multicast addresses in the 4th line must produce NO records
    assert "ff:ff:ff:ff:ff:ff" not in by_mac, by_mac
    assert "01:00:5e:00:00:fb" not in by_mac, by_mac
    assert len(records) == 2, records
    print("  [2] parse_tcpdump_80211: AP + station parsed, broadcast/multicast skipped  ok")

    # oui_classify wiring
    records2 = parse_tcpdump_80211(
        _SAMPLE_LINES,
        oui_classify=lambda mac: "VendorX" if mac == "24:3f:75:10:ae:1b" else "",
    )
    by_mac2 = {r.mac: r for r in records2}
    assert by_mac2["24:3f:75:10:ae:1b"].vendor == "VendorX", by_mac2
    print("  [3] oui_classify wired through  ok")

    # 3. Arbiter round-trip ---------------------------------------------------
    from engine.arbiter import RowReaderArbiter

    tmp = tempfile.mkdtemp(prefix="finderair_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    try:
        for rec in records:
            rec.net_id = "air"
            upsert_scent(arb, rec)

        rows = arb.read(
            DB_KNOWN_SCENTS,
            "SELECT mac, ssid, ap_bssid, is_station FROM scents ORDER BY mac",
        )
        assert len(rows) == 2, rows
        by_mac3 = {r[0]: r for r in rows}

        ap_row = by_mac3["aa:bb:cc:00:11:22"]
        assert ap_row[1] == "HomeNet", ap_row
        assert ap_row[3] == 0, ap_row  # is_station False -> 0

        sta_row = by_mac3["24:3f:75:10:ae:1b"]
        assert sta_row[2] == "aa:bb:cc:00:11:22", sta_row
        assert sta_row[3] == 1, sta_row  # is_station True -> 1

        print("  [4] RowReaderArbiter round-trip: AP + station rows present  ok")

        # 4b. bssid_filter scopes capture to the joined airspace -------------
        ours = "aa:bb:cc:00:11:22"
        fa_lock = FinderAir(arb, "mon0", net_id="wlan0", bssid_filter=ours)
        assert all(fa_lock._in_airspace(r) for r in records), "our AP+station must pass"
        fa_foreign = FinderAir(arb, "mon0", net_id="wlan0",
                               bssid_filter="00:00:00:00:00:00")
        assert not any(fa_foreign._in_airspace(r) for r in records), "foreign must drop"
        fa_none = FinderAir(arb, "mon0", net_id="wlan0")  # no filter = keep all
        assert all(fa_none._in_airspace(r) for r in records), "no filter keeps all"
        print("  [4b] bssid_filter: joined airspace kept, foreign dropped  ok")
    finally:
        arb.close()
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass

    print("U5b PASS")


if __name__ == "__main__":
    _self_test()
