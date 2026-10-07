"""
DeadNet engine — Finder-Passive: discover electronics WITHOUT knocking.

Active smell (engine/finder.py) sends ARP/ICMP and waits for replies — which a
client-isolated LAN silently drops, so it under-discovers. This unit instead
runs `tcpdump` on the ASSOCIATED (managed) interface and parses the ARP traffic
every active device emits on its own. ARP is link-layer **broadcast**, so it is
delivered to every station regardless of client isolation (which only blocks
*forwarded unicast* between clients). Every `who-has ... tell <ip>` reveals a
live sender's IP+MAC, and every `Reply <ip> is-at <mac>` reveals a responder —
so simply listening populates the master store with hosts active scanning can
never reach.

It is meant to ride along during FIRE: the poison provokes victims to re-ARP for
the gateway, turning the attack itself into a discovery engine (the owner's ask:
"during active, the capture can be used to populate"). Mirrors FinderAir's
capture plumbing (root `tcpdump` + background read thread + Arbiter upserts); the
parser `parse_tcpdump_arp` is a pure, device-free function for unit tests.

Stdlib only: re, subprocess, threading.
"""
from __future__ import annotations

import os
import re
import sys
import threading
import subprocess
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.contracts import ScentRecord, DB_KNOWN_SCENTS, now_ms  # noqa: E402
from engine import oui as _oui  # noqa: E402
from engine.finder import upsert_scent  # noqa: E402
from engine.finder_air import _mac_skip  # noqa: E402 - reuse broadcast/multicast guard

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

_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"
_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
# Source ether addr sits right after the timestamp: "12:00:00.1 <srcmac> > <dst>,"
_SRC_RE = re.compile(r"^\S+\s+(" + _MAC + r")\s+>")
_TELL_RE = re.compile(r"who-has\s+(" + _IP + r")\s+tell\s+(" + _IP + r")")
_REPLY_RE = re.compile(r"Reply\s+(" + _IP + r")\s+is-at\s+(" + _MAC + r")")


def _log(msg: str) -> None:
    Logger.info(f"{DEADNET_PREF}: finder_passive: {msg}")


# ----------------------------------------------------------------------------
# Pure parser — no I/O, unit-testable without a device
# ----------------------------------------------------------------------------
def parse_tcpdump_arp(
    lines,
    oui_classify: Optional[Callable[[str], str]] = None,
) -> List[ScentRecord]:
    """Parse `tcpdump -i <iface> -nn -e -l arp` text into deduped station
    ScentRecords (merged by mac). Both ARP request and reply forms are mined:

      * Request "who-has X tell Y"  -> sender Y lives at the frame's source MAC.
      * Reply   "X is-at Z"         -> responder X lives at MAC Z.

    Pure: no subprocess, no Arbiter writes. `oui_classify` defaults to "" so it
    runs with no device and no oui.csv.
    """
    if oui_classify is None:
        oui_classify = lambda _mac: ""  # noqa: E731

    ts = now_ms()
    out: Dict[str, ScentRecord] = {}

    def _add(mac: str, ip: str) -> None:
        if _mac_skip(mac):
            return
        mac = mac.lower()
        rec = out.get(mac)
        if rec is None:
            rec = ScentRecord(mac=mac, is_station=True, first_seen_ms=ts,
                              last_seen_ms=ts)
            rec.vendor = oui_classify(mac) or ""
            out[mac] = rec
        if ip and not rec.ip:
            rec.ip = ip

    for line in lines:
        src = _SRC_RE.search(line)
        src_mac = src.group(1) if src else ""
        m = _TELL_RE.search(line)
        if m:
            # sender IP is the "tell" address; its MAC is the frame source
            _add(src_mac, m.group(2))
            continue
        r = _REPLY_RE.search(line)
        if r:
            _add(r.group(2), r.group(1))        # is-at MAC, at that IP
    return list(out.values())


# ----------------------------------------------------------------------------
# Capture service
# ----------------------------------------------------------------------------
class PassiveFinder:
    """Listens to ARP on an associated (managed) iface and upserts every live
    sender/responder into known_scents. No frames are injected — pure listen."""

    def __init__(self, arbiter, iface: str, net_id: str = "", on_scent=None):
        self.arbiter = arbiter
        self.iface = iface
        self.net_id = net_id
        self.on_scent = on_scent

        self._proc: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._stop_evt.clear()
            # -e: ether header (source MAC), -nn: no name/port resolve, -l: line-buffered
            cmd = f"tcpdump -i {self.iface} -e -nn -l arp"
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
                _log(f"failed to start tcpdump on {self.iface}: {exc}")
                return
            self._proc = proc
            self._running = True
            self._thread = threading.Thread(
                target=self._read_loop, name=f"finderpassive-{self.iface}", daemon=True)
            self._thread.start()
            _log(f"listening for ARP on {self.iface} (pid {proc.pid})")

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
                subprocess.run(["su", "-c", f'pkill -f "tcpdump -i {self.iface} -e -nn -l arp"'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                subprocess.run(["su", "-c", f"kill -9 {pid}"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                proc.wait(timeout=3)
            except Exception as exc:  # noqa: BLE001
                _log(f"stop error: {exc}")
            _log(f"stopped ARP listen on {self.iface} (pid {pid})")
        t = self._thread
        self._thread = None
        if t is not None:
            t.join(timeout=3.0)

    def _read_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                if self._stop_evt.is_set():
                    break
                try:
                    recs = parse_tcpdump_arp([line], oui_classify=_oui.classify)
                except Exception as exc:  # noqa: BLE001
                    _log(f"parse error: {exc}")
                    continue
                for rec in recs:
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


# ----------------------------------------------------------------------------
# Self-test
# ----------------------------------------------------------------------------
_SAMPLE_ARP = [
    # request: 192.168.1.77 (at de:ad:...:01) asking for the gateway
    "21:30:01.100 de:ad:be:ef:00:01 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), "
    "length 42: Request who-has 192.168.1.1 tell 192.168.1.77, length 28",
    # reply: 192.168.1.1 is-at the router MAC
    "21:30:01.150 7c:db:98:64:54:9d > de:ad:be:ef:00:01, ethertype ARP (0x0806), "
    "length 42: Reply 192.168.1.1 is-at 7c:db:98:64:54:9d, length 28",
    # another station announcing itself via a request
    "21:30:02.000 de:ad:be:ef:00:02 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), "
    "length 42: Request who-has 192.168.1.1 tell 192.168.1.78, length 28",
    # broadcast/gratuitous noise that must NOT create a record for ff:ff...
    "21:30:02.500 ff:ff:ff:ff:ff:ff > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), "
    "length 42: Request who-has 192.168.1.9 tell 0.0.0.0, length 28",
]


def _self_test() -> None:
    import tempfile

    recs = parse_tcpdump_arp(_SAMPLE_ARP,
                             oui_classify=lambda m: "RouterCo" if m.startswith("7c:db") else "")
    by_mac = {r.mac: r for r in recs}

    assert "de:ad:be:ef:00:01" in by_mac, by_mac
    assert by_mac["de:ad:be:ef:00:01"].ip == "192.168.1.77", by_mac
    assert by_mac["de:ad:be:ef:00:01"].is_station is True
    assert "7c:db:98:64:54:9d" in by_mac, by_mac
    assert by_mac["7c:db:98:64:54:9d"].ip == "192.168.1.1", by_mac
    assert by_mac["7c:db:98:64:54:9d"].vendor == "RouterCo", by_mac
    assert "de:ad:be:ef:00:02" in by_mac and by_mac["de:ad:be:ef:00:02"].ip == "192.168.1.78"
    assert "ff:ff:ff:ff:ff:ff" not in by_mac, "broadcast source must be skipped"
    assert len(recs) == 3, recs
    print("  [1] parse_tcpdump_arp: request+reply mined, broadcast skipped  ok")

    from engine.arbiter import RowReaderArbiter
    tmp = tempfile.mkdtemp(prefix="finderpassive_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    try:
        for rec in recs:
            rec.net_id = "wlan0"
            upsert_scent(arb, rec)
        rows = arb.read(DB_KNOWN_SCENTS,
                        "SELECT mac, ip, is_station, net_id FROM scents ORDER BY mac")
        assert len(rows) == 3, rows
        assert all(r[3] == "wlan0" for r in rows), rows
        assert all(r[2] == 1 for r in rows), rows  # all stations
        print("  [2] RowReaderArbiter round-trip: 3 passively-found stations  ok")
    finally:
        arb.close()
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass
    print("U5c PASS")


if __name__ == "__main__":
    _self_test()
