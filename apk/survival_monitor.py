import os
import time
import threading
import traceback
import subprocess
from typing import Union, Callable

from kivy.logger import Logger

from utils import DEADNET_PREF


#   --------------------------------------------------------------------------------------------------------------------
#   SurvivalMonitor
#   --------------------------------------------------------------------------------------------------------------------
#   Thin Python wrapper around the native `sniff` binary. The binary passively reads Ethernet/IP/ARP *header* metadata
#   on the interface and emits one counter line per interval:
#
#       TS=<epoch_ms> ARP_TX=<n> ARP_RX=<n> SURV=<n> SURV_BYTES=<n> EVID=<n> TOTAL=<n>
#
#   This class runs the binary under `su`, parses those lines on a background thread, converts each interval's counts
#   into per-second rates, and hands them to a callback so the UI can drive its gauges. No packet payloads are ever
#   captured or stored - only counts, which is all that "is HTTPS still surviving the attack?" actually needs.
#   --------------------------------------------------------------------------------------------------------------------


class SurvivalSample:
    __slots__ = ("arp_tx_ps", "arp_rx_ps", "surv_ps", "surv_bytes_ps", "evid_ps", "total_ps",
                 "evidence_ps", "confirmed")

    def __init__(self, arp_tx_ps, arp_rx_ps, surv_ps, surv_bytes_ps, evid_ps, total_ps):
        self.arp_tx_ps = arp_tx_ps
        self.arp_rx_ps = arp_rx_ps
        self.surv_ps = surv_ps
        self.surv_bytes_ps = surv_bytes_ps
        self.evid_ps = evid_ps
        self.total_ps = total_ps
        # right gauge combines ARP chatter we receive with dead-MAC evidence
        self.evidence_ps = arp_rx_ps + evid_ps
        # DeadNet is "confirmed" once no other host's traffic reaches the real gateway
        self.confirmed = surv_ps == 0.0


class SurvivalMonitor:
    DEFAULT_INTERVAL_MS = 500

    def __init__(self, sniff_path: str, iface: str, gateway_mac: str, our_mac: str,
                 on_sample: Callable[[SurvivalSample], None], interval_ms: int = DEFAULT_INTERVAL_MS):
        self._sniff_path = sniff_path
        self._iface = iface
        self._gateway_mac = gateway_mac
        self._our_mac = our_mac
        self._on_sample = on_sample
        self._interval_ms = interval_ms if interval_ms > 0 else self.DEFAULT_INTERVAL_MS

        self._proc: Union[None, subprocess.Popen] = None
        self._reader_thread: Union[None, threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._proc is not None:
            return
        self._stop.clear()
        self._proc = subprocess.Popen(
            ["su", "-c",
             f"{self._sniff_path} {self._iface} {self._gateway_mac} {self._our_mac} {self._interval_ms}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        Logger.info(f"{DEADNET_PREF}: survival monitor started, proc_id {self._proc.pid}")
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                sample = self._parse_line(line)
                if sample is not None:
                    try:
                        self._on_sample(sample)
                    except Exception as e:
                        Logger.error(f"{DEADNET_PREF}: survival on_sample callback error {e} - {traceback.format_exc()}")
        except Exception as e:
            Logger.error(f"{DEADNET_PREF}: survival read loop error {e} - {traceback.format_exc()}")

    def _parse_line(self, line: str) -> Union[None, SurvivalSample]:
        line = line.strip()
        if not line or "ARP_TX=" not in line:
            return None
        fields = {}
        for tok in line.split():
            if "=" in tok:
                k, _, v = tok.partition("=")
                try:
                    fields[k] = int(v)
                except ValueError:
                    return None
        try:
            # counts are per interval -> normalize to per second
            scale = 1000.0 / float(self._interval_ms)
            return SurvivalSample(
                arp_tx_ps=fields["ARP_TX"] * scale,
                arp_rx_ps=fields["ARP_RX"] * scale,
                surv_ps=fields["SURV"] * scale,
                surv_bytes_ps=fields["SURV_BYTES"] * scale,
                evid_ps=fields["EVID"] * scale,
                total_ps=fields["TOTAL"] * scale,
            )
        except KeyError:
            return None

    def stop(self) -> None:
        self._stop.set()
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        pid = proc.pid
        try:
            # the sniffer runs as root under a new session, so reap it the same way the attack procs are reaped
            subprocess.run(["su", "-c", f"pkill -f {self._sniff_path}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            subprocess.run(["su", "-c", f"kill -9 {pid}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proc.wait(timeout=3)
        except Exception as e:
            Logger.error(f"{DEADNET_PREF}: survival monitor stop error {e} - {traceback.format_exc()}")
        Logger.info(f"{DEADNET_PREF}: survival monitor stopped (pid {pid})")
