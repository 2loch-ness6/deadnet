"""
BirdObserver — the "airborne-during-maneuver" attention service (work unit U9).

While the swarm is mid-maneuver (cards seized, poison in flight) BirdObserver
rides along and watches the runtime state store for UNCOOPERATIVE electronics:
the ones still leaking / not complying with our routing (escaped envelopes > 0,
poison not holding). It raises the "attention" the emitter gives them so effort
flows toward the hosts that are actually fighting back.

It is three independent, owner-toggleable GOVERNORS (all gated on Knobs, every
one an owner knob):

  1. Cadence governor   (knobs.bird_cadence_governor)
        Normalize the total attention weight so sum(weights) <= 1.0. The emitter
        budgets per-card pps by weight, so bounding the sum keeps the aggregate
        send rate under the benchmarked card maximum. Pure math on the weights.

  2. Attention governor (knobs.bird_attention_governor)
        Each in-focus entry whose StateMetric says it is NON-COMPLIANT
        (compliant == False AND escaped_pkts > 0) gets its weight multiplied by
        knobs.bird_noncompliant_boost — leakers earn MORE attention. Entries
        that are compliant decay back toward their base weight of 1.0 (*0.9
        toward 1.0). Pinned entries are owner-protected and never downweighted.

  3. Escalation governor (knobs.bird_escalation_governor)
        PROMOTE a leaker to focused targeting: a StateMetric showing escaped
        pkts/s >= knobs.bird_escalation_threshold for a mac NOT already in the
        attention set gets a brand-new AttentionEntry (weight =
        bird_noncompliant_boost).

Order: the attention + escalation governors run FIRST (they mutate the set and
the raw weights), then the cadence governor runs LAST to renormalize whatever
they produced.

The per-tick decision is a PURE function ``govern(metrics, attention, knobs)``
returning the NEW attention rows, so it is fully unit-testable with no threads
and no DB. The ``BirdObserver`` wrapper just pumps it on a daemon thread, reading
DB_STATE / DB_ATTENTION and writing the result back — ALL db access goes through
the arbiter.

Assumptions (documented per the brief):
  * StateMetric.tx_pps carries the live per-target send rate for hosts already
    in focus; for a not-yet-focused host there is no tx_pps yet, so the
    escalation governor treats StateMetric.escaped_pkts as the leak signal
    compared against bird_escalation_threshold. The rehydration state
    maintainer (U-state) is responsible for expressing escaped_pkts as a
    per-interval rate so the integer threshold is meaningful.
  * A freshly escalated entry has no resolved IP in the state store, so its
    AttentionEntry.ip is left empty ("") for a later resolver/finder to fill;
    the attention schema's NOT NULL on ip is satisfied by the empty string.

Stdlib only. Safe to import off-device (Kivy Logger import is guarded).
"""
from __future__ import annotations

import os
import threading
from typing import Dict, List

try:  # package import (app runs with apk/ on sys.path)
    from engine.contracts import (
        DB_STATE, DB_ATTENTION, DB_KNOWN_SCENTS,
        AttentionEntry, StateMetric, Knobs,
    )
except ImportError:  # running as a bare script: put apk/ on sys.path
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine.contracts import (  # noqa: E501
        DB_STATE, DB_ATTENTION, DB_KNOWN_SCENTS,
        AttentionEntry, StateMetric, Knobs,
    )

try:  # logging is optional off-device
    from kivy.logger import Logger as _Logger

    def _log(msg: str) -> None:
        _Logger.info("BirdObserver: %s" % msg)
except Exception:  # pragma: no cover - bare test env
    def _log(msg: str) -> None:
        pass


# Compliant entries ease back toward this base weight by this factor per tick.
_BASE_WEIGHT = 1.0
_DECAY = 0.9
# Cadence budget: the emitter's weight sum must stay at or below this.
_WEIGHT_BUDGET = 1.0


# ===========================================================================
# Pure decision core (no threads, no DB) — fully unit-testable.
# ===========================================================================
def govern(metrics: List[StateMetric],
           attention: List[AttentionEntry],
           knobs: Knobs) -> List[AttentionEntry]:
    """Compute the NEW attention rows from the current metrics + attention.

    Pure function: does not mutate its inputs and returns fresh AttentionEntry
    objects. Each governor is gated on its own owner knob. Attention +
    escalation run first (they change the set/weights), cadence renormalizes
    last.
    """
    by_mac: Dict[str, StateMetric] = {m.mac: m for m in metrics}

    # Work on copies so inputs are never mutated.
    out: List[AttentionEntry] = [
        AttentionEntry(mac=e.mac, ip=e.ip, net_id=e.net_id,
                       weight=float(e.weight), pinned=bool(e.pinned))
        for e in attention
    ]
    present = {e.mac for e in out}

    # --- Governor 2: Attention -------------------------------------------
    # Non-compliant (leaking) in-focus hosts get boosted; compliant ones decay
    # toward base weight. Pinned entries are never downweighted.
    if knobs.bird_attention_governor:
        boost = float(knobs.bird_noncompliant_boost)
        for e in out:
            m = by_mac.get(e.mac)
            if m is None:
                continue
            noncompliant = (not m.compliant) and (m.escaped_pkts > 0)
            if noncompliant:
                # Leakers earn more attention (boosting pinned is allowed —
                # only *down*weighting a pinned entry is forbidden).
                e.weight = e.weight * boost
            elif not e.pinned:
                # Compliant & unpinned: ease back toward the base weight.
                e.weight = _BASE_WEIGHT + (e.weight - _BASE_WEIGHT) * _DECAY
            # compliant & pinned -> untouched

    # --- Governor 3: Escalation ------------------------------------------
    # Promote any leaker above threshold that is not yet in the focus set.
    if knobs.bird_escalation_governor:
        threshold = knobs.bird_escalation_threshold
        boost = float(knobs.bird_noncompliant_boost)
        for m in metrics:
            if m.mac in present:
                continue
            # Not yet in focus -> no tx_pps; escaped_pkts is the leak signal.
            if m.escaped_pkts >= threshold:
                out.append(AttentionEntry(
                    mac=m.mac, ip="", net_id="", weight=boost, pinned=False))
                present.add(m.mac)

    # --- Governor 1: Cadence (LAST) --------------------------------------
    # Keep the total weight within the per-card pps budget (sum <= 1.0).
    if knobs.bird_cadence_governor:
        total = sum(max(0.0, e.weight) for e in out)
        if total > _WEIGHT_BUDGET:
            for e in out:
                e.weight = max(0.0, e.weight) / total

    return out


# ===========================================================================
# Threaded service wrapper. ALL db access goes through the arbiter.
# ===========================================================================
class BirdObserver:
    """Daemon-thread attention governor riding the state store."""

    def __init__(self, arbiter, knobs: Knobs, tick_ms: int = 250):
        self.arbiter = arbiter
        self.knobs = knobs
        self.tick_ms = tick_ms
        self._stop = threading.Event()
        self._thread = None  # type: ignore[assignment]

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="birdobserver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=5.0)
        self._thread = None

    # ----------------------------------------------------------------- loop
    def _loop(self) -> None:
        # Never let an exception escape the loop — guard every tick.
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001
                _log("tick failed: %r" % exc)
            self._stop.wait(self.tick_ms / 1000.0)

    def tick(self) -> None:
        """One governed pass: read state + attention, govern, write back."""
        if not self.knobs.bird_airborne:
            return
        metrics = self._read_metrics()
        attention = self._read_attention()
        new_attention = govern(metrics, attention, self.knobs)
        new_attention = self._resolve_entries(new_attention)
        self._write_attention(new_attention)

    def _resolve_entries(self, entries: List[AttentionEntry]) -> List[AttentionEntry]:
        """INTEGRATION SEAM: govern() escalates by mac only (ip/net_id empty, since
        the state store is mac-keyed). The emitter needs an IP to aim at, so fill
        any missing ip/net_id from the master store by mac. Entries we can't resolve
        yet are kept (a later NetFetcher pass will have populated the scent by then)."""
        missing = [e for e in entries if not e.ip and e.mac]
        if not missing:
            return entries
        try:
            rows = self.arbiter.read(
                DB_KNOWN_SCENTS,
                "SELECT mac, ip, net_id FROM scents WHERE ip != ''")
            by_mac = {r[0]: (r[1], r[2]) for r in rows}
        except Exception:  # noqa: BLE001
            return entries
        resolved = []
        for e in entries:
            if not e.ip and e.mac in by_mac:
                ip, net_id = by_mac[e.mac]
                resolved.append(AttentionEntry(
                    mac=e.mac, ip=ip, net_id=net_id or e.net_id,
                    weight=e.weight, pinned=e.pinned))
            else:
                resolved.append(e)
        return resolved

    # ----------------------------------------------------------- db helpers
    def _read_metrics(self) -> List[StateMetric]:
        rows = self.arbiter.read(
            DB_STATE,
            "SELECT mac, escaped_pkts, escaped_bytes, tx_pps, compliant, "
            "updated_ms FROM metrics")
        return [
            StateMetric(mac=r[0], escaped_pkts=r[1], escaped_bytes=r[2],
                        tx_pps=r[3], compliant=bool(r[4]), updated_ms=r[5])
            for r in rows
        ]

    def _read_attention(self) -> List[AttentionEntry]:
        rows = self.arbiter.read(
            DB_ATTENTION,
            "SELECT mac, ip, net_id, weight, pinned FROM attention")
        return [
            AttentionEntry(mac=r[0], ip=r[1], net_id=r[2],
                           weight=r[3], pinned=bool(r[4]))
            for r in rows
        ]

    def _write_attention(self, entries: List[AttentionEntry]) -> None:
        for e in entries:
            self.arbiter.write_async(
                DB_ATTENTION,
                "INSERT OR REPLACE INTO attention(mac, ip, net_id, weight, "
                "pinned) VALUES(?,?,?,?,?)",
                (e.mac, e.ip, e.net_id, float(e.weight),
                 1 if e.pinned else 0))


# ===========================================================================
# Self-test (no device / no root).  cd apk && python3 engine/birdobserver.py
# ===========================================================================
def _selftest() -> None:
    import time
    import tempfile

    # ---- 1. pure govern(): boost / decay / pinned (cadence off) ----------
    k = Knobs(bird_cadence_governor=False,
              bird_attention_governor=True,
              bird_escalation_governor=False,
              bird_noncompliant_boost=2.0)

    attention = [
        AttentionEntry(mac="aa:00:00:00:00:01", ip="10.0.0.1", weight=0.20),  # leaker
        AttentionEntry(mac="aa:00:00:00:00:02", ip="10.0.0.2", weight=0.30),  # compliant
        AttentionEntry(mac="aa:00:00:00:00:03", ip="10.0.0.3", weight=0.50,
                       pinned=True),                                          # pinned
    ]
    metrics = [
        StateMetric(mac="aa:00:00:00:00:01", escaped_pkts=10, compliant=False),
        StateMetric(mac="aa:00:00:00:00:02", escaped_pkts=0, compliant=True),
        StateMetric(mac="aa:00:00:00:00:03", escaped_pkts=0, compliant=True),
    ]
    res = govern(metrics, attention, k)
    r = {e.mac: e for e in res}
    # non-compliant entry boosted by exactly the factor
    assert abs(r["aa:00:00:00:00:01"].weight - 0.20 * 2.0) < 1e-9, r["aa:00:00:00:00:01"].weight
    # compliant entry decays toward 1.0: 1.0 + (0.30-1.0)*0.9 = 0.37
    assert abs(r["aa:00:00:00:00:02"].weight - (1.0 + (0.30 - 1.0) * 0.9)) < 1e-9, r["aa:00:00:00:00:02"].weight
    assert r["aa:00:00:00:00:02"].weight > 0.30, "compliant entry should move toward base 1.0"
    # pinned entry untouched
    assert r["aa:00:00:00:00:03"].weight == 0.50, r["aa:00:00:00:00:03"].weight
    # inputs not mutated
    assert attention[0].weight == 0.20, "govern must not mutate inputs"
    print("  [1] attention governor: boost / decay / pinned ... ok")

    # ---- 2. escalation: leaker above threshold, not in set, is ADDED -----
    k2 = Knobs(bird_cadence_governor=False,
               bird_attention_governor=False,
               bird_escalation_governor=True,
               bird_noncompliant_boost=2.0,
               bird_escalation_threshold=5)
    metrics2 = [
        StateMetric(mac="bb:00:00:00:00:99", escaped_pkts=20, compliant=False),  # promote
        StateMetric(mac="bb:00:00:00:00:98", escaped_pkts=2, compliant=False),   # below thr
    ]
    res2 = govern(metrics2, [], k2)
    macs2 = {e.mac: e for e in res2}
    assert "bb:00:00:00:00:99" in macs2, macs2
    assert "bb:00:00:00:00:98" not in macs2, "below-threshold leaker must not be promoted"
    assert macs2["bb:00:00:00:00:99"].weight == 2.0, macs2["bb:00:00:00:00:99"].weight
    print("  [2] escalation governor: leaker promoted to focus ... ok")

    # ---- 3. cadence: sum(weights) <= 1.0 after full pass -----------------
    k3 = Knobs()  # all governors on, boost 2.0, threshold 5
    attention3 = [
        AttentionEntry(mac="cc:00:00:00:00:01", ip="10.0.1.1", weight=0.8),
        AttentionEntry(mac="cc:00:00:00:00:02", ip="10.0.1.2", weight=0.8),
    ]
    metrics3 = [
        StateMetric(mac="cc:00:00:00:00:01", escaped_pkts=15, compliant=False),
        StateMetric(mac="cc:00:00:00:00:02", escaped_pkts=15, compliant=False),
        StateMetric(mac="cc:00:00:00:00:03", escaped_pkts=30, compliant=False),  # escalated
    ]
    res3 = govern(metrics3, attention3, k3)
    assert any(e.mac == "cc:00:00:00:00:03" for e in res3), "escalation should add the 3rd"
    total3 = sum(e.weight for e in res3)
    assert total3 <= 1.0 + 1e-6, total3
    print("  [3] cadence governor: Sum(w)=%.6f <= 1.0 ........ ok" % total3)

    # ---- 4. threaded path against a real RowReaderArbiter ----------------
    from engine.arbiter import RowReaderArbiter

    tmp = tempfile.mkdtemp(prefix="bird_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    try:
        # seed attention: one in-focus host at a low weight
        arb.write(DB_ATTENTION,
                  "INSERT INTO attention(mac, ip, net_id, weight, pinned) "
                  "VALUES(?,?,?,?,?)",
                  ("aa:00:00:00:00:01", "10.0.0.1", "n1", 0.20, 0))
        # seed state: that host is leaking (boost), plus a new leaker (escalate)
        arb.write(DB_STATE,
                  "INSERT INTO metrics(mac, escaped_pkts, compliant) "
                  "VALUES(?,?,?)",
                  ("aa:00:00:00:00:01", 10, 0))
        arb.write(DB_STATE,
                  "INSERT INTO metrics(mac, escaped_pkts, compliant) "
                  "VALUES(?,?,?)",
                  ("bb:00:00:00:00:99", 20, 0))

        bird = BirdObserver(arb, Knobs(), tick_ms=100)
        bird.start()
        time.sleep(1.0)
        bird.stop()

        rows = arb.read(DB_ATTENTION,
                        "SELECT mac, weight FROM attention ORDER BY mac")
        got = {m: w for m, w in rows}
        # the escalated leaker was ADDED to the attention table
        assert "bb:00:00:00:00:99" in got, got
        assert len(got) == 2, got
        # the seeded host's weight changed from its seed (governed)
        assert abs(got["aa:00:00:00:00:01"] - 0.20) > 1e-9, got
        # cadence kept the budget bounded
        assert sum(got.values()) <= 1.0 + 1e-6, got
        print("  [4] threaded path: attention changed, rows=%d, Sum(w)=%.6f ok"
              % (len(got), sum(got.values())))
    finally:
        arb.close()
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass

    print("U9 PASS")


if __name__ == "__main__":
    _selftest()
