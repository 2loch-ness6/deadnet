"""
RowReaderArbiter — the atomic gatekeeper ("row-reader RA") for the DeadNet
engine (work unit U2).

Owns the three in-memory shared-cache SQLite DBs (known_scents / attention /
state) and the shared-memory focus/stats bridge to the native emitter
(emit.cpp). Concurrency model (per CONTRACTS.md + contracts.py):

  * Reads are instant and concurrent. Each reader thread gets its own
    connection (threading.local) running ``PRAGMA read_uncommitted=1`` so
    shared-cache reads never block behind the writer's open transaction.
  * Writes are serialized through ONE dedicated writer thread per DB consuming
    a FIFO ``queue.Queue``. ``write()`` blocks until its item commits (via a
    per-item ``threading.Event``); ``write_async()`` enqueues and returns.
  * The in-memory DBs are kept alive by one persistent "keepalive" connection
    per DB (owned by that DB's writer thread) — the shared-cache backing store
    is freed the instant the last connection closes, so these never close until
    ``close()``.
  * ``publish_focus`` / ``read_stats`` memory-map ``<appdir>/focus_<iface>.shm``
    and ``<appdir>/stats_<iface>.shm`` and use the seqlock discipline defined in
    contracts.py (writer: seq->odd, body, seq->even; reader: retry until seq is
    even and unchanged around the body).

Stdlib only. Safe to import off-device (Kivy Logger import is guarded).
"""
from __future__ import annotations

import os
import mmap
import queue
import struct
import tempfile
import threading
from typing import Dict, List, Optional

try:  # package import (app runs with apk/ on sys.path)
    from engine.contracts import (
        ALL_DBS, SCHEMA, db_uri,
        EmitMode, AttentionEntry,
        FOCUS_HEADER_FMT, FOCUS_ENTRY_FMT, FOCUS_HEADER_SIZE, FOCUS_ENTRY_SIZE,
        FOCUS_MAX_ENTRIES, FOCUS_FILE_SIZE, FOCUS_FLAG_0TTL,
        STATS_HEADER_FMT, STATS_ENTRY_FMT, STATS_HEADER_SIZE, STATS_ENTRY_SIZE,
        STATS_MAX_ENTRIES, STATS_FILE_SIZE,
    )
except ImportError:  # running as a bare script: put apk/ on sys.path
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from engine.contracts import (  # noqa: E501
        ALL_DBS, SCHEMA, db_uri,
        EmitMode, AttentionEntry,
        FOCUS_HEADER_FMT, FOCUS_ENTRY_FMT, FOCUS_HEADER_SIZE, FOCUS_ENTRY_SIZE,
        FOCUS_MAX_ENTRIES, FOCUS_FILE_SIZE, FOCUS_FLAG_0TTL,
        STATS_HEADER_FMT, STATS_ENTRY_FMT, STATS_HEADER_SIZE, STATS_ENTRY_SIZE,
        STATS_MAX_ENTRIES, STATS_FILE_SIZE,
    )

import sqlite3

try:  # logging is optional off-device
    from kivy.logger import Logger as _Logger

    def _log(msg: str) -> None:
        _Logger.info("Arbiter: %s" % msg)
except Exception:  # pragma: no cover - bare test env
    def _log(msg: str) -> None:
        pass


# Header body = everything after the leading u32 seq (offsets 4..32).
_FOCUS_HEADER_BODY_FMT = "<III6s6sI"   # mode, count, gen, gw_mac, our_mac, flags
_SEQ_FMT = "<I"
_SEQ_SIZE = struct.calcsize(_SEQ_FMT)

# mode enum -> wire value (0 = UNFOCUSED, 1 = FOCUSED per contracts.py)
_MODE_WIRE = {EmitMode.UNFOCUSED: 0, EmitMode.FOCUSED: 1}

_STOP = object()   # writer-thread sentinel


class _WriteItem:
    __slots__ = ("sql", "params", "event", "error")

    def __init__(self, sql: str, params: tuple, event: Optional[threading.Event]):
        self.sql = sql
        self.params = params
        self.event = event
        self.error: Optional[BaseException] = None


def _mac_to_bytes(mac: str) -> bytes:
    """'aa:bb:cc:dd:ee:ff' -> 6 bytes. Empty/short -> zero-filled."""
    if not mac:
        return b"\x00" * 6
    raw = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(raw) < 6:
        raw = raw + b"\x00" * (6 - len(raw))
    return raw[:6]


def _bytes_to_mac(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw[:6])


def _ip_to_be_u32(ip: str) -> int:
    """Dotted IPv4 -> u32 whose little-endian packing yields the 4 octets in
    network order ([a,b,c,d]). Matches the 'ip_be' field (network byte order)."""
    if not ip:
        return 0
    octets = [int(x) & 0xFF for x in ip.split(".")]
    while len(octets) < 4:
        octets.append(0)
    return struct.unpack(_SEQ_FMT, bytes(octets[:4]))[0]


def _be_u32_to_ip(val: int) -> str:
    return ".".join(str(b) for b in struct.pack(_SEQ_FMT, val & 0xFFFFFFFF))


class RowReaderArbiter:
    """Concrete implementation of the ``Arbiter`` Protocol in engine.contracts."""

    def __init__(self, appdir: Optional[str] = None):
        self.appdir = appdir or tempfile.gettempdir()
        try:
            os.makedirs(self.appdir, exist_ok=True)
        except Exception:
            pass

        self._closed = False

        # Per-DB state.
        self._keepalive: Dict[str, sqlite3.Connection] = {}
        self._queues: Dict[str, "queue.Queue"] = {}
        self._writers: Dict[str, threading.Thread] = {}

        # Per-thread reader connections: threading.local holding {db: conn}.
        self._tls = threading.local()

        # Focus/stats mmap state.
        self._focus_maps: Dict[str, mmap.mmap] = {}
        self._focus_files: Dict[str, object] = {}
        self._focus_gen: Dict[str, int] = {}
        self._stats_maps: Dict[str, mmap.mmap] = {}
        self._stats_files: Dict[str, object] = {}
        self._shm_lock = threading.Lock()

        for name in ALL_DBS:
            self._init_db(name)

    # ------------------------------------------------------------------ DBs
    def _init_db(self, name: str) -> None:
        # Keepalive connection owned conceptually by the writer thread; created
        # here so we can run the schema synchronously before returning.
        keep = sqlite3.connect(db_uri(name), uri=True, check_same_thread=False)
        keep.executescript(SCHEMA[name])
        keep.commit()
        self._keepalive[name] = keep

        q: "queue.Queue" = queue.Queue()
        self._queues[name] = q
        t = threading.Thread(target=self._writer_loop, args=(name,),
                             name="arb-writer-%s" % name, daemon=True)
        self._writers[name] = t
        t.start()

    def _reader_conn(self, name: str) -> sqlite3.Connection:
        conns = getattr(self._tls, "conns", None)
        if conns is None:
            conns = {}
            self._tls.conns = conns
        conn = conns.get(name)
        if conn is None:
            conn = sqlite3.connect(db_uri(name), uri=True, check_same_thread=False)
            # read_uncommitted lets shared-cache reads skip the read lock so they
            # never block on the writer's open write transaction.
            conn.execute("PRAGMA read_uncommitted=1;")
            conns[name] = conn
        return conn

    def _writer_loop(self, name: str) -> None:
        conn = self._keepalive[name]
        q = self._queues[name]
        while True:
            first = q.get()
            if first is _STOP:
                return
            # Drain whatever else is queued into one commit (preserves FIFO).
            batch: List[_WriteItem] = [first]
            stop = False
            while True:
                try:
                    nxt = q.get_nowait()
                except queue.Empty:
                    break
                if nxt is _STOP:
                    stop = True
                    break
                batch.append(nxt)

            try:
                cur = conn.cursor()
                for it in batch:
                    cur.execute(it.sql, it.params)
                conn.commit()
            except BaseException as exc:  # noqa: BLE001
                try:
                    conn.rollback()
                except Exception:
                    pass
                _log("write batch failed: %r" % exc)
                for it in batch:
                    it.error = exc
            finally:
                for it in batch:
                    if it.event is not None:
                        it.event.set()

            if stop:
                return

    # --------------------------------------------------------------- public
    def read(self, db: str, sql: str, params: tuple = ()) -> List[tuple]:
        if self._closed:
            raise RuntimeError("arbiter closed")
        conn = self._reader_conn(db)
        cur = conn.execute(sql, params)
        return cur.fetchall()

    def write(self, db: str, sql: str, params: tuple = ()) -> None:
        if self._closed:
            raise RuntimeError("arbiter closed")
        ev = threading.Event()
        item = _WriteItem(sql, params, ev)
        self._queues[db].put(item)
        ev.wait()
        if item.error is not None:
            raise item.error

    def write_async(self, db: str, sql: str, params: tuple = ()) -> None:
        if self._closed:
            raise RuntimeError("arbiter closed")
        self._queues[db].put(_WriteItem(sql, params, None))

    # ---------------------------------------------------- focus/stats bridge
    def _focus_path(self, iface: str) -> str:
        return os.path.join(self.appdir, "focus_%s.shm" % iface)

    def _stats_path(self, iface: str) -> str:
        return os.path.join(self.appdir, "stats_%s.shm" % iface)

    @staticmethod
    def _ensure_file(path: str, size: int) -> None:
        if os.path.exists(path) and os.path.getsize(path) == size:
            return
        with open(path, "wb") as f:
            f.write(b"\x00" * size)

    def _focus_mmap(self, iface: str) -> mmap.mmap:
        mm = self._focus_maps.get(iface)
        if mm is not None:
            return mm
        path = self._focus_path(iface)
        self._ensure_file(path, FOCUS_FILE_SIZE)
        f = open(path, "r+b")
        mm = mmap.mmap(f.fileno(), FOCUS_FILE_SIZE)
        self._focus_files[iface] = f
        self._focus_maps[iface] = mm
        self._focus_gen.setdefault(iface, 0)
        return mm

    def _stats_mmap(self, iface: str) -> mmap.mmap:
        mm = self._stats_maps.get(iface)
        if mm is not None:
            return mm
        path = self._stats_path(iface)
        self._ensure_file(path, STATS_FILE_SIZE)
        f = open(path, "r+b")
        mm = mmap.mmap(f.fileno(), STATS_FILE_SIZE)
        self._stats_files[iface] = f
        self._stats_maps[iface] = mm
        return mm

    def ensure_stats_file(self, iface: str) -> str:
        """Pre-create a zeroed stats file so read_stats works before emit.cpp
        has started. Returns the file path."""
        path = self._stats_path(iface)
        self._ensure_file(path, STATS_FILE_SIZE)
        return path

    def publish_focus(self, iface: str, entries: List[AttentionEntry],
                      mode: EmitMode, gateway_mac: str, our_mac: str) -> None:
        with self._shm_lock:
            mm = self._focus_mmap(iface)

            n = min(len(entries), FOCUS_MAX_ENTRIES)
            use = list(entries[:n])

            # Normalize weights to sum <= 1.0 (sum to 1.0 when any positive).
            total = sum(max(0.0, float(e.weight)) for e in use)
            if total > 0.0:
                weights = [max(0.0, float(e.weight)) / total for e in use]
            else:
                weights = [0.0 for _ in use]

            gen = self._focus_gen.get(iface, 0) + 1
            self._focus_gen[iface] = gen

            # --- seqlock: seq -> odd, write body, seq -> even ---------------
            cur_seq = struct.unpack_from(_SEQ_FMT, mm, 0)[0]
            if cur_seq % 2 != 0:          # recover from a torn prior write
                cur_seq += 1
            odd = cur_seq + 1
            even = cur_seq + 2

            struct.pack_into(_SEQ_FMT, mm, 0, odd & 0xFFFFFFFF)

            # header body (offsets 4..32)
            struct.pack_into(
                _FOCUS_HEADER_BODY_FMT, mm, _SEQ_SIZE,
                _MODE_WIRE.get(mode, 0),
                n,
                gen & 0xFFFFFFFF,
                _mac_to_bytes(gateway_mac),
                _mac_to_bytes(our_mac),
                FOCUS_FLAG_0TTL,
            )

            off = FOCUS_HEADER_SIZE
            for e, w in zip(use, weights):
                struct.pack_into(
                    FOCUS_ENTRY_FMT, mm, off,
                    _ip_to_be_u32(e.ip),
                    _mac_to_bytes(e.mac),
                    0,                 # _pad
                    float(w),
                    0,                 # interval_us (0 = as-fast)
                    0,                 # _reserved
                )
                off += FOCUS_ENTRY_SIZE

            struct.pack_into(_SEQ_FMT, mm, 0, even & 0xFFFFFFFF)
            try:
                mm.flush()
            except Exception:
                pass

    def read_stats(self, iface: str) -> Dict[str, tuple]:
        with self._shm_lock:
            mm = self._stats_mmap(iface)

        hdr = struct.calcsize(STATS_HEADER_FMT)
        out: Dict[str, tuple] = {}
        for _ in range(100):
            s1 = struct.unpack_from(_SEQ_FMT, mm, 0)[0]
            if s1 % 2 != 0:
                continue  # writer mid-update
            _, count, _ts = struct.unpack_from(STATS_HEADER_FMT, mm, 0)
            count = min(count, STATS_MAX_ENTRIES)
            tmp: Dict[str, tuple] = {}
            off = hdr
            for _i in range(count):
                ip_be, tx_pkts, tx_bytes, _res = struct.unpack_from(
                    STATS_ENTRY_FMT, mm, off)
                tmp[_be_u32_to_ip(ip_be)] = (tx_pkts, tx_bytes)
                off += STATS_ENTRY_SIZE
            s2 = struct.unpack_from(_SEQ_FMT, mm, 0)[0]
            if s2 == s1 and s2 % 2 == 0:
                out = tmp
                break
        return out

    # ---------------------------------------------------------------- close
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True

        # Stop writer threads and wait.
        for name in ALL_DBS:
            try:
                self._queues[name].put(_STOP)
            except Exception:
                pass
        for name in ALL_DBS:
            t = self._writers.get(name)
            if t is not None:
                t.join(timeout=5.0)

        # Close keepalives last (frees the shared-cache backing stores).
        for name in ALL_DBS:
            try:
                self._keepalive[name].close()
            except Exception:
                pass

        # Reader connection owned by this thread (others are daemonic / GC'd).
        conns = getattr(self._tls, "conns", None)
        if conns:
            for c in conns.values():
                try:
                    c.close()
                except Exception:
                    pass

        for d in (self._focus_maps, self._stats_maps):
            for mm in d.values():
                try:
                    mm.close()
                except Exception:
                    pass
        for d in (self._focus_files, self._stats_files):
            for f in d.values():
                try:
                    f.close()
                except Exception:
                    pass

    def __enter__(self) -> "RowReaderArbiter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ===========================================================================
# Self-test (no device / no root).  cd apk && python3 engine/arbiter.py
# ===========================================================================
def _selftest() -> None:
    import threading as _th

    tmp = tempfile.mkdtemp(prefix="arb_selftest_")
    arb = RowReaderArbiter(appdir=tmp)
    try:
        # 1. schema + write()/read() round-trip -----------------------------
        arb.write(ALL_DBS[0],
                 "INSERT INTO scents(mac, ip, vendor) VALUES(?,?,?)",
                 ("aa:bb:cc:00:00:01", "10.0.0.5", "Acme"))
        rows = arb.read(ALL_DBS[0],
                       "SELECT mac, ip, vendor FROM scents WHERE mac=?",
                       ("aa:bb:cc:00:00:01",))
        assert rows == [("aa:bb:cc:00:00:01", "10.0.0.5", "Acme")], rows
        print("  [1] schema + write/read round-trip ....... ok")

        # 2. FIFO ordering via write_async ----------------------------------
        for i in range(100):
            arb.write_async("state",
                           "INSERT INTO metrics(mac, escaped_pkts) VALUES(?,?)",
                           ("m%03d" % i, i))
        # Force a flush/barrier: a blocking write after the async burst.
        arb.write("state",
                 "INSERT INTO metrics(mac, escaped_pkts) VALUES(?,?)",
                 ("zzz", 999))
        got = arb.read("state",
                      "SELECT escaped_pkts FROM metrics WHERE mac LIKE 'm%' "
                      "ORDER BY rowid")
        seq = [r[0] for r in got]
        assert seq == list(range(100)), seq[:10]
        print("  [2] FIFO order preserved (100 inserts) ... ok")

        # 3. concurrent readers while a writer does 500 writes --------------
        stop = _th.Event()
        errors: List[BaseException] = []

        def hammer():
            try:
                while not stop.is_set():
                    arb.read("attention", "SELECT COUNT(*) FROM attention")
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        readers = [_th.Thread(target=hammer, daemon=True) for _ in range(4)]
        for r in readers:
            r.start()
        for i in range(500):
            arb.write_async("attention",
                           "INSERT INTO attention(mac, ip, weight) VALUES(?,?,?)",
                           ("c%04d" % i, "10.0.1.%d" % (i % 254), 1.0))
        arb.write("attention",
                 "INSERT INTO attention(mac, ip) VALUES('sentinel','0.0.0.0')")
        stop.set()
        for r in readers:
            r.join(timeout=5.0)
        assert not errors, errors
        cnt = arb.read("attention", "SELECT COUNT(*) FROM attention")[0][0]
        assert cnt == 501, cnt
        print("  [3] 4 readers + 500 writes, final count=%d  ok" % cnt)

        # 4. focus publish round-trip ---------------------------------------
        iface = "wlan0"
        entries = [
            AttentionEntry(mac="de:ad:be:ef:00:01", ip="192.168.1.10",
                          net_id="n1", weight=1.0),
            AttentionEntry(mac="de:ad:be:ef:00:02", ip="192.168.1.20",
                          net_id="n1", weight=2.0),
            AttentionEntry(mac="de:ad:be:ef:00:03", ip="172.16.5.33",
                          net_id="n1", weight=1.0),
        ]
        gw, our = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
        arb.publish_focus(iface, entries, EmitMode.FOCUSED, gw, our)

        # Independently mmap + unpack using the contract FMT constants.
        with open(os.path.join(tmp, "focus_%s.shm" % iface), "rb") as f:
            buf = f.read()
        assert len(buf) == FOCUS_FILE_SIZE, len(buf)
        seq_, mode_, count_, gen_, gwb, ourb, flags_ = struct.unpack_from(
            FOCUS_HEADER_FMT, buf, 0)
        assert count_ == 3, count_
        assert seq_ % 2 == 0, seq_
        assert mode_ == 1, mode_
        assert flags_ & FOCUS_FLAG_0TTL, flags_
        assert _bytes_to_mac(gwb) == gw, _bytes_to_mac(gwb)
        assert _bytes_to_mac(ourb) == our, _bytes_to_mac(ourb)

        exp_total = 1.0 + 2.0 + 1.0
        exp_weights = [1.0 / exp_total, 2.0 / exp_total, 1.0 / exp_total]
        wsum = 0.0
        off = FOCUS_HEADER_SIZE
        for k, e in enumerate(entries):
            ip_be, macb, pad, weight, interval, res = struct.unpack_from(
                FOCUS_ENTRY_FMT, buf, off)
            assert _be_u32_to_ip(ip_be) == e.ip, (_be_u32_to_ip(ip_be), e.ip)
            assert _bytes_to_mac(macb) == e.mac, _bytes_to_mac(macb)
            assert abs(weight - exp_weights[k]) < 1e-6, (weight, exp_weights[k])
            wsum += weight
            off += FOCUS_ENTRY_SIZE
        assert wsum <= 1.0 + 1e-6, wsum
        print("  [4] focus round-trip (count=3, seq=%d, Sum(w)=%.3f) ok" % (seq_, wsum))

        # 5. stats round-trip: hand-write a seqlock buffer, then read_stats --
        iface2 = "wlan1"
        path2 = arb.ensure_stats_file(iface2)
        stats = {"192.168.1.10": (12345, 6789000),
                 "10.0.0.5": (42, 4242)}
        with open(path2, "r+b") as f:
            mm = mmap.mmap(f.fileno(), STATS_FILE_SIZE)
            try:
                struct.pack_into(_SEQ_FMT, mm, 0, 1)          # seq -> odd
                struct.pack_into(STATS_HEADER_FMT, mm, 0,
                                 1, len(stats), 1700000000000)
                off = STATS_HEADER_SIZE
                for ip, (p, b) in stats.items():
                    struct.pack_into(STATS_ENTRY_FMT, mm, off,
                                     _ip_to_be_u32(ip), p, b, 0)
                    off += STATS_ENTRY_SIZE
                struct.pack_into(_SEQ_FMT, mm, 0, 2)          # seq -> even
                mm.flush()
            finally:
                mm.close()
        got_stats = arb.read_stats(iface2)
        assert got_stats == stats, got_stats
        print("  [5] stats round-trip (%d entries) ......... ok" % len(got_stats))

    finally:
        arb.close()
        # cleanup temp dir
        try:
            for fn in os.listdir(tmp):
                os.remove(os.path.join(tmp, fn))
            os.rmdir(tmp)
        except Exception:
            pass

    print("U2 PASS")


if __name__ == "__main__":
    _selftest()
