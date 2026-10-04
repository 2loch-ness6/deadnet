"""
DeadNet engine contracts — the single source of truth every unit builds against.

This module defines the data model (dataclasses + enums), the three in-memory
SQLite schemas, the Python<->C++ shared-memory layout for the emission engine,
and the abstract Arbiter ("row-reader RA") interface. Implementations live in
sibling modules; nothing here does I/O so it is safe to import from anywhere
(UI thread, finder thread, emitter controller, unit tests).

Naming is in-theme (the owner's convention): signals are "scents", targets we
focus on get "attention", surviving/leaked packets are "escaped envelopes".
"""
from __future__ import annotations

import time
import enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Protocol, Any


# ----------------------------------------------------------------------------
# Database identity (in-memory, shared-cache so every thread sees one DB each)
# ----------------------------------------------------------------------------
# NB: sqlite3 ":memory:" is per-connection. Shared-cache URI makes all
# connections in this process attach to the SAME in-memory database.
DB_KNOWN_SCENTS = "known_scents"      # SQL #1 master store (canonical inventory)
DB_ATTENTION = "attention"            # SQL #2 in-focus targets + weights
DB_STATE = "state"                    # SQL #3 runtime metrics / escaped envelopes

ALL_DBS = (DB_KNOWN_SCENTS, DB_ATTENTION, DB_STATE)


def db_uri(name: str) -> str:
    """Shared-cache in-memory URI for a logical DB. Open with uri=True.

    The owning process must keep at least one connection open for the lifetime
    of the DB or the shared-cache backing store is freed.
    """
    return f"file:deadnet_{name}?mode=memory&cache=shared"


# ----------------------------------------------------------------------------
# Enums
# ----------------------------------------------------------------------------
class CardRole(enum.Enum):
    IDLE = "idle"
    FINDER_AIR = "finder_air"      # monitor-mode 802.11 sniff -> known_scents
    FINDER_WIRE = "finder_wire"    # associated subnet sweep -> known_scents
    TRANSMITTER = "transmitter"    # associated poison; sole reader of attention


class EmitMode(enum.Enum):
    UNFOCUSED = "unfocused"        # whole-subnet free-fire (baseline)
    FOCUSED = "focused"            # weighted per-host attention from attention-list


class ScanPhase(enum.IntEnum):
    P1_SMELL = 1      # cheap OUI inventory of every signal/electronic (the important one)
    P2_FINGERPRINT = 2  # SYN scan + fingerprint (optional enrichment)
    P3_SMART_X = 3    # owner's "smart X scan" — STUB


class CardState(enum.Enum):
    ANDROID = "android"      # under Android's control (not seized)
    SEIZING = "seizing"
    MONITOR = "monitor"      # seized, monitor mode
    MANAGED = "managed"      # seized, associated (our control)
    RELEASING = "releasing"
    ERROR = "error"


# ----------------------------------------------------------------------------
# Hardware / capability model  (U0 records this; U1 parses it)
# ----------------------------------------------------------------------------
@dataclass
class IfaceCombo:
    """One line from `iw phy info` 'valid interface combinations'."""
    limits: Dict[str, int]          # e.g. {"managed": 2} or {"monitor": 2}
    total: int
    channels: int


@dataclass
class CardInfo:
    iface: str                      # wlan0 / wlan1 ...
    phy: str                        # phy0 ...
    mac: str = ""
    driver: str = ""
    modes: List[str] = field(default_factory=list)       # managed/monitor/AP...
    combos: List[IfaceCombo] = field(default_factory=list)
    bands_channels: List[int] = field(default_factory=list)
    state: CardState = CardState.ANDROID
    role: CardRole = CardRole.IDLE
    is_internal: bool = False       # internal chip (== adb/control path, handle with care)
    max_pps: int = 0                # measured by card benchmark (0 = unknown)

    @property
    def max_managed(self) -> int:
        return max((c.limits.get("managed", 0) for c in self.combos), default=0)

    @property
    def max_monitor(self) -> int:
        return max((c.limits.get("monitor", 0) for c in self.combos), default=0)

    def can_monitor(self) -> bool:
        return "monitor" in self.modes

    def selectable_networks(self) -> int:
        """How many networks this card can attack concurrently (managed STA cap)."""
        return self.max_managed if self.role != CardRole.FINDER_AIR else 0


@dataclass
class NetInfo:
    """Per-interface L3 facts discovered from the policy routing table (U1)."""
    iface: str
    device_ip: str = ""
    cidr: int = 24
    subnet_cidr: str = ""           # e.g. 192.168.1.0/24 (real prefix, not assumed /24)
    gateway_ipv4: str = ""
    gateway_ipv6: str = ""          # real link-local gw from the route table (not EUI-64 guess)
    gateway_mac: str = ""
    ipv6_prefix: str = ""
    ipv6_preflen: int = 0


# ----------------------------------------------------------------------------
# Records that flow through the SQLs
# ----------------------------------------------------------------------------
@dataclass
class ScentRecord:
    """A detected electronic (row in known_scents)."""
    mac: str                        # primary key
    ip: str = ""
    vendor: str = ""                # from OUI lookup
    ssid: str = ""
    ap_bssid: str = ""
    channel: int = 0
    signal_dbm: int = 0
    is_station: bool = True         # station vs AP
    net_id: str = ""                # which network-of-interest this belongs to
    first_seen_ms: int = 0
    last_seen_ms: int = 0
    lease_expiry_ms: int = 0        # 0 = unknown


@dataclass
class AttentionEntry:
    """An in-focus target (row in attention)."""
    mac: str                        # primary key
    ip: str
    net_id: str = ""
    weight: float = 1.0             # attention share; BirdObserver adjusts
    pinned: bool = False            # owner-pinned, BirdObserver won't downweight


@dataclass
class StateMetric:
    """Runtime metric for one electronic (row in state)."""
    mac: str                        # primary key
    escaped_pkts: int = 0           # "envelopes that went the wrong-write way"
    escaped_bytes: int = 0
    tx_pps: float = 0.0             # our tx rate aimed at it (focused mode only)
    compliant: bool = False         # True once escaped ~ 0 (poison holding)
    updated_ms: int = 0


# ----------------------------------------------------------------------------
# SQL schema (DDL). Keep column order stable — units rely on it.
# ----------------------------------------------------------------------------
SCHEMA: Dict[str, str] = {
    DB_KNOWN_SCENTS: """
        CREATE TABLE IF NOT EXISTS scents (
            mac TEXT PRIMARY KEY,
            ip TEXT DEFAULT '',
            vendor TEXT DEFAULT '',
            ssid TEXT DEFAULT '',
            ap_bssid TEXT DEFAULT '',
            channel INTEGER DEFAULT 0,
            signal_dbm INTEGER DEFAULT 0,
            is_station INTEGER DEFAULT 1,
            net_id TEXT DEFAULT '',
            first_seen_ms INTEGER DEFAULT 0,
            last_seen_ms INTEGER DEFAULT 0,
            lease_expiry_ms INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_scents_net ON scents(net_id);
    """,
    DB_ATTENTION: """
        CREATE TABLE IF NOT EXISTS attention (
            mac TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            net_id TEXT DEFAULT '',
            weight REAL DEFAULT 1.0,
            pinned INTEGER DEFAULT 0
        );
    """,
    DB_STATE: """
        CREATE TABLE IF NOT EXISTS metrics (
            mac TEXT PRIMARY KEY,
            escaped_pkts INTEGER DEFAULT 0,
            escaped_bytes INTEGER DEFAULT 0,
            tx_pps REAL DEFAULT 0.0,
            compliant INTEGER DEFAULT 0,
            updated_ms INTEGER DEFAULT 0
        );
    """,
}


# ----------------------------------------------------------------------------
# Python <-> C++ shared-memory protocol (emit.cpp control + stats)
# ----------------------------------------------------------------------------
# Two fixed-size files are mmap'd by both the Python EmissionController (writer
# of control, reader of stats) and the native emit.cpp (reader of control,
# writer of stats). Concurrency is a SEQLOCK: the writer bumps `seq` to an odd
# value, writes the body, then bumps `seq` to the next even value. A reader
# retries until it reads the same even `seq` before and after the body. This
# gives atomic, lock-free, tear-free reads per cycle with no corruption.
#
# All integers little-endian (arm64/x86 are LE). One file per Transmitter card;
# paths are <appdir>/focus_<iface>.shm and <appdir>/stats_<iface>.shm.
#
# ---- FOCUS (control) file, Python -> C++ --------------------------------
#   offset  type        field
#   0       u32         seq            (seqlock; even = stable)
#   4       u32         mode           (0 = UNFOCUSED, 1 = FOCUSED)
#   8       u32         count          (number of valid target entries)
#   12      u32         gen            (generation id; bumps when set changes)
#   16      u8[6]       gateway_mac    (real gateway MAC being impersonated)
#   22      u8[6]       our_mac
#   28      u32         flags          (bit0 = 0ttl aggressive, ...)
#   32      ...         entries[count] (see FOCUS_ENTRY)
# FOCUS_ENTRY (packed, 24 bytes):
#   0       u32         ip_be          (target IPv4, network byte order)
#   4       u8[6]       mac            (target MAC; zero = resolve/broadcast)
#   10      u16         _pad
#   12      f32         weight         (attention share, normalized 0..1)
#   16      u32         interval_us    (per-target send interval, 0 = as-fast)
#   20      u32         _reserved
FOCUS_HEADER_SIZE = 32
FOCUS_ENTRY_SIZE = 24
FOCUS_MAX_ENTRIES = 1024
FOCUS_FILE_SIZE = FOCUS_HEADER_SIZE + FOCUS_ENTRY_SIZE * FOCUS_MAX_ENTRIES

FOCUS_FLAG_0TTL = 1 << 0

# ---- STATS file, C++ -> Python ------------------------------------------
#   0       u32         seq            (seqlock)
#   4       u32         count
#   8       u64         ts_ms          (emit's clock at publish)
#   16      ...         entries[count] (see STATS_ENTRY)
# STATS_ENTRY (packed, 24 bytes):
#   0       u32         ip_be
#   4       u64         tx_pkts        (cumulative sent aimed at this target)
#   12      u64         tx_bytes
#   20      u32         _reserved
STATS_HEADER_SIZE = 16
STATS_ENTRY_SIZE = 24
STATS_MAX_ENTRIES = FOCUS_MAX_ENTRIES
STATS_FILE_SIZE = STATS_HEADER_SIZE + STATS_ENTRY_SIZE * STATS_MAX_ENTRIES

# struct formats (little-endian) for the Python side (struct module)
FOCUS_HEADER_FMT = "<IIII6s6sI"      # seq,mode,count,gen,gw_mac,our_mac,flags (+2 pad handled below)
FOCUS_ENTRY_FMT = "<I6sHfII"         # ip_be,mac,pad,weight,interval_us,reserved
STATS_HEADER_FMT = "<IIQ"            # seq,count,ts_ms
STATS_ENTRY_FMT = "<IQQI"            # ip_be,tx_pkts,tx_bytes,reserved


# ----------------------------------------------------------------------------
# Knobs — EVERY tunable the owner can set (requirement: expose every knob)
# ----------------------------------------------------------------------------
@dataclass
class Knobs:
    # emission
    emit_mode: EmitMode = EmitMode.UNFOCUSED
    arp_interval_us: int = 75_000           # baseline per-send interval
    cycle_interval_us: int = 10_000_000     # between full cycles (unfocused)
    zero_ttl: bool = True
    ipv6_ra_enabled: bool = True
    ipv6_ra_interval_s: int = 2
    # discovery
    scan_phases: int = ScanPhase.P1_SMELL   # highest phase to run
    mac_vacuum_interval_ms: int = 1000      # focused rediscovery cadence
    finder_air_hop_dwell_ms: int = 250      # channel dwell when sweeping air
    # state / rehydration
    state_refresh_ms: int = 100             # rehydrationStateMaintainer cadence
    compute_pps_focused_only: bool = True
    # BirdObserver
    bird_airborne: bool = True
    bird_cadence_governor: bool = True
    bird_attention_governor: bool = True
    bird_escalation_governor: bool = True
    bird_noncompliant_boost: float = 2.0    # weight multiplier for leakers
    bird_escalation_threshold: int = 5      # escaped pkts/s before promote->focused
    # safety
    confirm_before_live: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["emit_mode"] = self.emit_mode.value
        return d


# ----------------------------------------------------------------------------
# Preset model
# ----------------------------------------------------------------------------
@dataclass
class Preset:
    name: str
    description: str
    role_plan: Dict[str, CardRole]   # iface -> role (filled at apply time by count)
    knobs: Knobs


def kill_confirmed_knobs() -> Knobs:
    """KC: 2 transmitters full-speed unfocused baseline + 1 monitor finder;
    BirdObserver escalates focused attention onto any leaker it smells."""
    return Knobs(
        emit_mode=EmitMode.UNFOCUSED,
        arp_interval_us=0,            # full speed
        zero_ttl=True,
        bird_airborne=True,
        bird_attention_governor=True,
        bird_escalation_governor=True,
        bird_noncompliant_boost=3.0,
    )


# ----------------------------------------------------------------------------
# Arbiter ("row-reader RA") — abstract interface (U2 implements)
# ----------------------------------------------------------------------------
class Arbiter(Protocol):
    """Atomic gatekeeper over the three in-memory SQLs.

    Reads are instant (concurrent, lock-free from the caller's view). Writes are
    enqueued and applied FIFO per-DB by a single serialized writer thread, so a
    fast reader can never observe a torn/partial write. The emitter's in-focus
    rowset is additionally published to a shared-memory focus buffer on every
    committed attention write (see focus/stats protocol above).
    """

    def read(self, db: str, sql: str, params: tuple = ()) -> List[tuple]:
        """Immediate read. Returns all rows."""

    def write(self, db: str, sql: str, params: tuple = ()) -> None:
        """Enqueue a write (FIFO per db). Returns after it is committed."""

    def write_async(self, db: str, sql: str, params: tuple = ()) -> None:
        """Enqueue a write and return immediately (canonical FIFO order kept)."""

    def publish_focus(self, iface: str, entries: List[AttentionEntry],
                      mode: EmitMode, gateway_mac: str, our_mac: str) -> None:
        """Republish the in-focus rowset into the shared focus buffer for emit.cpp."""

    def read_stats(self, iface: str) -> Dict[str, tuple]:
        """Read the native stats buffer (ip -> (tx_pkts, tx_bytes))."""

    def close(self) -> None:
        ...


def now_ms() -> int:
    return int(time.time() * 1000)
