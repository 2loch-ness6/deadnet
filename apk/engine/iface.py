"""
DeadNet engine — U1: per-interface network + capability discovery.

Used by Detect & Connect and the multi-card engine to learn, for each wifi
card seized on the device:
  - its L3 facts (IP/CIDR/subnet/gateway v4+v6/gateway MAC) -> NetInfo
  - its hardware capability (modes, valid interface combinations, channels)
    plus identity (mac/driver/phy) -> CardInfo

All privileged reads go through `su -c "<cmd>"` (see `_su`), matching the
pattern in `apk/utils/net_utils.py`. Every parser below is a pure function
over a text string so it is unit-testable off-device (see the self-test at
the bottom of this file).

Stdlib only: re, subprocess, ipaddress.
"""
from __future__ import annotations

import os
import re
import sys
import subprocess
import ipaddress
from typing import Dict, List, Optional, Tuple

# Make `import engine.contracts` work whether this module is imported as
# part of the app (apk/ already on sys.path per CONTRACTS.md) or run
# standalone as `python3 engine/iface.py` from inside apk/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.contracts import NetInfo, CardInfo, IfaceCombo, CardState, CardRole  # noqa: E402

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

# Interfaces that are never attack-worthy, even if they happen to have an
# IPv4 + gateway (loopback, cellular data, tunnels, p2p/aware side-channels,
# virtualized container bridges, ...).
_EXCLUDED_IFACE_PREFIXES = (
    "lo", "tun", "rmnet", "dummy", "ifb", "p2p", "wifi-aware",
    "sit", "gre", "ip6", "tunl", "docker",
)


# ----------------------------------------------------------------------------
# Privileged shell-out (matches apk/utils/net_utils.py's su pattern)
# ----------------------------------------------------------------------------
def _su(cmd: str, timeout: float = 5.0) -> str:
    """Run `cmd` as root via `su -c`. Returns stdout, or "" on any failure."""
    try:
        result = subprocess.run(
            ["su", "-c", cmd], capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 and not result.stdout:
            Logger.error(f"{DEADNET_PREF}: iface._su non-zero rc for {cmd!r}: {result.stderr!r}")
        return result.stdout or ""
    except Exception as e:
        Logger.error(f"{DEADNET_PREF}: iface._su error for {cmd!r}: {e}")
        return ""


# ----------------------------------------------------------------------------
# Pure parsers — no I/O, unit-testable without a device
# ----------------------------------------------------------------------------
def _parse_addr_ipv4(text: str) -> Tuple[str, int]:
    """`ip -4 addr show dev <iface>` -> (device_ip, cidr prefixlen).

    e.g. "    inet 192.168.1.254/24 brd 192.168.1.255 scope global dynamic wlan0"
    """
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", text)
    if m:
        return m.group(1), int(m.group(2))
    return "", 0


def _parse_route_default_ipv4(text: str, iface: Optional[str] = None) -> str:
    """`ip route show table <iface|all> default` -> gateway ipv4.

    e.g. "default via 192.168.1.1 dev wlan0 table wlan0 proto static"
    If `iface` is given, only a line whose `dev <iface>` matches counts.
    """
    for line in text.splitlines():
        m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:.*?\bdev\s+(\S+))?", line)
        if not m:
            continue
        if iface is not None:
            if m.group(2) != iface:
                continue
        return m.group(1)
    return ""


def _parse_route_default_ipv6(text: str, iface: Optional[str] = None) -> str:
    """`ip -6 route show table <iface> default` -> link-local gateway ipv6.

    e.g. "default via fe80::1 dev wlan0 proto static metric 1024"
    """
    for line in text.splitlines():
        m = re.search(r"default\s+via\s+([0-9a-fA-F:]+)(?:.*?\bdev\s+(\S+))?", line)
        if not m:
            continue
        if iface is not None and m.group(2) is not None and m.group(2) != iface:
            continue
        return m.group(1)
    return ""


def _parse_neigh_mac(text: str, ip: str) -> str:
    """`ip neigh show <ip> dev <iface>` -> gateway MAC.

    e.g. "192.168.1.1 lladdr 7c:db:98:64:54:9d REACHABLE"
    Skips entries with no resolved lladdr (e.g. "<incomplete>" / "FAILED"),
    which the lladdr-mac regex simply won't match.
    """
    esc = re.escape(ip)
    for line in text.splitlines():
        if not re.match(rf"^{esc}\b", line.strip()):
            continue
        m = re.search(r"lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if m:
            return m.group(1).lower()
    return ""


def _parse_if_inet6(text: str, iface: str) -> Tuple[str, int]:
    """`cat /proc/net/if_inet6` filtered to `iface` -> (ipv6_prefix, preflen).

    Mirrors net_utils.get_ipv6_prefdata's hex parse. Each line is:
      <32-hex addr> <netlink dev no> <prefix len (hex)> <scope> <flags> <ifname>
    """
    for line in text.strip().splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == iface:
            raw = parts[0]
            try:
                preflen = int(parts[2], 16)
            except ValueError:
                preflen = 0
            prefix = ":".join(raw[i:i + 4] for i in range(0, 16, 4)) + "::"
            return prefix, preflen
    return "", 0


def _parse_iw_dev(text: str) -> Dict[str, Dict[str, str]]:
    """`iw dev` -> {iface: {"phy": "phy0", "type": "managed"}}."""
    out: Dict[str, Dict[str, str]] = {}
    cur_phy = ""
    cur_iface = ""
    for raw in text.splitlines():
        m = re.match(r"\s*phy#(\d+)", raw)
        if m:
            cur_phy = f"phy{m.group(1)}"
            cur_iface = ""
            continue
        m = re.match(r"\s*Interface\s+(\S+)", raw)
        if m:
            cur_iface = m.group(1)
            out[cur_iface] = {"phy": cur_phy, "type": ""}
            continue
        m = re.match(r"\s*type\s+(\S+)", raw)
        if m and cur_iface:
            out[cur_iface]["type"] = m.group(1)
            continue
    return out


def _extract_indented_block(text: str, header_pattern: str) -> List[str]:
    """Return the lines strictly more-indented than the header line matching
    `header_pattern`, i.e. the body of that section in `iw phy ... info`
    output. Blank lines inside the block are skipped but don't end it."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(header_pattern, line):
            header_indent = len(line) - len(line.lstrip())
            body: List[str] = []
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    continue
                indent = len(nxt) - len(nxt.lstrip())
                if indent <= header_indent:
                    break
                body.append(nxt)
            return body
    return []


def _parse_modes_block(body_lines: List[str]) -> List[str]:
    """`Supported interface modes:` body -> ["managed", "AP", "monitor", ...]."""
    modes = []
    for line in body_lines:
        s = line.strip()
        if s.startswith("*"):
            modes.append(s[1:].strip())
    return modes


def _merge_combo_lines(body_lines: List[str]) -> List[str]:
    """Join the (possibly multi-physical-line) `* ...` combo entries in the
    `valid interface combinations:` body into one logical string per combo."""
    combos_raw: List[str] = []
    current: Optional[str] = None
    for line in body_lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("*"):
            if current is not None:
                combos_raw.append(current)
            current = s[1:].strip()
        else:
            if current is None:
                continue
            current += " " + s
    if current is not None:
        combos_raw.append(current)
    return combos_raw


def _parse_one_combo(combo_text: str) -> IfaceCombo:
    """Parse one merged combo line, e.g.:
      "#{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, #{ AP } <= 1,
       total <= 3, #channels <= 2, STA/AP BI must match"
    -> IfaceCombo(limits={"managed":1,"P2P-client":1,"P2P-GO":1,"AP":1},
                   total=3, channels=2)
    """
    limits: Dict[str, int] = {}
    for kinds_blob, n in re.findall(r"#\{\s*([^}]+?)\s*\}\s*<=\s*(\d+)", combo_text):
        n = int(n)
        for kind in kinds_blob.split(","):
            kind = kind.strip()
            if kind:
                limits[kind] = n

    total_m = re.search(r"\btotal\s*<=\s*(\d+)", combo_text)
    chan_m = re.search(r"#channels\s*<=\s*(\d+)", combo_text)
    total = int(total_m.group(1)) if total_m else 0
    channels = int(chan_m.group(1)) if chan_m else 0
    return IfaceCombo(limits=limits, total=total, channels=channels)


def _parse_channels(text: str) -> List[int]:
    """`* 2412 MHz [1] (20.0 dBm)` style lines (anywhere in the phy info
    text, across all Frequencies: sub-blocks) -> deduped channel numbers."""
    nums = re.findall(r"^\s*\*\s*\d+(?:\.\d+)?\s*MHz\s*\[(\d+)\]", text, re.MULTILINE)
    seen: List[int] = []
    for n in nums:
        v = int(n)
        if v not in seen:
            seen.append(v)
    return seen


def parse_phy_info(text: str) -> Tuple[List[str], List[IfaceCombo], List[int]]:
    """Parse the full output of `iw phy <phy> info`.

    Returns (modes, combos, channels):
      modes    - list[str], e.g. ["managed", "AP", "monitor", "P2P-client"]
      combos   - list[IfaceCombo], one per "valid interface combinations" line
      channels - list[int], deduped channel numbers from all Frequencies: blocks
    """
    modes_body = _extract_indented_block(text, r"Supported interface modes:")
    modes = _parse_modes_block(modes_body)

    combos_body = _extract_indented_block(text, r"valid interface combinations:")
    combos_raw = _merge_combo_lines(combos_body)
    combos = [_parse_one_combo(c) for c in combos_raw]

    channels = _parse_channels(text)

    return modes, combos, channels


# ----------------------------------------------------------------------------
# Device-facing discovery (does I/O via _su)
# ----------------------------------------------------------------------------
def discover_iface_net(iface: str) -> NetInfo:
    """Discover the L3 facts for `iface` from the policy routing table."""
    net = NetInfo(iface=iface)

    addr_text = _su(f"ip -4 addr show dev {iface}")
    ip, cidr = _parse_addr_ipv4(addr_text)
    net.device_ip = ip
    net.cidr = cidr if cidr else 24

    network = None
    if ip:
        try:
            network = ipaddress.ip_network(f"{ip}/{net.cidr}", strict=False)
            net.subnet_cidr = str(network)
        except ValueError as e:
            Logger.error(f"{DEADNET_PREF}: discover_iface_net bad subnet for {iface}: {e}")

    # gateway v4: this iface's own policy table, then "table all" filtered
    # by dev, then fall back to .1 of the subnet.
    gw4 = _parse_route_default_ipv4(_su(f"ip route show table {iface} default"), iface=iface)
    if not gw4:
        gw4 = _parse_route_default_ipv4(_su("ip route show table all default"), iface=iface)
    if not gw4 and network is not None and network.num_addresses > 1:
        gw4 = str(network.network_address + 1)
    net.gateway_ipv4 = gw4

    net.gateway_ipv6 = _parse_route_default_ipv6(
        _su(f"ip -6 route show table {iface} default"), iface=iface
    )

    if net.gateway_ipv4:
        net.gateway_mac = _parse_neigh_mac(
            _su(f"ip neigh show {net.gateway_ipv4} dev {iface}"), net.gateway_ipv4
        )

    prefix, preflen = _parse_if_inet6(_su("cat /proc/net/if_inet6"), iface)
    net.ipv6_prefix = prefix
    net.ipv6_preflen = preflen

    return net


def _iface_mac(iface: str) -> str:
    return _su(f"cat /sys/class/net/{iface}/address").strip()


def _iface_driver(iface: str) -> str:
    # Best-effort: readlink the driver symlink and take its basename.
    out = _su(f"readlink -f /sys/class/net/{iface}/device/driver").strip()
    if not out:
        return ""
    return out.rstrip("/").rsplit("/", 1)[-1]


def _iface_has_own_default_route(iface: str) -> bool:
    out = _su(f"ip route show table {iface} default")
    return bool(_parse_route_default_ipv4(out, iface=iface))


def enumerate_cards() -> List[CardInfo]:
    """Enumerate every wifi card/iface visible to `iw dev`, with capability
    (modes/combos/channels) resolved once per phy and identity per iface."""
    dev_map = _parse_iw_dev(_su("iw dev"))

    phy_cache: Dict[str, Tuple[List[str], List[IfaceCombo], List[int]]] = {}
    for info in dev_map.values():
        phy = info.get("phy", "")
        if phy and phy not in phy_cache:
            phy_cache[phy] = parse_phy_info(_su(f"iw phy {phy} info"))

    cards: List[CardInfo] = []
    for iface, info in dev_map.items():
        phy = info.get("phy", "")
        modes, combos, channels = phy_cache.get(phy, ([], [], []))
        is_internal = iface == "wlan0" and _iface_has_own_default_route(iface)
        cards.append(
            CardInfo(
                iface=iface,
                phy=phy,
                mac=_iface_mac(iface),
                driver=_iface_driver(iface),
                modes=modes,
                combos=combos,
                bands_channels=channels,
                state=CardState.ANDROID,
                role=CardRole.IDLE,
                is_internal=is_internal,
            )
        )
    return cards


def list_attackable_ifaces() -> List[str]:
    """Interfaces that are UP, have an IPv4, and have a resolvable gateway,
    excluding loopback/cellular/tunnel/p2p/virtual interfaces."""
    raw = _su("ls /sys/class/net").split()
    attackable: List[str] = []
    for iface in raw:
        if any(iface.startswith(p) for p in _EXCLUDED_IFACE_PREFIXES):
            continue
        state = _su(f"cat /sys/class/net/{iface}/operstate").strip().lower()
        if state != "up":
            continue
        net = discover_iface_net(iface)
        if net.device_ip and net.gateway_ipv4:
            attackable.append(iface)
    return attackable


# ----------------------------------------------------------------------------
# Self-test (no device/root needed) — captured sample strings from the brief
# ----------------------------------------------------------------------------
_PHY_INFO_SAMPLE = """\
Wiphy phy0
\tSupported interface modes:
\t\t * managed
\t\t * AP
\t\t * monitor
\t\t * P2P-client
\tvalid interface combinations:
\t\t * #{ managed } <= 2,
\t\t   total <= 2, #channels <= 2
\t\t * #{ monitor } <= 2,
\t\t   total <= 2, #channels <= 2
\t\t * #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, #{ AP } <= 1,
\t\t   total <= 3, #channels <= 2, STA/AP BI must match
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412 MHz [1] (20.0 dBm)
\t\t\t* 2417 MHz [2] (20.0 dBm)
"""

_ADDR_SAMPLE = "    inet 192.168.1.254/24 brd 192.168.1.255 scope global dynamic wlan0"
_ROUTE_SAMPLE = "default via 192.168.1.1 dev wlan0 table wlan0 proto static"
_ROUTE6_SAMPLE = "default via fe80::1 dev wlan0 proto static metric 1024 pref medium"
_NEIGH_SAMPLE = "192.168.1.1 lladdr 7c:db:98:64:54:9d REACHABLE"
_NEIGH_INCOMPLETE_SAMPLE = "192.168.1.5 dev wlan0  INCOMPLETE"
_IF_INET6_SAMPLE = (
    "fe800000000000001234567890abcdef 03 40 20 80     wlan0\n"
    "00000000000000000000000000000001 01 80 10 80       lo\n"
)
_IW_DEV_SAMPLE = """\
phy#0
\tInterface wlan0
\t\tifindex 7
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:ff
\t\ttype managed
phy#1
\tInterface wlan1
\t\tifindex 9
\t\twdev 0x100000001
\t\taddr 11:22:33:44:55:66
\t\ttype monitor
"""


def _self_test() -> None:
    modes, combos, channels = parse_phy_info(_PHY_INFO_SAMPLE)
    assert "monitor" in modes, f"monitor not in modes: {modes}"
    assert "managed" in modes and "AP" in modes and "P2P-client" in modes, modes

    managed_combo = next(
        (c for c in combos if c.limits.get("managed") == 2 and c.total == 2), None
    )
    assert managed_combo is not None, f"no managed<=2,total==2 combo in {combos}"
    assert managed_combo.channels == 2, managed_combo

    tri_combo = next((c for c in combos if c.total == 3), None)
    assert tri_combo is not None, combos
    assert tri_combo.limits.get("managed") == 1, tri_combo
    assert tri_combo.limits.get("P2P-client") == 1 and tri_combo.limits.get("P2P-GO") == 1, tri_combo
    assert tri_combo.limits.get("AP") == 1, tri_combo

    card = CardInfo(iface="wlan0", phy="phy0", modes=modes, combos=combos)
    assert card.max_managed == 2, card.max_managed
    assert card.can_monitor()

    assert channels == [1, 2], channels

    ip, cidr = _parse_addr_ipv4(_ADDR_SAMPLE)
    assert ip == "192.168.1.254", ip
    assert cidr == 24, cidr

    gw4 = _parse_route_default_ipv4(_ROUTE_SAMPLE, iface="wlan0")
    assert gw4 == "192.168.1.1", gw4

    gw6 = _parse_route_default_ipv6(_ROUTE6_SAMPLE, iface="wlan0")
    assert gw6 == "fe80::1", gw6

    mac = _parse_neigh_mac(_NEIGH_SAMPLE, "192.168.1.1")
    assert mac == "7c:db:98:64:54:9d", mac

    incomplete_mac = _parse_neigh_mac(_NEIGH_INCOMPLETE_SAMPLE, "192.168.1.5")
    assert incomplete_mac == "", incomplete_mac

    prefix, preflen = _parse_if_inet6(_IF_INET6_SAMPLE, "wlan0")
    assert preflen == 0x40, preflen
    assert prefix == "fe80:0000:0000:0000::", prefix

    dev_map = _parse_iw_dev(_IW_DEV_SAMPLE)
    assert dev_map["wlan0"]["phy"] == "phy0" and dev_map["wlan0"]["type"] == "managed", dev_map
    assert dev_map["wlan1"]["phy"] == "phy1" and dev_map["wlan1"]["type"] == "monitor", dev_map

    # subnet math sanity (ipaddress), as discover_iface_net would compute it
    net = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)
    assert str(net) == "192.168.1.0/24", str(net)

    print("U1 PASS")


if __name__ == "__main__":
    _self_test()
