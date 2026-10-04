# Proven radio command matrix — OnePlus 12 (CPH2581 / Android 14 / phy0)

Established empirically on real hardware (owner directive: "we can't guess").
Single RF chain → the radio is EITHER associated (managed/attack) OR sniffing
(monitor), never both. `radio.py` (U6) encodes exactly these sequences.

## Facts
- `iw dev wlan0 set type monitor` → **rejected (-95)**. Monitor is only reachable
  via a monitor **vif** (`mon0`).
- `svc wifi disable` alone does **not** free the channel: `wlan0` netdev lingers and
  `iw dev mon0 set channel N` fails **-16 (busy)**. Must down `wlan0` first.
- Both 2.4 GHz and 5 GHz tune/hop work once `wlan0` is down (verified ch 1 / 6 / 36).

## RECON (→ monitor), proven order "B"
```
svc wifi disable
sleep 2
ip link set wlan0 down
iw phy phy0 interface add mon0 type monitor     # add_rc=0
ip link set mon0 up
iw dev mon0 set channel <N>                      # ch_rc=0  (hop = re-run)
# tcpdump -i mon0 -e -nn  → beacons + data visible
```

## RELEASE-BACK (→ Android/managed), proven
```
iw dev mon0 del
ip link set wlan0 up
svc wifi enable
# wlan0 re-associates on its own; confirm via: iw dev wlan0 link  → "Connected to <bssid>"
```
Guaranteed in `radio.py` via atexit + SIGINT/SIGTERM handlers (idempotent).

## LOCK & LEVEL (→ managed/attack)
Ensure wifi enabled + `wlan0` associated (`svc wifi enable`, wait for link), then
`iface.discover_iface_net(wlan0)` for gateway/subnet. Attack needs an associated
link (ARP injection into the WPA2 BSS uses the negotiated keys).

## NB
Internal `wlan0` is also the adb-over-tailscale control path. Seizing it for recon
drops that path for the duration (release-back restores it). Validated via
lh-laptop USB adb (serial 76b35c06), which is unaffected.
