# DeadNet — mgmt-TX port (branch `feature/mgmt-replace-arp`)

State as of **2026-10-12**. Branch cut from `feature/multi-card-redesign`
(tip `536e20c`). Goal: replace DeadNet's ARP-based emission with 802.11
management-frame injection (cfg80211 `NL80211_CMD_FRAME`), orchestrated by an
Android-namespace harness that owns the single `phy0` cycle.

## Why

On the OnePlus 12 (CPH2581 / SM8650 / WCN7850 "kiwi-v2"), the ARP poison path
needs an associated L3 link + gateway and is blind under client isolation.
Management-frame injection is proven on this device up to a documented ceiling
(see `op12/wifi-modem-seams.md` "FULL nl80211_inject SURFACE MAP"): every mgmt
subtype accepted, SA/DA/BSSID arbitrary, any action category, off-channel + 6
GHz, on-air deauth confirmed by an external AP reaction. It needs only
`CAP_NET_ADMIN` + an UP vif.

## Branch commits

| Commit | What |
|--------|------|
| `a69fd89` | Vendor the OP12 PoC: `nl80211_inject.c`, `op12-mgmt-poc.{py,sh}`, seam/build notes (`op12/`) |
| `9cebb76` | `apk/engine/mgmt_tx.py` + `apk/engine/phycycle.py` (Android-ns harness) |
| `65001ec` | `nl80211_inject.{arm,arm64,x86,x86_64}` assets + `[app@mgmt]` buildozer profile |
| `4fc294a` | Built + committed `apk/bin/deadnetmgmt-2.0-...debug.apk` |

## What is done

### Engine (`apk/engine/`)

* **`mgmt_tx.py`** — Android-ns transmitter. Byte-identical frame builders to
  the container PoC (`fr()` / `ssid_ies()` / `build_frame()` modes 1-12 /
  `bld_nuke()`), plus a persistent `nl80211_inject --stdio` daemon per iface
  (socket + netlink family + mlme membership set up once, one frame per
  stdin/stdout line) with one-shot fallback. Staging mirrors
  `EmissionController`: `assets/nl80211_inject.<arch>` copied into `appdir`,
  `chmod 777` + `chown root`, launched under `su -c`. Self-test: `MGMT_TX PASS`.
* **`phycycle.py`** — Android-ns orchestrator porting the PoC's
  DETECT/LOCK/`sched_run`/`nuke_build`/`doctor`. Uses `iw scan dump`
  (associated => qcacld denies fresh scan, so cache), `cmd wifi
  list-scan-results`, `ip neigh`, peer `iw station dump`. SSID matcher (glob
  default, ERE on regex metachars or `S~`), comma multi-select, deadline-paced
  scheduler, PMF capability readout, opt-in 1-frame self-deauth proof.
  Never toggles wifi itself — release stays with `RadioController`.
  Self-test: `PHYCYCLE PASS`.
* No regressions: `apk/app_controller.py`, `apk/engine/rootshell.py`,
  `apk/engine/iface.py` still PASS.

### Packaging

* `nl80211_inject.*` built with the tree's **NDK r25b**, `-O2 -static`,
  `*-android29-*` targets (matches existing `arp.*` / `sniff.*` asset flags).
  Not yet stripped.
* New buildozer profile `[app@mgmt]` -> `title = Deadnet Mgmt`,
  `package.name = deadnetmgmt` => **`org.deadnet.deadnetmgmt`**, side-by-side
  with the existing `org.deadnet.deadnet` / `org.deadnet.deadneu` /
  `org.deadnet.arpmaxx`.

### Device

* Built APK installed on CPH2581 via `adb connect 100.87.236.24:5555`.
  Verified in `assets/private.tar`: `engine/mgmt_tx.pyc`,
  `engine/phycycle.pyc`, `assets/nl80211_inject.*`.
  Smoke-launched: process up, `PythonActivity` resumed, no Python errors.

## Build recipe (host)

Environment gotchas that must be satisfied (all hit and solved 2026-10-12):

```bash
cd apk
export JAVA_HOME=/srv/deadnet-build/jdk17/jdk-17.0.20.1+1   # Gradle 8.0.2 cannot run on system Java 25
export PATH=$JAVA_HOME/bin:$HOME/.local/bin:$PATH
export PIP_BREAK_SYSTEM_PACKAGES=1                          # Debian PEP-668 blocks p4a's `pip install --user`
# buildozer 1.6.0 + cython==0.29.36 installed via
#   pip install --user --break-system-packages buildozer==1.6.0 "cython==0.29.36"
buildozer --profile mgmt android debug
# artifact: apk/bin/deadnetmgmt-2.0-arm64-v8a_armeabi-v7a-debug.apk
```

Storage dir is `/srv/deadnet-build/dot-buildozer` (kept off the ~2 GB root fs);
the in-repo `apk/.buildozer` is effectively empty. Gradle tasks run under JDK 17.

## What is NOT done (next)

1. **UI wiring.** `apk/main.py` / `app_controller.py` still drive the ARP path.
   FIRE must route to `PhyCycle` (single-target `13 <atk>`) / spoof-set
   `NUKE`; gauges should show target vs actual pps, `accepted/N`,
   `ACK=yes/N` from `TXSTATUS` instead of the ARP `SURV` counters.
2. **Retire ARP behind a knob.** `apk/src/emit.cpp` / `arp.cpp` /
   `nra.cpp` and the survival `sniff` gauges stay compiled but default off;
   `PassiveFinder` + `BirdObserver` re-fed from mgmt `TXSTATUS`.
3. **Strip the injector assets** (currently ~3 MB each with debug_info).
4. **On-device validation** of the harness end-to-end: `phycycle.doctor`
   then `doctor`-disruptive (own-AP only), through the installed variant.

## Known constraints / caveats (from `op12/wifi-modem-seams.md`)

* PMF-required (WPA3) APs are immune to spoofed deauth **by design** — the
  WPA3 need-case, not a failure.
* `auth` subtype is accepted but emits no `FRAME_TX_STATUS` within the wait
  window (only such subtype) — on-air status unknown.
* `FRAME_TX_STATUS` `ACK=yes` is the firmware completion flag mapped onto
  `NL80211_ATTR_ACK`, NOT a literal 802.11 ACK (only unicast-to-AP carries real
  ACK meaning).
* One radio cannot witness its own spoofed frames; a second station/sniffer is
  required for true on-air diffs (seq/power rewrites).
* Data/null/QoS frames via this API are `EINVAL` (management-only path);
  monitor-mode TX is a dead end in this tree.
* Associated `nl80211 scan` trigger is denied by qcacld (`EPERM`) — detection
  rides the BSS cache + framework results.
* Root LAN destinations route via the Tailscale `uidrange` rule; bind the oif
  (`ping -I wlan0`) when verifying reachability as root.

## Deliberately excluded

Monitor-mode injection, data-frame injection, PMF bypass, and container-driven
reassociation (`svc`/`cmd` own that from the Android side).
