# DeadNet — mgmt-TX port (branch `feature/mgmt-replace-arp`)

State as of **2026-10-13**. Branch cut from `feature/multi-card-redesign`
(tip `536e20c`). Goal: replace DeadNet's ARP-based emission with 802.11
management-frame injection (cfg80211 `NL80211_CMD_FRAME`), orchestrated by an
Android-namespace harness that owns the single `phy0` cycle, and **build full
support for the mgmt path into DeadNet itself** (see *Roadmap*).

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

* Built APK installed on CPH2581 via `adb connect` (tailnet IP rotates on
  reboot; current `100.84.93.116:5555`). Verified in `assets/private.tar`:
  `engine/mgmt_tx.pyc`, `engine/phycycle.pyc`,
  `assets/nl80211_inject.*`. Smoke-launched: process up, `PythonActivity`
  resumed, no Python errors.
* **Device base moved to kernel `6.1.118-android14-11-o-g818f2506c9e7`** (the
  `op12/` notes were written against `6.1.57`; refresh them to this base).

## Persistent flash milestone — gates live on every boot (2026-10-12/13)

The two `cfg80211` mlme gates we were previously neutralising at runtime
(`mlme.c:766` STA/non-public-action check and `mlme.c:822` SA anti-spoof) are
now **permanently flashed** into the `vendor_dlkm_b` partition, with verity
disabled, so the patched module loads on every boot and the whole dependent
stack works normally.

| check | result |
|---|---|
| Flash | `vendor_dlkm_b` resized + written, `vbmeta_b` (verity-disabled) written |
| Boot | `sys.boot_completed=1` in ~18 s, slot `_b`, no bootloop |
| Patched module | `/vendor_dlkm/lib/modules/cfg80211.ko` vermagic `6.1.118-android14-11-o-maybe-dirty` |
| Loaded at boot | `cfg80211 … 2 qca_cld3_kiwi_v2,mac80211` |
| CRC gate held | mac80211, qca_cld3, bluetooth, nfc, rfkill all loaded against the patched cfg80211 — zero symbol drift |
| Radios | WiFi STA enabled (`wlan0=192.168.1.173`), BT + NFC up |
| Verity | disabled (modified vendor_dlkm mounts) |
| Module errors | none (no unknown-symbol / disagrees-about-version) |

### Functional proof (non-disruptive, run 2026-10-13)

Injected from the STA on-channel (5220 MHz, SELinux **Enforcing**, magisk root;
`wlan0` MAC `2a:b9:96:ac:74:18`) with the vendored `nl80211_inject.arm64`:

| # | frame | stock behaviour | observed | verdict |
|---|-------|-----------------|----------|---------|
| 1 | default vendor action | accepted | accepted + `FRAME_TX_STATUS` | baseline TX path live |
| 2 | spoofed-SA public action (cat 04), bogus DA/BSSID | `EINVAL` @ `mlme.c:822` | accepted + TXSTATUS | SA anti-spoof gate neutralised |
| 3 | non-public action (cat 00), BSSID ≠ our AP | `ENOTCONN` @ `mlme.c:766` | accepted + TXSTATUS | action/AP address gate neutralised |
| 4 | assoc-resp from a STA vif (blocked subtype), real SA | `EINVAL` @ tx-subtype mask | accepted + TXSTATUS | TX-subtype mask gate neutralised |

An **independent** netlink tester run from the Kali chroot
(`/tmp/.../nl80211_frametest.py`, root over USB) reproduced the same three
gate-bypass cases against bogus locally-administered addrs on-channel, and
confirmed both gated checks are compiled into **stock**'s disassembly:

* **SA anti-spoof** — `cfg80211_allowed_address()` (the gate at `mlme.c:822`).
* **TX-subtype mask** — `wiphy->mgmt_stypes[iftype].tx & BIT(stype >> 4)`,
  i.e. a vdev only permits the mgmt subtypes its driver advertises for TX.

So the patch neutralises three checks in total: the STA/non-public address
carve-out (`mlme.c:766`), the SA anti-spoof (`mlme.c:822`), and the TX-subtype
mask. All three frames were single, addressed to non-existent
locally-administered MACs on the current channel — nothing real was affected.

Recovery stays intact: GOLDEN + stock vbmeta are staged on `loch-nuc`, so a
two-command `fastboot` rollback restores 100 % stock + verity any time.
`adb reboot fastboot` → fastbootd (logical-partition flash) works; the earlier
"fastboot broken" was only the key-combo bootloader-mode path.

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

## Roadmap — build full support into DeadNet

The end goal is not just a validating harness: the mgmt path becomes a
first-class emission backend in the app.

1. **UI wiring.** `apk/main.py` / `app_controller.py` still drive the ARP path.
   FIRE must route to `PhyCycle` (single-target `13 <atk>`) / spoof-set
   `NUKE`; gauges should show target vs actual pps, `accepted/N`,
   `ACK=yes/N` from `TXSTATUS` instead of the ARP `SURV` counters.
2. **Retire ARP behind a knob.** `apk/src/emit.cpp` / `arp.cpp` /
   `nra.cpp` and the survival `sniff` gauges stay compiled but default off;
   `PassiveFinder` + `BirdObserver` re-fed from mgmt `TXSTATUS`.
3. **Make the emission backend selectable** (ARP vs mgmt) so the ARP path
   remains available where the patched module is not present.
4. **Strip the injector assets** (currently ~3 MB each with debug_info).
5. **On-device validation** of the harness end-to-end through the installed
   variant: `phycycle.doctor`, then opt-in disruptive self-deauth (own AP only).

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
