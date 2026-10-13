# DeadNet v3 — plan (branch `feature/v3-phy-ownership`)

Cut from `feature/mgmt-replace-arp` (`a5de708`). v3 is a re-founding of the app
around **PHY ownership + 802.11 mgmt-TX injection**. ARP poisoning is removed.

## 1. Vision

A single-radio tool that **takes exclusive control of the Wi-Fi PHY, locks
Android out of it, and walks the operator through two phases**:

1. **RECON (monitor)** — passively detect targets (APs + their clients) on air.
2. **ATTACK (managed mgmt-TX)** — inject 802.11 management frames at the
   operator's selection, using the patched `cfg80211` (three gates
   neutralised; see `op12/wifi-modem-seams.md`, `apk/MGMT_PORT.md`).

The app holds a **built-in baseline of the networking-stack defaults** and
restores it on exit, so the phone is left exactly as found.

## 2. Core model — one binary ownership state

| Ownership | Meaning |
|-----------|---------|
| `ANDROID` | Baseline. The framework owns the radio; the app is dormant. |
| `APP`     | **The app owns the PHY and guards it** — Android is locked out. |

Under `APP` the PHY sits in exactly one *mode*, switched by the workflow:

| Mode | vif | Android Wi-Fi | Purpose |
|------|-----|---------------|---------|
| `RECON`  | monitor (`mon0`) | disabled + guarded | passive detect |
| `ATTACK` | managed (`wlan0`, **unassociated**) | disabled + guarded | mgmt-TX injection |

Only one mode is ever live — the single RF chain forbids monitor + managed
together (`apk/engine/RADIO_MATRIX.md`).

**Attack needs no association / no credentials.** The patched gates allow
arbitrary `SA`/`DA`/`BSSID` and off-channel TX from an unassociated managed
wdev (proven: `op12/wifi-modem-seams.md` §D "p2p0 brought UP (unassociated
managed wdev) → ACCEPTED + TXSTATUS"). We bring `wlan0` (or a fresh managed
vif) UP, unassociated, and inject per target channel (implicit ROC).

## 3. Operator workflow

```
launch ─► APP/RECON   (seize phy → monitor; Android guarded)
          │  live target list: BSSID · SSID · ch · RSSI · client count
          ▼
        SELECT        (operator picks one / many targets, or S<pattern>)
          ▼
        APP/ATTACK    (mon0 → down; managed vif up; mgmt-TX at selection)
          │  live: accepted/N, TXSTATUS ack, actual pps
          ▼
        back to RECON | EXIT ─► ANDROID (baseline restored, guarded off)
```

## 4. What we tear out (incompatible with v3)

* `apk/src/emit.cpp`, `apk/src/arp.cpp`, `apk/src/nra.cpp` — ARP poison + RA
  spoof are gone. (History preserved on `feature/mgmt-replace-arp`.)
* `apk/assets/{emit,arp,nra}.*` — corresponding binaries.
* `apk/engine/emission.py` — ARP emit controller + focus/stats shm protocol.
* `apk/engine/birdobserver.py` — ARP-escapement attention; not meaningful for
  mgmt-TX (replace with a TXSTATUS-driven view).
* `apk/survival_monitor.py` + `apk/src/sniff.cpp` (SURV gauges) — ARP-survival
  counters. Recon needs 802.11 RX instead, not ARP headers.
* `apk/engine/finder.py` subnet sweep / `finder_passive.py` ARP listen — v3
  detection is monitor-based, not L3 sweep.
* `apk/engine/portscan.py` — unused enrichment for the old model.
* The dual-STA / `wlan1` "double guns" path in `radio.py` /
  `app_controller.py` — v3 is explicitly single-radio, own-the-PHY.

**Needs the user's call:** the standalone CLI `deadnet.py` (scapy ARP/RA). It
is a separate deliverable from the app; proposed to leave untouched (or move to
a `legacy/` dir) rather than delete.

## 5. What we keep / promote

* `apk/engine/rootshell.py` — the persistent `su` shell (reused as-is).
* `apk/engine/toolbroker.py` — tool resolution.
* `apk/engine/iface.py` — L3 facts (still useful for labels/gateway, trimmed of
  the ARP-only pieces).
* `apk/engine/arbiter.py` + `contracts.py` — keep the in-memory data model
  (scents/attention/state); **drop** the emit focus/stats shm layout.
* `apk/engine/mgmt_tx.py` — **promoted** from harness to the core attack
  transport (byte-identical builders, `--stdio` daemon).
* `apk/engine/phycycle.py` — **split up**: scheduler + target model + doctor
  become first-class; its `iw scan dump` detect is replaced by monitor recon.
* `apk/engine/radio.py` — **extended into** the PHY owner (see §6), not kept
  as-is (it currently models only seize-for-recon vs release).

## 6. New components

### `apk/engine/phyguard.py` — *the* owner of the PHY
The single authority over `phy0`. Encodes the binary ownership + mode machine.

* `own()` — `ANDROID → APP/RECON`: capture baseline, `svc wifi disable`, down
  all sibling vifs, add `mon0`, up, tune.
* `to_attack(freq)` / `to_recon(channel)` — mode switch (del mon0 → managed vif
  up unassociated, or reverse). No re-association, no `svc wifi enable`.
* `release()` — del vifs, restore baseline, `svc wifi enable`, wait for link.
* **Guarantees release** via `atexit` + SIGINT/SIGTERM (idempotent), carrying
  forward `radio.py`'s proven order-B sequence and emergency handler.

### `apk/engine/recon.py` — monitor-mode target discovery
* Native `src/recon.cpp` (ndk static, 4 arches): radiotap → 802.11 mgmt parse,
  emits one line per sighting (`BSSID SSID CH RSSI TYPE`), and client
  associations from data-frame addr fields (sees through client isolation).
* Python wrapper parses into the scent store; live-updates the RECON list.
* Fallback: tcpdump + Python parser (the `finder_air` approach) when the native
  binary is unavailable.

### `apk/engine/attack.py` — selection → scheduled mgmt-TX
* Target model + selection (single / comma-multi / `S<pattern>` glob|ERE),
  lifted from `phycycle.py`.
* Deadline-paced rotation over the selection (lifted `sched_run`), freq-sorted
  (channel-sticky), bounded or infinite; live `accepted/N`, `ack`, `pps`.
* Attack catalogue = the proven modes 1-12 (deauth/disassoc/probe/auth/assoc/
  action/beacon + custom hex) + wildcard `NUKE`.

### `apk/engine/capgate.py` — capability gate
Refuse ATTACK (with a clear message) unless the patched `cfg80211` is live:
vermagic `*-maybe-dirty` **or** a one-shot spoofed-SA probe that is accepted.
Keeps v3 honest on unpatched devices.

## 7. Architecture / module map

```
main.py (Kivy shell)
  └─ app_controller.py         state machine: ANDROID ↔ APP{RECON,ATTACK}
       ├─ engine/phyguard.py   own(a)/to_recon/to_attack/release  (phy0)
       ├─ engine/recon.py      monitor sniff -> scents (target list)
       ├─ engine/attack.py     selection + scheduler -> engine/mgmt_tx.py
       ├─ engine/mgmt_tx.py    nl80211 --stdio daemon (patched cfg80211)
       ├─ engine/capgate.py    patched-kernel gate
       ├─ engine/arbiter.py    scents / attention / state
       └─ engine/{rootshell,toolbroker,iface}.py
```

## 8. Baseline capture & restore ("leave it how it was found")

Snapshot once at `own()` (from `radio.py`'s baseline code), restate on
`release()`:
`wifi_on`, `airplane_mode_on`, `dual_sta_switch_on`, `WifiMultiInternetMode`,
associated SSID/BSSID. Plus the vif set we changed (which we down/up) and the
`mon0` we add (which we delete). Verified by an on-device restore test.

## 9. Guarding the PHY from Android

While in `APP` ownership we must stop the framework from re-grabbing the radio
(it auto-reconnects, raises `p2p0`/`wifi-aware0`, rescans):

* `svc wifi disable` (framework STA down) and keep it disabled across mode
  switches (do **not** toggle back on during ATTACK — attack uses our own
  unassociated managed vif).
* Down every sibling vif before adding `mon0` (proven necessary: `-16 busy`
  otherwise).
* Re-assert the guard on each transition and periodically (framework can
  self-heal); watch for a vif reappearing.
* **adb note:** disabling Wi-Fi drops any Wi-Fi/`tailscale` control path. USB
  adb is the safe channel during `APP` ownership (already flagged in
  `RADIO_MATRIX.md`).

## 10. UI (Kivy/KivyMD 1.2.0)

Rework the existing three screens to the new flow (keep framework/theme):

1. **Recon** — big `OWN PHY` control; live monitor target list (vendor-grouped
   like the old smell list), signal/CH/clients.
2. **Select** — pick targets (single/comma/`S<pattern>`), see the spoof set.
3. **Attack** — mode picker (1-12 + `NUKE`), focused (picks) vs unfocused (all
   detected), live gauges: **accepted/N**, **ack**, **actual vs target pps**.
4. Global: `RELEASE` (back to Android), capability-gate status, baseline status.

## 11. Build & packaging

* New profile `[app@v3]` → `package.name = deadnet3` → `org.deadnet.deadnet3`,
  side-by-side with the existing variants.
* Assets: drop `arp/emit/nra`; add `nl80211_inject.*` + `recon.*`. Strip
  binaries in the build recipe.
* Host recipe unchanged from `apk/MGMT_PORT.md` (JDK 17, `PIP_BREAK_SYSTEM_
  PACKAGES=1`, buildozer 1.6.0, storage under `/srv`).

## 12. Milestones

| M | Deliverable | Done when |
|---|-------------|-----------|
| M0 | Branch + teardown | ARP/emit/bird/survival removed, tree imports clean, old self-tests still green where kept |
| M1 | `phyguard.py` | off-device self-test: ownership+mode state machine, baseline capture/restore, guaranteed release |
| M2 | `recon.py` + `src/recon.cpp` | monitor detect populates targets on-device (AP + clients) |
| M3 | `attack.py` + `capgate.py` | selection → scheduled mgmt-TX on-device; gate refuses unpatched |
| M4 | UI rework | 3 screens drive the real state machine; gauges from TXSTATUS |
| M5 | Packaging | `org.deadnet.deadnet3` APK builds, installs side-by-side |
| M6 | On-device validation | own → recon → select → attack → release, baseline restored |

## 13. Testing

* **Off-device:** every module keeps a `__main__` self-test per
  `apk/engine/CONTRACTS.md` (mock `su`/`iw`/`ip` from canned strings).
* **On-device:** `capgate` probe; RECON sees a known AP; ATTACK acceptance +
  `TXSTATUS` on a bogus/local target; release restores Wi-Fi + baseline;
  opt-in disruptive self-deauth as the positive on-air control.

## 14. Risks / open questions

* **Device-specific patch.** v3's attack core assumes the flashed patched
  `cfg80211`. `capgate` gates it; on stock the ATTACK path is disabled.
* **Single RF chain** ⇒ recon and attack are strictly sequential; no live
  monitor during injection (an external radio is needed to observe TX).
* **PMF-required (WPA3) APs** are detected but immune to spoofed deauth by
  design — present as the WPA3 need-case, not a failure.
* **Framework fights the guard.** Some OEM builds re-enable Wi-Fi; the guard
  loop must be resilient (and must still release cleanly).
* **Recon throughput.** Native `recon.cpp` radiotap parsing vs tcpdump
  fallback — decide after M2 measurements.
* **Open:** keep the CLI `deadnet.py`? keep any L3/subnet features? move
  removed code to a `legacy/` tag vs rely on branch history?
