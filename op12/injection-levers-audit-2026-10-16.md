# OP12 / WCN7850 kiwi_v2 — injection lever audit + on-device verdicts (2026-10-16)

Two source audits of the WLAN tree (`/srv/op12-kernel/kernel_platform/vendor/qcom/
opensource/wlan`, branch `a15-wifi-monitor`) looking for ways to widen 802.11 mgmt
injection, then ground-truthed the key claims on the ESP32+modem rig. Companion to
`wifi-modem-seams.md` (seam map) and the memory note
`unassoc-injection-needs-channel-context.md`.

Goal context: device runs PATCHED cfg80211 (`-maybe-dirty`; SA/subtype/address gates
removed) + STOCK qca_cld3 (`-gd0d07692e8eb`). Unassociated spoofed mgmt injection does
NOT radiate. Two serial gates: (A) scan-concurrency for ROC [opened via INI
`gDualMacFeatureDisable=0`, Magisk `op12_dualmac`], (B) peer requirement in the qca_cld3
mgmt-TX paths [THE WALL].

## VERDICT TABLE (what actually works)

| Approach | No-rebuild? | On-device result |
|---|---|---|
| Associated STA, SA = the AP you're assoc'd to | yes | **WORKS, 77% victim loss** (AP is a real peer) |
| Unassoc STA, spoofed SA | yes | FAIL — `no valid peer`, 0% |
| Unassoc STA, self/cloned MAC as SA | yes | FAIL — no objmgr self-peer exists for idle STA, 0% |
| `rand_mac_tx` self-peer fallback | yes | FAIL — same missing self-peer |
| SAP vdev, inject deauth addr2=SAP-BSSID | yes | gate PASSES but does NOT radiate (canned cookies, 0%); + can't set SAP BSSID to a target |
| SAP beacon/probe-resp templates | yes | peer-less, radiates (rogue-AP content) — NOT deauth; untested here |
| TDLS add-peer at arbitrary MAC | yes, assoc-required | UNTESTED |
| qca_cld3 rebuild (create-peer / peer-agnostic WMI TX) | NO (rebuild) | firmware radiation UNPROVEN |

## TX-paths audit — the peer gate, precisely

Every mgmt-TX converges on a peer lookup: **addr1 → addr2 → (self-peer only if
`opmode==QDF_NAN_DISC_MODE || rand_mac_tx`)**.
- STA/ROC/off-chan path (what our nl80211 injector uses): `p2p_populate_mac_header`
  (`qcacld-3.0/components/p2p/core/src/wlan_p2p_off_chan_tx.c:657`, lookups @678/683,
  self-peer fallback @698-701, `no valid peer` @710) and the twin in
  `p2p_execute_tx_action_frame` (@1227-1264).
- Non-offchan path: `wma_tx_packet` (`core/wma/src/wma_data.c:2754-2788`), addr1→addr2→
  vdev-MLD, NO NAN/rand gating — but TXes on the vdev HOME channel (needs assoc/SAP).
- WMI layer is peer-AGNOSTIC: `send_mgmt_cmd_tlv` (`qca-wifi-host-cmn
  wmi/src/wmi_unified_tlv.c:4756`) carries only vdev_id + chanfreq + raw frame, no peer.
  So the peer requirement is a HOST-side software gate, not firmware.
- **DISPROVEN claim:** idle unassoc STA has NO self-peer (addr2==vdev MAC lookup @684
  returns NULL on-device). Self-peer is created at vdev START (connect), not create.
  `rand_mac_tx` setter = `p2p_rand_mac_tx` @3090 (needs `!no_ack && chan_freq &&
  buf_len>MIN_MAC_HEADER_LEN && p2p_is_vdev_support_rand_mac(STA=true) &&
  (p2p_is_random_mac(SA) || !is_vdev_up)`), but its fallback resolves the same missing
  self-peer → useless.
- SAP vdev DOES have a self/bss-peer at its BSSID (gate passes) but our CMD_FRAME inject
  on it doesn't radiate (off-chan path no-ops on AP vdev).

## INI/config audit — real levers (host-side; FW regdb/PMF still authoritative)

Tier 1 (no-rebuild, SAP-centric offensive value):
- `enable_bcast_deauth_for_sap` 0→1 (`cfg_mlme_sap.h:668`; read
  `lim_send_management_frames.c:3812`, `lim_process_mlm_req_messages.c:1474`): SAP bcast
  deauth → one frame + `lim_del_sta_all()` kicks all clients. PMF clients ignore it.
- `gRateForTxMgmt` / `2G` / `5G` 0xFF→low rate code (`cfg_mlme_sap.h:106/130/155` →
  `wlan_mlme_main.c:2361` → `wma_set_vdev_mgmt_rate` → `wmi_vdev_param_mgmt_tx_rate`):
  pin self-gen mgmt to a robust low rate (range/reliability). Validated by
  `wma_verify_rate_code`.
- `gNumVdevs`→5 (`hdd_config.h:764`), `gMaxConcurrentActiveSessions`→4
  (`cfg_policy_mgr.h:97`), `gSoftApMaxPeers`→64 (`cfg_mlme_sap.h`): more concurrent
  vdevs / bigger SAP. FW target + interface-combo clamped.
- OEM vendor subcmds (`wlan_hdd_cfg80211.c:21585`): `OPLUS_...SET_MAX_ASSOC` (raise SAP
  cap from userspace), `OPLUS_...SET_WIFI_CONFIGURATION`.

Tier 2 (no-rebuild channel/power — only pays off WITH a country override, FW regdb
clamps): `gIgnoreCAC` (`cfg_mlme_dfs.h:155`), `gDisableDFSChSwitch` (:177),
`gSapAllowAllChannel` (`cfg_mlme_sap.h:245`), `etsi13_srd_chan_in_master_mode` /
`fcc_5dot9_ghz_chan_in_master_mode` / `gindoor_channel_support` /
`enable_nan_indoor_channel` (`cfg_mlme_reg.h:98/148/237/124`),
`coex_unsafe_chan_reg_disable` (:476), `gSelfGenFrmPwr` (:~43), chainmask knobs
(`cfg_mlme_chainmask.h`).

Ruled OUT: no INI defeats PMF (per-connection RSN cap, target-side); `TxPower2g/5g`
already 30 (max); `gEnableMacAddrSpoof` already 1. Raw-FW path =
`gEnableUnitTestFramework` → `/sys/.../unit_test_target` (module ids: MGMT_TXRX=0xd,
SCAN=0x9, WAL=0x13, UNIT_TEST=0x33, TX=0x48, RX=0x49 — `fw-api/fw/wlan_module_ids.h`).

Parsed INI inventories (if regenerating): were at
`scratchpad/ini_all.tsv` (913 qcacld) + `ini_cmn.tsv` (340 host-cmn) — session scratch,
regenerate from source if needed.
