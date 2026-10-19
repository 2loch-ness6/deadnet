# OP12 / WCN7850 kiwi_v2 — peer-agnostic raw mgmt-injection method (2026-10-16)

Design + implementation of a NEW qca_cld3 driver method that injects an
arbitrary 802.11 management frame **bypassing the host-side peer gate** that
blocks unassociated/spoofed injection. Companion to
`injection-levers-audit-2026-10-16.md` (what works vs disproven) and
`wifi-modem-seams.md` (seam map). For authorized testing on owned radios only.

## Why the old "wall" was the wrong wall

Two more source audits (the convergence audit + the channel/peerless audit)
established:

1. **Convergence.** Both mgmt-TX paths (p2p off-chan for STA/ROC, and
   `wma_tx_packet` for SAP/home-channel self-gen) funnel into ONE function:
   `wlan_mgmt_txrx_mgmt_frame_tx()` —
   `qca-wifi-host-cmn/umac/cmn_services/mgmt_txrx/dispatcher/src/wlan_mgmt_txrx_utils_api.c:437`.
   The peer it requires is a **pure bookkeeping token**: it (a) holds a ref,
   (b) derives the vdev (`:465`), (c) is stored in `desc->peer` for the
   completion ref-release. **The frame's addr1/addr2/addr3 are never read from
   the peer** — they are whatever bytes are in the nbuf.

2. **Wire is peer-agnostic (confirmed).** `wmi_mgmt_tx_send_cmd_fixed_param`
   (fw-api) carries `vdev_id, desc_id, chanfreq, paddr_lo/hi, frame_len,
   buf_len, tx_flags, peer_rssi` and the raw frame TLV — **no peer field**.
   `send_mgmt_cmd_tlv` (`wmi/src/wmi_unified_tlv.c:4756`) DMA-maps the nbuf
   itself and fills paddr. The peer requirement is 100% host-side policy, not a
   firmware requirement.

3. **Auto-cleanup with NULL callbacks.** If `wlan_mgmt_txrx_mgmt_frame_tx` is
   called with a NULL context and NULL tx/ota completion callbacks, the
   completion handler
   (`wlan_mgmt_txrx_tgt_api.c:1673-1690`) frees the nbuf, releases the peer
   ref, and recycles the descriptor automatically. The DMA unmap is already
   done in `wma_process_mgmt_tx_completion` (`wma_mgmt.c:2792`) before the
   handler runs. **Zero leak, no guard patches needed.**

4. **Channel context is the real gate** (not the peer). The firmware only
   radiates on a vdev that holds channel context. Only two vdev states have it:
   - **SAP up/beaconing** — camped continuously on its configured channel.
   - **associated STA** — on its operating channel.
   An **idle STA has none**; ROC-via-scan-engine is unreliable on this chip
   (measured 0–5%). So idle-STA injection is deprioritized. **SAP-camp is the
   high-confidence route:** set the SAP channel = the target's channel; put the
   target's BSSID in the RAW frame (the SAP's own BSSID is irrelevant — the SAP
   exists only to provide channel context). We do NOT need to be associated to
   the target and do NOT need to host it.

## The method (implemented)

`wma_inject_mgmt_frame(uint8_t vdev_id, uint16_t chanfreq,
const uint8_t *frame, uint16_t frm_len)` — `core/wma/src/wma_data.c`
(prototype `core/wma/inc/wma_types.h`):

1. bound-check vdev_id; get `wma_handle`, `psoc`, `pdev`.
2. `wlan_objmgr_get_vdev_by_id_from_psoc(psoc, vdev_id, WLAN_MGMT_NB_ID)`.
3. `wlan_objmgr_vdev_try_get_bsspeer(vdev, WLAN_MGMT_NB_ID)` — the vdev's own
   bss/self peer = a guaranteed-valid token (present iff SAP up / STA assoc).
4. `qdf_nbuf_alloc` + `qdf_nbuf_put_tail` + copy the raw frame bytes in.
5. fill `struct wmi_mgmt_params` (tx_frame=nbuf, pdata=nbuf-data, frm_len,
   vdev_id, chanfreq [0 => `interfaces[vdev_id].ch_freq`], qdf_ctx).
6. `wlan_mgmt_txrx_mgmt_frame_tx(peer, NULL, nbuf, NULL, NULL,
   WLAN_UMAC_COMP_MLME, &mgmt_param)` — **skips the p2p off-chan path and the
   `wma_tx_packet` addr-lookup gate entirely**.
7. release my vdev + peer refs (tx-side ref + nbuf owned by completion now).
   Error paths free the nbuf and release refs; nothing leaks.

Trigger: new per-interface sysfs node **`inject_mgmt`**
(`core/hdd/src/wlan_hdd_sysfs_inject_mgmt.{c,h}`, mirrors
`wlan_hdd_sysfs_unit_test`), write-only 0220, wired into the STA and SAP adapter
create/destroy lists in `wlan_hdd_sysfs.c`; object added to `Kbuild`.

```
echo "<freq_mhz> <hexframe>" > /sys/class/net/<ifname>/inject_mgmt
# freq 0 => the vdev's current operating channel
# e.g. deauth victim 40:45:da:96:aa:37 as ESP32 BSSID 08:d1:f9:e9:ed:41 on ch6:
echo "2437 c00000004045da96aa3708d1f9e9ed4108d1f9e9ed4100000700" \
        > /sys/class/net/wlan1/inject_mgmt
```

Injects on the vdev that owns `<ifname>`. **Normal mgmt-TX paths are
untouched** — the new code is only reachable through this node, so it cannot
regress stock Wi-Fi.

## Build

`/srv/op12-kernel/kernel_platform`:
```
tools/bazel run \
  --//build/kernel/kleaf/impl:force_disable_trim=true \
  --//build/kernel/kleaf:kmi_symbol_list_violations_check=false \
  --//build/kernel/kleaf:kmi_symbol_list_strict_mode=false \
  //vendor/qcom/opensource/wlan/qcacld-3.0:pineapple_gki_kiwi-v2_modules_dist
```
~5 min module-only; dist `.ko` unstripped (~523 MB) → `llvm-strip --strip-debug`
→ ~19.2 MB. Deliver via the same vendor_dlkm/Magisk live-swap path as the
monitor + cfg80211 work. **FLASHING is strictly user-gated.**

## Open / unproven (retire on the rig after build)

- FW actually radiates the raw frame through this entry on a SAP-camped
  channel — HIGH confidence (identical `wma_mgmt_unified_cmd_send` path that
  SAP's own deauths use) but UNPROVEN until fired.
- PoC: SAP up on ch6 (ESP32 rig channel) → inject deauth
  `addr1=victim-modem, addr2/3=ESP32-BSSID` → ping from inside the victim modem
  (192.168.4.2 → 192.168.4.1) as ground truth. Non-zero loss = unassociated
  injection cracked on this chip.
- Flags already satisfied: `gDualMacFeatureDisable=0` (op12_dualmac),
  `wmi_service_mgmt_tx_wmi` advertised by FW.
