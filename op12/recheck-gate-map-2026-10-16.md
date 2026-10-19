# Full re-check: mgmt-injection gate map, TX plumbing, and radiation blockers (source audit, pass 2)

**Date:** 2026-10-16
**Scope:** qca_cld3 / qca-wifi-host-cmn at `/srv/op12-kernel/kernel_platform/vendor/qcom/opensource/wlan`, branch `a15-wifi-monitor`. READ-ONLY — nothing in the tree was modified.
**Goal:** re-verify the earlier audit from scratch (better model, fresh eyes), correct errors, and close the two open source-side unknowns: (a) exact TX-completion plumbing without a peer, (b) the true set and shape of host-side gates between `NL80211_CMD_FRAME` and `WMI_MGMT_TX_SEND_CMDID`.

Device context: WCN7850 / kiwi_v2 fullmac, OnePlus 12 (CPH2581, SM8650). Patched cfg80211 on device (three kernel gates already neutralised: SA anti-spoof, TX-subtype mask, STA/non-public carve-out); stock qca_cld3. Firmware is NOT patchable — "we can patch anything above the SoC."

---

## 1. What held up exactly as previously reported

| Claim | Status | Ref |
|---|---|---|
| WMI layer is peer-agnostic | ✔ verified | `wmi_unified_tlv.c:4756` (`send_mgmt_cmd_tlv` assembles `WMI_MGMT_TX_SEND_CMDID` from buffer + `chanfreq` + vdev_id; no peer object touched) |
| Full frame reaches FW via DMA; the 64-B cap is not a frame limit | ✔ verified | `wmi_unified_tlv.c:4767-4768`; `mgmt_tx_dl_frm_len = 64` is the inline-copy cap only, `qca-wifi-host-cmn/wmi/inc/wmi_unified_param.h:53-57` (`#ifndef CONFIG_HL_SUPPORT` → 64, else 1532) |
| Completion handler is bounds-safe | ✔ verified | `wlan_mgmt_txrx_tgt_api.c:1638-1641` (`desc_id >= MGMT_DESC_POOL_MAX` → `E_INVAL`), `:1643` (not-in-use desc → `E_NULL_VALUE`) |
| Desc pool size on this build: **64** | ✔ verified | `qcacld-3.0/configs/config_to_feature.h:2518-2522` (`CONFIG_MGMT_DESC_POOL_MAX (64)`), not overridden in `pineapple_gki_kiwi-v2_defconfig` |
| RMF rewriter is not a threat to forged frames | ✔ verified | `wlan_p2p_off_chan_tx.c:1735-1737` — only rewrites `P2P_MGMT_ACTION` frames when `is_mgmt_protected` is set; deauth/disassoc/beacon/probe-rsp pass through byte-exact |
| Monitor mode is a TX dead end | ✔ unchanged | no radiotap→TX wiring anywhere in the data path; no monitor TX op |
| No STA+monitor iface combination | ✔ verified | `wlan_hdd_cfg80211.c:917-1050`; monitor-only combo allows 2 mons (`:1021-1027`); `.set_monitor_channel` present (`:30413`) |
| Dual-MAC / scan gate numbers | ✔ verified | `gDualMacFeatureDisable` default = 6, `cfg_policy_mgr.h:361»; `wlan_is_scan_allowed` at `wlan_cfg80211_scan.c:1444`; `wmi_service_mgmt_tx_wmi` present (used at `wma_mgmt.c:4087` to pick the WMI path over the `cdp_mgmt_send_ext` fallback) |
| Empirical anchors | ✔ unchanged | associated STA with SA = associated AP → radiates (77% victim ping loss); unassociated → 0%; ROC ≈ 2000 ms FW cap (3000+ → EINVAL); SAP beacons (template path) do radiate |

---

## 2. Correction 1 — `wlan_objmgr_peer_release_ref(NULL)` is NULL-safe

Earlier report flagged the unconditional release at `wlan_mgmt_txrx_tgt_api.c:1689` as a dangling-deref / crash risk for peerless TX. **Wrong:**

```c
// qca-wifi-host-cmn/umac/cmn_services/obj_mgr/src/wlan_objmgr_peer_obj.c:1417-1426
void wlan_objmgr_peer_release_ref(struct wlan_objmgr_peer *peer,
                                  wlan_objmgr_ref_dbgid id)
{
    ...
    if (!peer) {
        obj_mgr_err("peer obj is NULL for %d", id);
        QDF_ASSERT(0);      // WARN-level assert log in release builds
        return;             // ← no dereference, returns cleanly
    }
```

A peerless desc reaching `wlan_mgmt_txrx_tgt_api.c:1689` logs an assert line and continues. **Downgraded** from "must patch before first peerless TX" to **hygiene** (assert spam on a deauth flood would be de-facto log flooding, and hot-path asserts in this driver family are worth silencing anyway — patch remains desirable, but it is not a safety prerequisite).

Note for completeness: the `ref_cnt == 0` branch (`:1428-1436`) contains `WLAN_OBJMGR_BUG(0)`, which can be fatal in some build families — but that branch is unreachable in the peerless path (no ref was ever taken), so it is not load-bearing here.

---

## 3. Correction 2 — the peer gate is not one wall; it is a **series of three** peer lookups, and which one bites depends on subtype

Every existing route to firmware for mgmt frames dereferences a peer object. Full trace:

| Subtype injected | Route | Hard peer gate |
|---|---|---|
| action / deauth / disassoc / probe-rsp | cfg80211 → `wlan_hdd_mgmt_tx` → `wlan_cfg80211_mgmt_tx` → `ucfg_p2p_mgmt_tx` (`wlan_p2p_ucfg_api.c:298`) → `p2p_process_mgmt_tx` (`wlan_p2p_off_chan_tx.c:3178`) → `p2p_execute_tx_action_frame` (`:1825`) → `p2p_mgmt_tx` (`:1197`) → `wlan_mgmt_txrx_mgmt_frame_tx` (`:1291`) | **`p2p_mgmt_tx` lookup, `wlan_p2p_off_chan_tx.c:1239-1267`** — "no valid peer" rejection lives here, *not* in `p2p_populate_mac_header` |
| **AUTH only** | `__wlan_hdd_mgmt_tx` → `sme_send_mgmt_tx` (`sme_api.c:5608`) → `sme_prepare_mgmt_tx` (`:5577`, posts `eWNI_SME_SEND_MGMT_FRAME_TX`) → LIM `lim_send_mgmt_frame_tx` (`lim_process_message_queue.c:1877-1881`) → `lim_send_frame` (`lim_send_management_frames.c:7658`) → `lim_tx_mgmt_frame` (`:7423`) → `wma_tx_packet` | **`wma_tx_packet` lookup, `wma_data.c:2756-2788`** — peer by DA, fallback SA, then self/MLD |
| everything | — | `wlan_mgmt_txrx_mgmt_frame_tx` rejects a `NULL` peer argument outright (`wlan_mgmt_txrx_utils_api.c:454-457`) |

### 3.1 `p2p_populate_mac_header`'s peer lookup is NOT a gate

`p2p_execute_tx_action_frame` calls it at `wlan_p2p_off_chan_tx.c:1900` **without checking the return status**:

```c
1900:  p2p_populate_mac_header(tx_ctx);      // status ignored
1917:  status = p2p_populate_rmf_field(...); // (only rewrites PMF action frames)
1924:  status = p2p_mgmt_tx(tx_ctx, buf_len, packet, frame);   // ← the real gate
```

When its internal lookup (`:657-724`, by `addr1` then `addr2`, self-peer fallback only for NAN / `rand_mac_tx`) fails, the frame proceeds with the **sequence-control field exactly as userspace wrote it** — the host never touches seq on a peerless frame. The peer lookup's original purpose is per-peer seq bookkeeping (`p2p_get_next_seq_num`, `:596-715`, reads the peer's counter); that is cosmetic loss for us, not a functional loss: we control the seq bytes in the injector.

`p2p_get_next_seq_num` itself is `vdev`-based (`:606-612`) and only reads the peer for the counter — further confirmation that "peer" here means seq state, not TX permission.

### 3.2 The "auth emits no TXSTATUS" anomaly is now explained by source, not by firmware

Unassociated AUTH goes: `sme_send_mgmt_tx` → LIM → `wma_tx_packet` → peer lookup fails (no peer exists on an unassociated vdev) → `goto error` → frame dropped **host-side**, before any WMI command → no completion event can ever exist. The surface-map §A mystery is closed: **host drop, not a firmware quirk.**

(Corollary: when *associated*, the AUTH lookup passes and the frame does reach FW. If AUTH truly never produced TXSTATUS even while associated, that residue is still a genuine FW-side quirk — unproven either way.)

---

## 4. Correction 3 — the SAP "passes gate but won't radiate, canned cookies" datapoint was misdiagnosed: SAP deauth/disassoc/probe-rsp is **host-dropped**

New find: `p2p_vdev_check_valid` runs **first** in `p2p_process_mgmt_tx` (`wlan_p2p_off_chan_tx.c:3224`), before any peer lookup or WMI send. It has two compiled variants keyed on `SUPPORT_P2P_BY_ONE_INTF_WLAN` (`:103`, `:151`); `CONFIG_SUPPORT_P2P_BY_ONE_INTF_WLAN` is **not set** in `pineapple_gki_kiwi-v2_defconfig` (verified `config_to_feature.h:1184-1185` defines it only under `CONFIG_`, absent from defconfig), so the `#else` variant at `:152-199` is live on OP12:

```c
// wlan_p2p_off_chan_tx.c:172-179
/* drop probe response/disassoc/deauth for sta, go, sap */
if ((mode == QDF_STA_MODE &&
     tx_ctx->frame_info.sub_type == P2P_MGMT_PROBE_RSP) ||
    ((mode == QDF_SAP_MODE || mode == QDF_P2P_GO_MODE) &&
     ((tx_ctx->frame_info.sub_type == P2P_MGMT_PROBE_RSP) ||
      (tx_ctx->frame_info.sub_type == P2P_MGMT_DISASSOC) ||
      (tx_ctx->frame_info.sub_type == P2P_MGMT_DEAUTH)))) {
    → E_FAILURE → frame dropped host-side
}
```

(The `#ifdef` variant at `:104-133` has the same SAP/GO drops, plus extra non-P2P-action drops, so the conclusion holds either way.)

Consequences:

1. **The SAP channel-context verdict must be re-opened.** SAP is camped on a live channel, beaconing, with a real self-peer object — the most context-complete vdev on the phone. Whether *patched-through* SAP deauth/disassoc radiates is now **unknown (unproven)**, and testing it is one small patch away.
2. Beacons are **not** in the drop list (only probe-rsp/disassoc/deauth), which is consistent with the one SAP path empirically known to radiate: template/rogue-beacon content.
3. The "canned cookie 0x85c/0x861" attribution to firmware becomes suspect. The SAP deauth frames in that test should never have produced a FW completion (host drop at `:3224` precedes everything), so whatever cookie artifact was observed needs a clean re-test post-patch before it can be attributed to either side.

---

## 5. The complete, verified host-side gate map

In execution order for a deauth on an unassociated STA:

| # | Gate | Location | Status |
|---|---|---|---|
| 1 | Kernel cfg80211 anti-spoof / TX-subtype mask / STA carve-out | (patched GKI cfg80211) | **already removed** on device (`-maybe-dirty` vendor_dlkm_b, verity off) |
| 2 | HDD FTM-only gate | `wlan_hdd_p2p.c:239-348` | passes (blocks only FTM opmode) |
| 3 | p2p opmode/type drop | `wlan_p2p_off_chan_tx.c:173-179` | passes for STA+deauth; **blocks SAP/GO deauth + disassoc + probe-rsp** (Correction 3) |
| 4 | on-channel drop when `chan_freq==0` && unassoc STA | `wlan_p2p_off_chan_tx.c:3251-3258` | passes — injector always sets frequency |
| 5 | `p2p_populate_mac_header` peer lookup | `:657-724`, called unwrapped at `:1900` | fails **silently** — frame payload/FC/seq untouched; effectively already bypassed |
| 6 | **`p2p_mgmt_tx` peer lookup + "no valid peer"** | `:1239-1267` | **THE WALL** for unassociated STA |
| 7 | `wlan_mgmt_txrx_mgmt_frame_tx` non-NULL peer arg | `wlan_mgmt_txrx_utils_api.c:454-457` | second half of the same wall |
| 8 | Completion: `cb_context = context ? : peer` (`:1671`), unconditional release (`:1689`) | `wlan_mgmt_txrx_tgt_api.c` | **safe** per Correction 1; guard optional |
| 9 | AUTH-subtype only: `wma_tx_packet` peer lookup | `wma_data.c:2756-2788` | third wall on the SME/LIM shortcut path |

Firmware side: `wmi_service_mgmt_tx_wmi` selects `wma_mgmt_unified_cmd_send` (`wma_mgmt.c:4087`) over the legacy `cdp_mgmt_send_ext` fallback; the WMI command itself is peer-agnostic (§1).

---

## 6. What this changes in the bypass design

### Option A (patch the p2p engine to admit peerless frames) — now strictly preferred, and smaller than planned

1. `p2p_mgmt_tx` (`wlan_p2p_off_chan_tx.c:1239-1267`): when the lookup returns NULL, proceed with `peer = NULL` instead of failing. One-line logic change.
2. `wlan_mgmt_txrx_mgmt_frame_tx` (`wlan_mgmt_txrx_utils_api.c:454-457`): accept `peer == NULL`; skip the `try_get_ref`/release pair. Nothing else in the function needs the peer (p2p already holds the vdev ref and fills `mgmt_param->vdev_id` / `chanfreq` / `mac_hdr`).
3. Desc alloc: set `desc->peer = NULL`; `desc->context` stays `tx_ctx->p2p_soc_obj` (passed non-NULL at `wlan_p2p_off_chan_tx.c:1291-1293`) → completion callbacks (`tgt_p2p_mgmt_download_comp_cb` / `tgt_p2p_mgmt_ota_comp_cb`, `wlan_p2p_tgt_api.c:231-256`) validate `context != NULL` and never touch the peer → **the TXSTATUS path remains fully intact for peerless frames**.
4. Optional hygiene: guard the unconditional `wlan_objmgr_peer_release_ref(mgmt_desc->peer, ...)` at `wlan_mgmt_txrx_tgt_api.c:1689` against assert spam when `desc->peer == NULL`.
5. For SAP-channel-context injection, additionally lift the SAP/GO drop in `p2p_vdev_check_valid` (single condition, `:173-179`).

Side benefits of riding the p2p engine (vs. direct WMI): the frame keeps cookie→TXSTATUS mapping, rate/retry control via `tx_params_valid` (`:1171-1183`), and the entire desc lifecycle — no new infra.

### Option B (direct WMI, bypassing mgmt_txrx) — clearly inferior

`wma_process_mgmt_tx_completion` resolves the buffer via `mgmt_txrx_get_nbuf` (bounds-checked, `wlan_mgmt_txrx_tgt_api.c:1709`); for a desc_id that never entered the pool it returns NULL → **the DMA mapping is never unmapped** (the unmap step in the WMA completion handler is skipped — `wma_mgmt.c:2838+`) and no completion indication is ever generated. Direct-WMI injection means leaking one DMA mapping per frame and losing TXSTATUS. Rejected.

---

## 7. Still open / unproven after this pass

1. **Does firmware radiate a peerless-but-channel-contexted WMI mgmt TX?** Every prior 0%-loss datapoint was collected *behind* gates 6/7/3 — FW behavior for such frames was never directly observed. The SAP "canned cookie" datapoint that used to count against it is re-classified (Correction 3). Genuinely undetermined until a patched build is tested. Top candidate experiments: (a) patch 1+2 and fire from an associated STA vdev with a foreign-channel `chanfreq`; (b) also lift gate 3 and fire on the SAP vdev.
2. **Does FW rewrite seq control on the WMI path?** New nuance: because `p2p_populate_mac_header` failure is silently ignored (`:1900`), all previously-injected unassociated frames already carried our own seq bits host-side — but every *radiating* datapoint (77% case) had its seq assigned by `p2p_get_next_seq_num` from the real peer's counter. FW's own policy for the WMI path has never been observed. Sniffer job.
3. Whether FW also fakes completions ("canned desc_ids") for SAP vdevs, or whether the observed artifacts were host-side: needs the post-patch re-test.
4. `WLAN_OBJMGR_BUG` semantics in this build family — noted in §2, not load-bearing for the peerless path.

---

## 8. Bottom line

The strategic conclusion is unchanged and now *sharper*: everything blocking unassociated mgmt injection is **host-side, three peer lookups deep** (Correction 2), plus a second, previously-unlisted **opmode wall** for SAP/GO (Correction 3). The completion path is confirmed safe for peerless descs, so the minimal viable patch set is:

- ~3 small host-side patches (p2p `p2p_mgmt_tx` peer-optional, `wlan_mgmt_txrx_mgmt_frame_tx` peer-optional, optional `:1689` guard),
- optionally one more condition in `p2p_vdev_check_valid` to unlock SAP channel context,
- zero firmware work.

The firmware radiation verdict remains genuinely unobtained: in the entire prior test history the host never once let an unassociated peerless frame through to `WMI_MGMT_TX_SEND_CMDID`, so even the "canned" evidence is re-testable under a corrected configuration.

### Ranked experiment plan (patched build, all reversible, no flashing)

1. Patch §6/Option A(1)(2); fire unassociated STA deauth/action at the usual victim; watch ping loss + TXSTATUS. Resolves §7.1 for the STA case directly.
2. Add Option A(5); fire the same over the SAP vdev. Resolves §7.1 for the best channel-context vdev.
3. External sniffer (or second phone in monitor mode) to settle §7.2 (seq/power rewrite policy) once radiation occurs.

## Related repo docs

- `op12/injection-levers-audit-2026-10-16.md` — original verdict table (some entries superseded by Corrections 2/3 above)
- `op12/injection-method-design-2026-10-16.md` — method design
- `op12/wifi-modem-seams.md` — empirical surface map and device notes
- `op12/MEMORY.md` — session memory
