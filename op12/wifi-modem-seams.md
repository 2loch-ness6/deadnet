# OnePlus 12 — Wi-Fi modem seam map & kernel-rebuild notes

Device: CPH2581 (OP595DL1), SoC SM8650 "pineapple". Wi-Fi: **WCN7850 / "kiwi-v2"**, PCIe
device id **0x1107**, driver module `qca_cld3_kiwi_v2.ko` + platform `cnss2.ko`.
Source tree: `/srv/op12-kernel`. Running kernel at time of notes:
`6.1.57-android14-11-o-ge02429a7e0f3-dirty` (custom build, Magisk root, SELinux **Enforcing**).

Goal: map every host↔Wi-Fi-firmware control/debug seam, know what each gate is in
*source* (because we can rebuild the kernel + these out-of-tree modules), and know the
raw byte-level paths to talk to the firmware directly.

Both `cnss2` and the cld WLAN module are **built from this tree** (bzl globs the .c files;
kiwi-v2 → "BERYLLIUM" target), so every gate below is ours to flip in a rebuild.

---

## Trees
- Wi-Fi driver: `vendor/qcom/opensource/wlan/qcacld-3.0`  (HDD/SME/WMA + components/)
- Shared cmn:   `vendor/qcom/opensource/wlan/qca-wifi-host-cmn`
- FW API defs:  `vendor/qcom/opensource/wlan/fw-api`
- Platform:     `vendor/qcom/opensource/wlan/platform`  (cnss2, icnss2, cnss_utils, cnss_genl)
- GKI kernel:   `kernel_platform/common` + `kernel_platform/msm-kernel`
- Device WLAN config: `qcacld-3.0/configs/pineapple_gki_kiwi-v2_defconfig`
- Stock ini (on device): `/vendor/etc/wifi/kiwi_v2/WCNSS_qcom_cfg.ini`

---

## Wi-Fi feature audit (what the stock build ships)
Interface modes advertised by `iw list`: managed, AP, **monitor**, P2P-cli/GO, NAN.
Combos: `#{ monitor } <= 2` (monitor only appears standalone in combos).

- **Local packet capture (LPC)** — the OP12's capture path. `CONFIG_WLAN_DP_LOCAL_PKT_CAPTURE=y`.
  ini `local_packet_capture` defaults **true** (`qca-wifi-host-cmn/wlan_cfg/cfg_dp.h:896`).
  Handler: `os_if/dp/src/os_if_dp_local_pkt_capture.c` (vendor subcmd 202 SET_MONITOR_MODE / 225 GET).
  Stay-connected sniffing of own link; filters are "ALL"-only; single-STA, no MLO, no concurrency.
- **Old pkt_capture** (`os_if/pkt_capture/src/os_if_pkt_capture.c`, `WLAN_FEATURE_PKT_CAPTURE`) —
  NOT built on OP12 (only SDM660 / Lahaina+Parrot+QCA6490). Has a format-string bug at line 155
  (8 conversions, 7 args — stray `%s`). Irrelevant to us; noted.
- **Full monitor mode**: `CONFIG_FEATURE_MONITOR_MODE_SUPPORT=y`; entered via module param `con_mode=4`
  (QDF_GLOBAL_MONITOR_MODE); channel set via sysfs `monitor_mode_channel`. TX path shares the normal
  STA xmit; only RX monitor data-path code found → **frame injection likely absent** (not fully traced).
- **Spectral scan** `CONFIG_WLAN_CONV_SPECTRAL_ENABLE=y` (`wlan_hdd_spectralscan.c`).
- **CFR / enhanced CFR** `CONFIG_WLAN_CFR_ENABLE` + `_ENH_` (`wlan_hdd_cfr.c`) — channel-state / sensing.
- FTM factory mode `con_mode=5` (`CONFIG_QCA_WIFI_FTM`), NL80211_TESTMODE on.

Device check at notes time: `con_mode=0`, connected on ch149/80MHz, `gEnablePacketLog=0`,
`gEnableSNRMonitoring=1`, debugfs **not mounted**.

---

## Host ↔ firmware SEAMS (ranked by rawness)

### 1. cnss2 MMIO peek/poke + dev_boot  — RAWEST (arbitrary modem register access over PCIe)
Nodes: debugfs `cnss/reg_read`, `cnss/reg_write`, `cnss/dev_boot` (+ control_params, dynamic_feature,
runtime_pm, stats). File: `platform/cnss2/debug.c`.
- **Double gate** (`debug.c:984`): `#ifdef CONFIG_DEBUG_FS` (kernel) && `#ifdef CONFIG_CNSS2_DEBUG` (module).
- `CONFIG_CNSS2_DEBUG=y` is in **`cnss2/pineapple_consolidate_defconfig`** but **absent from
  `cnss2/pineapple_gki_defconfig`** → production GKI build compiles these OUT.
  Build picks `cnss2/{target}_{variant}_defconfig` (variant string `pineapple_gki` vs `pineapple_consolidate`).
  **REBUILD ACTION:** build consolidate variant, or add `CONFIG_CNSS2_DEBUG=y` to the gki defconfig.
- Write path (true HW MMIO, no FW cooperation for raw):
  `reg_write` → `cnss_bus_debug_reg_write` (`bus.c:589`) → `cnss_pci_debug_reg_write`
  → `cnss_pci_select_window()` (`pci.c:984`, sliding window over PCIe BAR) → `writel_relaxed`.
  Reaches whole modem address space via window remap.
- Usage: `echo <mem_type> <offset> <val> > cnss/reg_write`.
  `mem_type 0xFE` = MMIO_REG_RAW_ACCESS (direct, works pre-FW_READY); `0xFF` = MMIO_REG_ACCESS (needs FW up).
- `dev_boot` words: on/off/enumerate/powerup/shutdown/download/linkup/linkdown/**assert**/set_cbc_done/
  assert_host_sol/deassert_host_sol/pdc_update/dev_check/dev_enable.
- Still needs debugfs MOUNTED at runtime; SELinux labels gate access.
- CAVEAT: whether the WCN7850 PBL/firmware honors a given raw BAR region is firmware behavior, not in source.

### 2. unit_test_target  — raw WMI command injection to firmware
Node: sysfs `/sys/class/net/wlanX/unit_test_target` (`core/hdd/src/wlan_hdd_sysfs_unit_test.c`).
Path: store → `sme_send_unit_test_cmd` (`sme_api.c:10079`) → `WMI_UNIT_TEST_CMDID` to FW.
Args: `echo "<module_id> <n_args> <arg0> <arg1> ..."` (up to WMI_UNIT_TEST_MAX_NUM_ARGS u32s).
- Code already BUILT (`CONFIG_WLAN_SYSFS=y`). Gated at RUNTIME by ini:
  `CFG_ENABLE_UNIT_TEST_FRAMEWORK` = `gEnableUnitTestFramework`, **default 0** (`hdd_config.h:1001`).
  **ACTION:** set `gEnableUnitTestFramework=1` in ini (no rebuild) or patch default to 1.
- module_id validated against WLAN_MODULE_ID_MIN/MAX. Enum = `fw-api/fw/wlan_module_ids.h` (full list below).

### 3. DIAG / LOOPBACK MHI channels  — raw byte pipe to firmware, UNGATED in source
Channel table `platform/cnss2/pci.c:107` (unconditional):
  ch0/1 LOOPBACK, ch4/5 **DIAG**, ch20/21 IPCR (QMI/IPC-router), ch50 ADSP_0.
UCI char driver: `kernel_platform/msm-kernel/drivers/bus/mhi/devices/mhi_uci.c`.
- Node name = `"{parent}_pipe_{ul_chan_id}"` (`mhi_uci.c:650`). Parent = `mhi_1107_00.01.00`.
  → DIAG(ul=4) = **`/dev/mhi_1107_00.01.00_pipe_4`** (SELinux `vendor_mhi_diag_device`, system:system)
  → LOOPBACK(ul=0) = `/dev/mhi_1107_00.01.00_pipe_0` (root).
- UCI match table claims: LOOPBACK, SAHARA, DIAG, EFS, QMI0, QMI1, TF, DCI, DUN (`mhi_uci.c:759`).
  Only channels the cnss2 table actually defines bind → for WCN7850 only LOOPBACK + DIAG get UCI nodes
  (IPCR is grabbed by qrtr-mhi, not UCI → no pipe node).
- read/write = raw bytes: `mhi_uci_write` copy_from_user → `mhi_queue_buf(DMA_TO_DEVICE)`;
  `mhi_uci_read` dequeues inbound → copy_to_user. Chunked by `uci_dev->mtu` (driver_data 0x1000 = 4KB/xfer).
  So `pipe_4` carries raw **Qualcomm DIAG protocol** frames (0x7E-delimited), ≤4KB per write.

### 4. Already-ON in production gki config (no rebuild needed, some need debugfs mounted)
- `CONFIG_WLAN_DEBUGFS=y` → cld debugfs tree (`wlan_hdd_debugfs*.c`: unit_test, csr, llstat, coex, mibstat, config).
- `CONFIG_WLAN_SYSFS=y` + ~34 `WLAN_SYSFS_*` → per-netdev nodes always present:
  crash_inject, wlan_dbg, dl_* (loglevels), monitor_mode_channel, rf_test_mode, log_buffer, unit_test_target,
  txrx_fw_stats, dump_stats, wowl_add/del_ptrn, temperature, etc.
- `CONFIG_WLAN_FEATURE_WMI_DIAG_OVER_CE7`, `WMI_SEND_RECV_QMI`, `WLAN_DIAG_VERSION`, `QMI_SUPPORT`.
- cnss sysfs (live now, root, write-only): `shutdown`, `recovery`, `qdss_trace_start/stop`,
  `qdss_conf_download`, `hw_trace_override`, `fs_ready`, `enable_hds`  (QDSS = FW HW trace stream).
- Netlink families: `cnss-genl` (`cnss2/genl.c`, segmented data / QDSS cfg download) and
  `cld80211` (`qca-wifi-host-cmn/utils/nlink`, normal userspace↔driver, OEM/diag msgs ≤8K).

---

## Highest-leverage source edits
| Goal | Edit | Result |
|------|------|--------|
| Modem MMIO peek/poke + dev_boot | `CONFIG_CNSS2_DEBUG=y` in `cnss2/pineapple_gki_defconfig` | cnss/reg_read, reg_write, dev_boot (needs debugfs mounted) |
| Raw WMI→FW injection | default 1 on `gEnableUnitTestFramework` (hdd_config.h:1001) | unit_test_target live |
| Reach debug nodes at runtime | ensure debugfs mounted + SELinux label/permissive for testing | unlocks all debugfs trees |

---

## Runtime gates separate from source
- debugfs not mounted on current build → `mount -t debugfs none /sys/kernel/debug`.
- SELinux Enforcing → DIAG device + debugfs labels; Magisk can switch context for testing.
- adb currently tunnels over Wi-Fi (Tailscale tun0 → wlan0): anything that bounces the FW
  (DIAG writes, `dev_boot assert`, `recovery`, driver reload for con_mode) will drop the session.
  **Use USB adb for disruptive tests.**

---

## WLAN_MODULE_ID enum (unit_test module_id targets) — fw-api/fw/wlan_module_ids.h
0x0 INF, 0x1 WMI, 0x2 STA_PWRSAVE, 0x3 WHAL, 0x4 COEX, 0x5 ROAM, 0x6 RESMGR_CHAN_MANAGER,
0x7 RESMGR, 0x8 VDEV_MGR, 0x9 SCAN, 0xa RATECTRL, 0xb AP_PWRSAVE, 0xc BLOCKACK, 0xd MGMT_TXRX,
0xe DATA_TXRX, 0xf HTT, 0x10 HOST, 0x11 BEACON, 0x12 OFFLOAD, 0x13 WAL, 0x14 DE, 0x15 PCIELP,
0x16 RTT, 0x17 RESOURCE, 0x18 DCS, 0x19 CACHEMGR, 0x1a ANI, 0x1b P2P, 0x1c CSA, 0x1d NLO,
0x1e CHATTER, 0x1f WOW, 0x20 WAL_VDEV, 0x21 WAL_PDEV, 0x22 TEST, 0x23 STA_SMPS, 0x24 SWBMISS,
0x25 WMMAC, 0x26 TDLS, 0x27 HB, 0x28 TXBF, 0x29 BATCH_SCAN, 0x2a THERMAL_MGR, 0x2b PHYERR_DFS,
0x2c RMC, 0x2d STATS, 0x2e NAN, 0x2f IBSS_PWRSAVE, 0x30 HIF_UART, 0x31 LPI, 0x32 EXTSCAN,
0x33 UNIT_TEST, 0x34 MLME, 0x35 SUPPL, 0x36 ERE, 0x37 OCB, 0x38 RSSI_MONITOR, 0x39 WPM, 0x3a CSS,
0x3b PPS, 0x3c SCAN_CH_PREDICT, 0x3d MAWC, 0x3e CMC_QMIC, 0x3f EGAP, 0x40 NAN20, 0x41 QBOOST,
0x42 P2P_LISTEN_OFFLOAD, 0x43 HALPHY, 0x44 ENQ, 0x45 GNSS, 0x46 WAL_MEM, 0x47 SCHED_ALGO,
0x48 TX, 0x49 RX, 0x4a WLM, 0x4b RU_ALLOCATOR, 0x4c 11K_OFFLOAD, 0x4d STA_TWT, 0x4e AP_TWT,
0x4f UL_OFDMA, 0x50 HPCS_PULSE, 0x51 DTF (Deterministic Test Framework), 0x52 QUIET_IE,
0x53 SHMEM_MGR, 0x54 CFIR (Channel Capture), 0x55 CODE_COVER, 0x56 SHO (SAP HW offload),
0x57 MLO_MGR, 0x58 PEER_INIT, 0x59 STA_MLO_PS, 0x5a MLO_SYNC_SEQ_NUM, 0x5b PLCMGR (Policy Mgr),
0x5c-0x63 OEM0..OEM7, 0x64 T2LM, 0x65 HEALTH_MON, 0x66 XGAP, 0x67 MLO_OWNERSHIP_UPDATE,
0x68-0x6f SCHED_ALGO_* , 0x70 BAR ...  (WLAN_MODULE_ID_MAX bounds it; re-dump tail if needed)

Notable for poking: 0x3 WHAL / 0x13 WAL / 0x43 HALPHY (PHY), 0x54 CFIR (channel capture),
0x51 DTF, 0x22 TEST, 0x33 UNIT_TEST, 0x16 RTT.

---

## Open / not yet done
- Frame injection in monitor mode: TX path not fully traced (shares STA xmit; looks RX-only). CONFIRM.
- DIAG framing specifics (which DIAG cmd codes the WCN7850 FW answers) — firmware side, not in tree.
- Next: Bluetooth seam map (same WCN7850 combo chip — BT over UART/SoC, separate stack).

---

## WMI_MGMT_TX path trace — the injection ceiling (management frames)

Entry (cfg80211 `.mgmt_tx`): `wlan_hdd_mgmt_tx` → `__wlan_hdd_mgmt_tx` (`core/hdd/src/wlan_hdd_p2p.c:211`).
- Reads type/subtype from frame control `buf[0]` (WLAN_HDD_GET_TYPE/SUBTYPE_FRM_FC).
- Blocks ONLY in FTM mode. Does NOT validate/restrict content — caller supplies full 802.11 hdr+body.
- Routing:
  - mgmt AUTH subtype → `sme_send_mgmt_tx` (direct, no ROC / no policy-mgr). PASN/FT special-cased.
  - (re)assoc-resp in SAP/GO → FT-info filtered then `sme_send_mgmt_tx`.
  - everything else → `wlan_cfg80211_mgmt_tx` (needs remain-on-channel for off-channel).

Common sink (packer): `send_mgmt_cmd_tlv` (`qca-wifi-host-cmn/wmi/src/wmi_unified_tlv.c:4544`)
→ `WMI_MGMT_TX_SEND_CMDID`.
- **Frame copied VERBATIM.** `qdf_mem_copy(bufp, param->pdata, bufp_len)` — no parse, no rewrite.
- Inline cap `mgmt_tx_dl_frm_len` = **64** (non-HL/PCIe; `wmi_unified_param.h:54`, `#ifndef CONFIG_HL_SUPPORT`).
  Only first 64 B inlined as a header snapshot; FULL frame goes by **DMA** (2nd packer variant @4630:
  `cmd->paddr_lo/hi = qdf_nbuf_get_frag_paddr(tx_frame)`). So frame size is NOT capped at 64 — up to ~MTU.
- Fixed-param the HOST sets: vdev_id, desc_id, chanfreq, frame_len, buf_len, tx_flags, peer_rssi,
  optional tx_params (rate/power/chain via populate_tx_send_params). **No 802.11 header fields touched.**
- Seq-number host-set ONLY in the beacon-template path (`wma_mgmt.c:187`, `bcn->seq_no`), NOT mgmt-tx.

### What this means for injection
- **Host pass-through:** you can craft arbitrary mgmt frames — any subtype, any addr1/2/3, arbitrary IEs —
  and the host forwards them unmodified to firmware. This is the legit action-frame TX API.
- **Firmware decides the ceiling** (not in host source): assigns sequence control, duration/ID, enforces
  regulatory power, retries, and MAY reject subtypes / spoofed src depending on vdev state/mode.
- Works for: action / public-action, probe-req/resp, auth, deauth/disassoc; beacon/assoc-resp in AP/GO.
- Off-channel TX requires ROC; on the connected channel it's immediate.

### Monitor-interface injection = DEAD END in this tree
- A monitor vdev's TX goes through netdev `hdd_hard_start_xmit` (same as STA), NOT WMI_MGMT_TX.
- DP monitor code is RX-only (`wlan_dp_txrx.c` FEATURE_MONITOR_MODE_SUPPORT = `dp_mon_rx_packet_cbk`).
- No radiotap→TX wiring found. So classic `aireplay`/radiotap injection via mon0 is not supported here.
- **Use the cfg80211 mgmt_tx / action-frame API on a managed/AP/P2P vdev**, not a monitor interface.

### Net
Management-frame injection is real and host-unrestricted up to the WMI command; the only limits are
firmware policy (seq/power/subtype/addr). Data-frame raw injection (TCL rings) remains firmware-gated
and unreliable (matches ath12k: raw/monitor aimed at QCN9274, not WCN7850). Confirmed: no ath12k in tree
(have ath11k=WCN6855, wcn36xx); kiwi fw blobs on device at /vendor/firmware_mnt/image/kiwi/
(amss.bin, amss20.bin, bdwlan.e01..e0a board data).

---

## EMPIRICAL: mgmt-frame injection on stock fw (nl80211_inject, confirmed)

Tool: ~/OnePlus12_kernal/nl80211_inject.c (raw netlink → NL80211_CMD_FRAME). Built with NDK r23
(aarch64-linux-android31-clang). Device: USB (adb -P 5038, id 76b35c06), root, SELinux permissive,
wlan0 associated on ch149 / 5745 MHz.

Result progression (each result pinned the next gate, all in cfg80211 CORE, not qcacld/firmware):
1. cat 0x7f (vendor), spoofed SA/BSSID/DA  → -107 ENOTCONN
   gate: net/wireless/mlme.c:766-784 cfg80211_mlme_mgmt_tx — for STA, non-public action requires
   bssid==DA==connected AP.  Carve-out: `if (is_action && category != WLAN_CATEGORY_PUBLIC)`.
2. cat 0x04 (public action), spoofed SA/BSSID/DA  → -22 EINVAL
   gate: net/wireless/mlme.c:822 `if (!cfg80211_allowed_address(wdev, mgmt->sa) &&
         !cfg80211_allowed_random_address(wdev, mgmt)) return -EINVAL;`  → SA must be own MAC.
3. cat 0x04 public, **SA = wlan0 MAC (2a:b9:96:ac:74:18)**, DA=broadcast, BSSID=aabbccddeeff(spoofed)
   → **ACCEPTED, TX cookie returned.** Frame reached driver → firmware.

### The injection ceiling (empirically mapped), STA/managed, stock fw, no rebuild
- **SA / addr2 MUST be the interface MAC** (or a pre-registered random addr). cfg80211 anti-spoof.
- **addr1 (DA) and addr3 (BSSID) can be arbitrary** — spoofed BSSID accepted.
- **Non-public action** (cat != 0x04) only to the connected AP (bssid==da==AP), else ENOTCONN.
- **Public action (cat 0x04)** bypasses the connected-AP address check → free DA/BSSID.
- qcacld `__wlan_hdd_mgmt_tx` returns 0 for action frames (ignores lower status) → route is cfg80211→
  wlan_cfg80211_mgmt_tx → WMI_MGMT_TX. On-channel needs no ROC; off-channel set env OFFCHAN=1 (+ROC).
- Every block hit so far is **cfg80211 core (GKI kernel)**, NOT the qcacld module or firmware.

### Rebuild levers to widen it (we can rebuild the GKI kernel)
- **Arbitrary source-MAC spoofing:** patch `cfg80211_allowed_address()` / the check at mlme.c:822
  (net/wireless/mlme.c) to allow any SA. One kernel edit = full addr2 spoofing. (ONLY gate on SA.)
- **Arbitrary non-public action w/ spoofed addrs on STA:** relax the STA switch at mlme.c:766-784.
- Neither requires touching qcacld; both are core cfg80211.

### Still unverified (needs a sniffer / tx-status)
- Whether firmware actually puts the accepted frame ON AIR, and what it rewrites (seq ctrl is
  firmware-assigned; duration; power). Broadcast DA isn't ACKed, so cookie==accepted-for-TX, not on-air
  proof. NEXT: second-radio capture or oplus wlan debug stack / LPC monitor to observe + diff seqnum.

---

## CONFIRMED on-air (FRAME_TX_STATUS, nl80211_inject v2)

Tool extended to join the nl80211 "mlme" multicast group and read NL80211_CMD_FRAME_TX_STATUS.
Device wlan0 = 2a:b9:96:ac:74:18, assoc to AP c8:b4:22:5f:9d:ce, 5745 MHz.

- Unicast public-action → AP (DA=BSSID=c8:b4:22:5f:9d:ce, SA=own):
  RESULT accepted (cookie) + **FRAME_TX_STATUS success** → firmware transmitted; completion success
  for a unicast-to-AP ⇒ on-air delivery confirmed.
- Broadcast public-action (DA=ff..., BSSID spoofed aabbccddeeff, SA=own):
  accepted + FRAME_TX_STATUS success. NOTE: qcacld maps mgmt-tx completion onto the nl80211 ACK flag,
  so "ACK=yes" here = firmware reported successful TX, NOT a literal 802.11 ACK (broadcast isn't ACKed).

### Final confirmed ceiling (stock fw, no rebuild)
Management/action-frame injection WORKS end-to-end and goes on air. Constraints (all cfg80211 core):
  - SA/addr2 = own MAC (hard lock; anti-spoof at mlme.c:822).
  - addr1(DA)+addr3(BSSID) arbitrary for category 0x04 public action.
  - non-public action only to the connected AP.
Gold-standard external-sniffer capture still not done (would let us diff seqnum/power rewrites), but
in-band TX-status success + unicast-to-AP completion is strong on-air evidence.

Tool: ~/OnePlus12_kernal/nl80211_inject.c (v2: resolves family + mlme mcast grp, injects, waits TX status).
Build: NDK r23 aarch64-linux-android31-clang. Run: adb -P 5038, root, SELinux permissive.

## Device identity note
Model code CPH2581, board PJD110 (git), chip WCN7850/kiwi (PCIe 17cb:1107). Peer session labeled it
"OnePlus 12R"; our notes/session say "OnePlus 12". Marketing name ambiguous (PJD110 = Ace 3 / 12R family);
CONFIRM with user. All findings are chip/SoC-level and unaffected either way.

## Teammate debug-interface map (peer session, debugfs mounted) — reference
After `mount -t debugfs none /sys/kernel/debug`:
- /sys/kernel/debug/kiwi_v2/cldkiwi_v2/dbglog_block : blocking read of FW dbglog stream.
- /sys/kernel/debug/kiwi_v2/cnss_runtime_pm : RPM state machine.
- /sys/kernel/debug/wlan0/ : ll_stats, mib_stats, roam_stats, offload_info, wow_pattern, pattern_gen.
- /sys/kernel/debug/cnss/ : stats (subsystem bitmask; 0x6f26107 = FW_READY|... bring-up state),
  pin_connect_result, cnss_utils/mac_address.  (reg_read/reg_write/dev_boot ABSENT → confirms
  CONFIG_CNSS2_DEBUG off on gki, matches our source analysis.)
- /sys/kernel/debug/ipc_logging/ : cnss, cnss-long, cnss_plat, mhi_1107_00.01.00(_DIAG/_LOOPBACK).
- /sys/kernel/debug/tracing/events/wlan/ + instances/wifi/ : DP tracepoints (dp_tx_comp_pkt, dp_rx_pkt…)
  — NOTE: datapath only; mgmt frames (WMI_MGMT_TX) do NOT appear here, use FRAME_TX_STATUS instead.
- /sys/module/kiwi_v2/parameters/ : con_mode(0), con_mode_ftm, fwpath, country_code, pcie_gen_speed…
- /sys/bus/pci/drivers/cnss_pci/0000:01:00.0/ : link speed, reset, AER counters, mhi_1107…
- To widen debug surface in a rebuild: WLAN_DP_DEBUGFS, WLAN_DEBUG, WLAN_DEBUGFS+WLAN_STREAMFS.

---

## LPC self-capture attempt (WLAN_DP_LOCAL_PKT_CAPTURE) — did NOT work by hand

Goal: use the OP12's own Local Packet Capture to observe our injected TX (+ firmware rewrites),
no second radio. Built lpc_ctl.c (QCA vendor SET_MONITOR_MODE, id 0x1374 subcmd 202, frame-type
attrs 1..6 = BIT(0) ALL). Outcome: not usable through the manual iw + vendor-command path.

What happened:
- `iw phy phy0 interface add mon0 type monitor` created a monitor netdev (radiotap, tcpdump attaches)
  BUT immediately **disconnected wlan0**, and wlan0 could not re-associate while mon0 existed.
  i.e. STA + manual monitor do NOT coexist on this build, despite the source's LPC coexist design
  (wlan_hdd_add_monitor_check skips the force-disconnect branch when LPC is enabled, opens a
  QDF_MONITOR_MODE adapter — main.c:21278).
- lpc_ctl SET_MONITOR_MODE → **-1 EPERM**, both with others-down (0 conn) and as-is. Matches the gates
  in os_if_start_capture_allowed(): needs monitor-opmode vdev AND (0 conn OR exactly 1 STA) AND the
  connected channel. Downing NAN(wifi-aware0)+p2p0 didn't clear it → the missing piece is a live STA
  connection providing the capture channel, which we couldn't have while mon0 blocked association.
- tcpdump on mon0 = 0 packets (engine never started; `iw set channel` = EBUSY, no active channel).
- Tool is correct (cleanly reaches the vendor handler and gets a well-formed EPERM); blocker is the
  chip/driver STA+monitor state, not the tool. The Android WiFi HAL presumably drives LPC via an
  atomic keep-STA + add-monitor-vdev + start sequence we can't reproduce by hand.
- Cleanup: removed mon0, toggled wifi, wlan0 reconnected fine (ch11).

Verdict: LPC-by-hand is impractical here. To see firmware rewrites, best options remain:
  (a) mac80211 USB sniffer dongle (ath9k_htc/mt7601u/rtl8812au) — cleanest.
  (b) rebuild with WLAN_DP_DEBUGFS (+ WLAN_DEBUG) for datapath frame dumps.
  (c) accept existing strong on-air proof (unicast-to-AP MAC-ACK via FRAME_TX_STATUS).
Tools on device: /data/local/tmp/nl80211_inject (works), /data/local/tmp/lpc_ctl (works, gated by driver).

---

## REBUILD (in progress) — 4 levers, split across the dual-GKI boundary

Key architecture fact (from op12-docker-cfi-lto-invariant): device has TWO module sets —
  - system_dlkm (Google-signed): holds **cfg80211.ko**  ← CONFIG_CFG80211=m
  - vendor_dlkm (OnePlus):        holds **qca_cld3_kiwi_v2.ko**, **cnss2.ko**
So our 4 changes are NOT in the GKI Image; they are in MODULES.

PHASE 1 (building now via proven `build_with_bazel.py -t pineapple gki` → produces cfg80211.ko):
  - common/net/wireless/mlme.c, 2 edits, marked OP12-RESEARCH:
    (a) STA case in cfg80211_mlme_mgmt_tx → `break` (allow non-public action w/ arbitrary DA/BSSID).
    (b) cfg80211_allowed_address check → `if (0 && ...)` (allow arbitrary source MAC / addr2).
  - Both are INTERNAL logic; cfg80211 exported-symbol CRCs unchanged → KMI-safe (verify w/ gate).
  - Unlocks: full arbitrary-address mgmt/action injection (removes the only hard lock we hit).
  - Build log: /srv/op12-kernel/build-research-cfg80211.log ; artifact:
    kernel_platform/out/msm-kernel-pineapple-gki/dist/cfg80211.ko

PHASE 2 (staged, NOT built — needs the vendor WLAN module build target stood up, separate from gki):
  - cnss2/pineapple_gki_defconfig += CONFIG_CNSS2_DEBUG=y  → debugfs reg_read/reg_write/dev_boot.
  - qcacld configs/pineapple_gki_kiwi-v2_defconfig: += CONFIG_WLAN_STREAMFS=y, CONFIG_FEATURE_PKTLOG=y;
    disabled CONFIG_REMOVE_PKT_LOG  → pktlog frame capture (the real capture path; CONNECTIVITY_PKTLOG
    already =y). NOTE capture also needs ini gEnablePacketLog=1 on-device.
  - WLAN_DP_DEBUGFS does NOT exist in this tree; capture = pktlog/streamfs.

DELIVERY (undecided; STRICT no-flash-without-user-go rule applies, GOLDEN on standby):
  - cfg80211.ko → system_dlkm (Google-signed). Options: repack+flash system_dlkm partition, OR runtime
    module swap (hard: cfg80211 loaded early, many dependents).
  - qcacld/cnss2 → vendor_dlkm. Options: repack+flash vendor_dlkm, OR runtime rmmod/insmod (wifi down).
  - MANDATORY CRC gate before any flash (vs vendor-ref/ref_required_crcs.tsv); expect cfg80211 = 0 drift.

---

## REBUILD RESULT — cfg80211.ko BUILT + GATED (ready to swap)

Build: `build_with_bazel.py -t pineapple gki` completed OK. Artifact:
  /srv/op12-kernel/kernel_platform/out/msm-kernel-pineapple-gki/dist/cfg80211.ko  (fresh 07:15)
  pushed to device: /data/local/tmp/cfg80211_patched.ko (when device was up)
Built vermagic: 6.1.57-android14-11-o-g8c63b58fa7c2-dirty  (SHA label from msm-kernel/superproject).
Running device kernel: ...-o-ge02429a7e0f3-dirty. common/ (actual kernel source) HEAD = e02429a7e =
  SAME as device → vmlinux KMI our cfg80211 imports MATCHES device; SHA label diff is cosmetic
  (same_magic skips release token when CRCs present).

CRC GATE: PASS. cfg80211 provides 142 EXPORT symbols; 106 imported by on-device stock modules;
  **0 CRC drift** vs vendor-ref/ref_required_crcs.tsv. Canaries all match stock:
  init_task 0xd567d551, module_layout 0xea759d7f, register_netdevice 0xb4bdff70,
  cfg80211_connect_done 0x6699ba8e, rfkill_alloc 0x6a3675f4. → stock kiwi_v2 will relink cleanly.

RUNTIME SWAP (pending device reconnect; adb -P 5038 dropped the phone):
  deps: rfkill <- cfg80211 <- {kiwi_v2, mac80211}
  1. svc wifi disable; stop supplicant
  2. rmmod kiwi_v2 ; rmmod mac80211 ; rmmod cfg80211
  3. insmod /data/local/tmp/cfg80211_patched.ko
  4. insmod stock mac80211 + kiwi_v2 (from /vendor_dlkm/lib/modules/); svc wifi enable
  5. TEST: nl80211_inject with SPOOFED source MAC (addr2 != wlan0 MAC) → expect cookie + FRAME_TX_STATUS
     (previously -22 EINVAL at mlme.c:822; patch should now allow it).
  Reversible: reboot restores stock cfg80211.

---

## DELIVERY: Magisk module (bind-mount) — runtime rmmod/insmod FAILED, this is the fix

Lesson: hand rmmod/insmod of cfg80211 desyncs the qcacld Wi-Fi HAL (it owns module load/unload via
init.wlan -> `/vendor/bin/modprobe -d /vendor/lib/modules qca_cld3_wlan`; /vendor/lib/modules is a
symlink -> /vendor_dlkm/lib/modules). After a manual swap, "Wifi won't turn on at all". Reboot reverts
(swap is runtime-only) and restores stock — CONFIRMED recovery.

Correct delivery = replace the ON-DISK module so the HAL loads ours normally. /vendor_dlkm is erofs RO,
and Magisk magic-mount doesn't cover vendor_dlkm, so we BIND-MOUNT at post-fs-data:
  Magisk module `cfg80211patch`: module.prop + cfg80211.ko (patched, stripped 2.1MB, vermagic+__versions
  intact) + post-fs-data.sh:
    chcon u:object_r:vendor_file:s0 $MODDIR/cfg80211.ko ; mount -o bind $MODDIR/cfg80211.ko \
      /vendor_dlkm/lib/modules/cfg80211.ko
  Flashable zip (with META-INF/.../update-binary calling install_module) at:
    device: /sdcard/Download/cfg80211patch.zip ; host: /tmp/cfg80211patch.zip
  Install via Magisk app (Install from storage) -> reboot. Revert = remove module + reboot.
  Stock cfg80211.ko SELinux ctx = u:object_r:vendor_file:s0 (matched). Stock=2.1MB, our stripped=2.1MB.

POST-REBOOT TEST (pending): mount|grep cfg80211 (bind live) ; wifi on+assoc ; nl80211_inject spoofed SA
  -> expect cookie + FRAME_TX_STATUS (was -22 EINVAL at mlme.c:822 on stock).

---

## FULL nl80211_inject SURFACE MAP (2026-10-07, tested ON-DEVICE, persistent vendor_dlkm build)

Environment: tests ran on the phone itself (Debian container, host netns, root, SELinux **Disabled**).
The NDK binary can't run there (no /apex) → same source rebuilt with container gcc 15 (**needed
`#include <stdint.h>`** — bionic pulled it transitively, glibc doesn't; portability fix now in
nl80211_inject.c). wlan0 assoc c8:b4:22:5f:9d:ce, ch149/5745, MAC 2ab996ac7418.
cfg80211 scmversion `g8c63b58fa7c2-dirty` = the patched build → **persistent vendor_dlkm delivery
CONFIRMED live**: default frame with SPOOFED SA accepted + TXSTATUS (stock = -22 EINVAL at
mlme.c:822). Both kernel patches (arbitrary SA + non-public action w/ arbitrary addrs) verified
working. Raw results: /tmp/opencode/surface_results.txt, runner: /tmp/opencode/surface_test.sh.

### A. Frame-type/subtype gate (SA=own, DA=bcast, BSSID=spoofed, on-channel)
- **Every management subtype is accepted** — assoc-req/resp, reassoc-req/resp, probe-req (wildcard),
  probe-resp, beacon, disassoc, auth, deauth, action, action-no-ack (10/10 + body cases). No
  subtype filtering anywhere host-side (qcacld passes through, fw takes it).
- **Body required: frame must be ≥25 B** — bare 24-B header → EINVAL; ATIM (valid subtype, no body)
  → EINVAL (same gate, not a subtype gate).
- **Data/null/QoS-null (non-mgmt FC) → EINVAL**: path is management-only (cfg80211
  `cfg80211_mlme_mgmt_tx` type check). Raw data injection via this API = impossible; still
  monitor/TCL firmware-gated as previously documented.
- **Anomaly (consistent, 2/2): auth subtype accepted (cookie) but NO FRAME_TX_STATUS within 2 s.**
  Every other accepted frame reports TX status. Firmware/host apparently doesn't emit completion for
  AUTH → on-air status of auth frames UNKNOWN (only such subtype).

### B. Address gates — FULLY REMOVED by the patch (12/12 accepted)
- SA: own, locally-administered spoof, **broadcast ff:ff:…, all-zero, the AP's own MAC**, U/L-bit
  flipped own MAC → all accepted + TXSTATUS. cfg80211 does **zero** source validation now.
- DA: broadcast / third-party unicast / AP unicast — free.
- BSSID: connected AP / spoofed / broadcast / all-zero — free. DA≠BSSID mismatch — free.
- Net: arbitrary 3-address control on mgmt frames at the cfg80211 layer. Remaining limits are
  firmware policy only (seq ctrl, power, regulatory) + physical (who actually processes the frame).

### C. Action categories (10 tested: 00,01,04,06,07,0d,11,7f,fe,ff)
All accepted. Category is irrelevant host-side post-patch (the public-vs-non-public carve-out is
gone). cat 07 spuriously reported ACK=no once — the ACK flag is noisy (see TXSTATUS notes).

### D. Interface / frequency / off-channel
- Nonexistent iface → tool exits `no such iface` (if_nametoindex).
- Non-root → EPERM (-1) at netlink (needs CAP_NET_ADMIN).
- p2p0 / wifi-aware0 admin-DOWN → **-100 ENETDOWN** (pure IFF_UP gate).
- **p2p0 brought UP (unassociated managed wdev) → ACCEPTED + TXSTATUS.** Post-patch even an
  unassociated interface transmits (stock world: ENOTCONN).
- wifi-aware0 UP (NAN wdev) → **-95 EOPNOTSUPP** — real iftype gate: NAN has no mgmt-TX support.
- freq=0 → EINVAL; freq=36 (channel# given as MHz) → EINVAL; freq=5746 (not a channel) → EINVAL
  (must be a valid regulatory channel freq).
- **freq=2412 off-channel with NO OFFCHANNEL_TX_OK flag → ACCEPTED** (driver does implicit ROC;
  the flag is not a gate). Same for 5180. **freq=5955 (6 GHz ch2) accepted** → phy advertises
  6 GHz; off-channel 6 GHz TX reaches firmware too. ONCHAN freq + OFFCHAN=1 → accepted (flag
  harmless on-channel).
- TXSTATUS arrives even for off-channel frames (within tool's 2 s window).

### E. Frame size
- **Minimum 25 B** (24-B hdr only → EINVAL).
- 25 → 1500 B accepted (incl. 64/65-B boundary: both fine — the 64-B WMI inline cap is not a size
  limit; full frame goes by DMA as documented).
- **≥1601 B → tool limit `bad hexframe`** (hex2bin `frame[1600]` cap). Kernel/firmware max frame
  size above 1600 B NOT tested — raise `frame[]` + BUFSZ in the tool to probe further.

### F. Malformed input (tool behavior)
- `zz` → `bad hexframe`, exit 2. Empty frame str → EINVAL (0-len attr). Odd hex `d00` → parses 1 B →
  EINVAL. Spaced hex (`d0 00 …`) accepted (hex2bin skips separators). OFFCHAN takes atoi (non-numeric
  = off). ERROR path returns before the 2-s TXSTATUS wait (fast).

### TXSTATUS semantics (learned across ~60 frames)
- `ACK=yes` fires for BROADCAST frames constantly → it is the firmware TX-completion flag mapped
  onto NL80211_ATTR_ACK, NOT a literal 802.11 ACK (as previously suspected — now statistically
  clear: e.g. identical bcast frames report yes/no nondeterministically).
- Only unicast-to-AP completions carry literal-ACK meaning. Cookie = accepted-for-TX only.

### Net: post-patch acceptance ceiling of NL80211_CMD_FRAME on this device
Accepted iff: root (CAP_NET_ADMIN) + iface exists + IFF_UP + iftype supports mgmt TX (NAN out) +
freq = valid channel (0/channel#-as-MHz rejected; any band/ch incl. off-channel & 6 GHz) +
mgmt FC + body ≥1 B + frame ≤1600 B (tool cap). Everything else — SA/DA/BSSID/category/subtype of
any mgmt frame — is unconstrained host-side. Notable residual unknowns: auth TXSTATUS silence,
true on-air diff (seq/power rewrites) still needs external sniffer.

### G. DISRUPTIVE case (run last): deauth TO OUR OWN AP — the strongest on-air proof yet
Frame `c000 0000 DA=AP SA=own BSSID=AP 0000 reason=7` → accepted + TXSTATUS ACK=yes (unicast →
literal-ACK meaning applies here). Recovery: link back "Connected" at t+1s, DHCP lease intact,
gw ping blip 514ms. **Host dmesg confirms AP-side effect at the exact instant** (20:09:40.884):
`kiwi_v2: wlan0 ... Roam with c8:**:**:**:9d:ce "MySpectrumWiFiCF-5G" is SUCCESS` — i.e. our deauth
hit the air, the AP deauthenticated us, supplicant/driver immediately re-associated.
This is stronger than TXSTATUS: an external entity (the AP) reacted to the frame we crafted.
Log: /tmp/opencode/groupG.log.

### Session notes (2026-10-07 run)
- Ran on-device in Debian container (host netns, root via sudo, SELinux Disabled); session egress
  rode wlan0 itself → all disruptive tests deferred to the very end (survived, ~1 s blip).
- p2p0/wifi-aware0 left DOWN as found; no other state changed.

---

## PoC: op12-mgmt-poc.sh — interactive end-to-end driver of the patch (2026-10-07)

`~/OnePlus12_kernal/op12-mgmt-poc.sh` (+ nl80211_inject.c with the stdint.h portability fix).
Bash, self-rooting (sudo -n), auto-locates/builds the injector. Flow:
1. **Arm gate**: type YES (authorized-testing-only banner).
2. **Detect** (station mode, state-aware):
   - APs: fresh `iw dev wlan0 scan` when UNassociated (operator workflow); while ASSOCIATED the
     driver denies nl80211 scan (EPERM) → cached dump only (framework backfills it periodically)
     + `cmd wifi list-scan-results` if a real Android shell. Menu **D** = disconnect hint
     (svc wifi disable) for a full scan — with explicit session-drop warning.
   - Stations: `iw station dump` on other vdevs + active `arping` sweep → `ip neigh`
     (parser must take MAC after the `lladdr` token — field position varies with `router` flags).
   - Manual entry (MAC/freq/label/SSID).
3. **Operator selects target → LOCKED** (mac/type/freq/label + generated random fake-client MAC;
   locks across all attacks; R = relock/rescan). Locking OUR AP prints the SELF_KICK warning.
4. **Attack menu** (type-aware): deauth/disassoc (ap: broadcast-from-AP or directed-to-prompted-
   client | sta: AP→target or target→AP), probe-req flood w/ target SSID, auth/assoc join floods
   (SA=fake client), public/vendor/non-public action frames (OP12POC tag), beacon/probe-resp
   spoof, custom hex, **A** = safe demo set (probe+3 actions), **V** = end-to-end verify
   (link + addr + gw ping + target BSS/ARP state), **I** = capability recap.
   Every shot tallies accepted/N + fw-completion(ACK=yes)/N via the injector's RESULT/TXSTATUS.
5. Kick attacks marked `*` in the menu (disruptive), inert ones `#`.

Tested 2026-10-07 (associated, safe paths): safe demo set + beacon spoof 5/5 accepted, manual
target 5/5, verify OK (link/addr/gw/BSS), clean EOF/quit. Disruptive items intentionally not
auto-exercised in the test run (kick attacks cause ~1 s self-reconnect if target = our AP —
proven recoverable in Group G above).

Environment gotcha found while testing verify: **as ROOT (uid 0) LAN destinations route via
Tailscale tun1** (Android uidrange rule 0-10101 → table 1033 holds a 192.168.1.0/24 subnet
route), so plain `ping 192.168.1.1` as root = 100% loss while kali (uid 100000) pings fine.
Fix in script: `ping -I wlan0` (oif binding beats the uid rule). Debug recipe:
`ip route get <dst>` as both users shows the divergence immediately.

Unassociated fresh-scan path is coded but the associated-EPERM environment can't verify it
in-session (disabling Wi-Fi kills the session riding wlan0) — expected to work per driver
behavior; first thing to check when run from a real Android shell.

---

## PoC addition: NUKE mode — persistent promiscuous deauth (2026-10-07)

`op12-mgmt-poc.sh` (587 lines) now carries a hidden second example set for the
impact/CVSS case: type **NUKE** instead of YES at the arm prompt. While the
interactive menu covers one locked target per run, NUKE is the blast-radius
demonstration — it spoofs every detected AP and fires wildcard
FF:FF:FF:FF:FF deauth+disassoc until killed. Point: an *unauthenticated,
spoofed-SA broadcast-management flood* from a stock Wi-Fi 7 (WCN7850) client
takes down every client of every spoofed BSSID in RF range — exactly what
802.11w / WPA3-PMF (mandatory PMF) prevents. This is the documented WPA3/PMF
need case (2017 ESP8266-class deauth across the latest Wi-Fi standards).

### Behavior / controls
- Trigger: arm prompt, `NUKE` (not YES). Fires after a 3s listing/countdown (q aborts).
- On start: prints all detected APs + stations, then the spoof set; live status
  line every 1s: `spoofing N AP(s) . stations M . target P pps actual A pps . sent (ok) . keys`.
- Live keys: `+`/`=` up 10 pps, `-`/`_` down 10 pps (10..1000), `s` rescan (BSS
  cache refresh every ~30s automatic), `q` or Ctrl-C quit with summary.
- Env: `NUKE_SCOPE=all|own|<mac>` (default **all** = every detected AP; `own` =
  our associated AP; a bare MAC = single BSSID — used for safe mechanics tests).
  `NUKE_PPS=n` initial target.
- Rotation is sorted by frequency so consecutive frames share a dwell where possible.

### Implementation notes
- Lookups the injector in `--fast` mode (new fire-and-forget flag added to
  nl80211_inject.c): exits on the TX ACK instead of waiting up to 2s for
  FRAME_TX_STATUS → per-frame cost drops from ~40ms to ~5ms, measured ~190pps
  ceiling. Sends deauth(0700)/disassoc(0800), reason generic.
- Deadline pacing via bash EPOCHREALTIME + fractional `read -t` key poll — zero
  forks per frame; overrun resync prevents a busy-radio spiral.
- Status "actual" is the measured window rate; during framework scan windows
  the radio serializes TX and actual dips (observed 88→2pps during a rescan) —
  by design, the mode reports reality rather than masking it.

### Verified live (own-network scope only, 2026-10-07)
- Dry (fake BSSID): target 100→87/89, 110→96/94, 100→86/92 pps; 716 frames,
  716 accepted; rescan/keys/quit clean.
- On-air (scope=<own AP> c8b4225f9dce, 5745): 128 broadcast deauth/disassoc at
  88pps, all accepted — wildcard DA frames spoofed from a real AP BSSID.
- Board state during tests: wlan0 *unassociated* (station mode, scanning).
  Notable: nl80211 scan-trigger is denied by qcacld even unassociated
  (`iw scan` = EPERM), but the framework's background scans continuously fill
  the cfg80211 BSS cache (~500-600 BSS, 50k lines of dump) — so AP discovery
  goes through `scan dump`. parse_bss was rewritten from per-line sed forks
  (≈20s for 600 BSS) to a single awk state-machine (~0.1s).
- sudo re-exec drops caller env (env_reset), so NUKE_SCOPE/NUKE_PPS are frozen
  at script top and re-injected via `sudo env ...` — otherwise scope silently
  reverted to all.
- Field run (scope=all, 258 BSSIDs): sustained ~90 pps, 2770/2770 accepted over
  30s; at the 30s auto-refresh the cache shrank 258->149 and a stale rotation
  index crashed the loop (`NUKE_MAC[$idx]: unbound`). Fixed by clamping
  `idx % ${#NUKE_MAC[@]}` each iteration + `idx=0` on refresh. Re-verified live
  (own-AP scope): 30s refresh mid-flood, 3512/3512 accepted @ avg 92pps/38s.

### Scheduler generalized + multi-target scheduled bursts (2026-10-07, +105 lines)

The nuke pacing/rotation loop was refactored into a reusable **scheduler engine
(`sched_run <budget> <pps> <title>`)** that runs over the parallel spoof set
arrays `NUKE_MAC/NUKE_FREQ/NUKE_TYPE/NUKE_SSID` and drives frames through a
builder hook (`$SCHED_BUILDER`, called as `builder <idx> <mac> <freq> <tog>` →
sets `FRV`; `tog` alternates so builders can interleave two variants):

- `bld_nuke`  — wildcard deauth(0700)/disassoc(0800), SA/BSSID = spoofed BSSID.
- `bld_sched` — menu attack frames (modes 1-12, mirrored from the `atk_*`
  functions): broadcast/directed deauth+disassoc, probe, auth, assoc,
  public/vendor/nonpub action, beacon/probe-resp, custom hex. Each uses the
  target's own type (ap|station) and SSID; directed modes take one client MAC
  (`SCHED_CLI`) applied to all AP-type targets.

New capabilities from the refactor:

- **Bounded NUKE**: arm prompt accepts `NUKE <N>` (e.g. `NUKE 500`) — runs the
  promiscuous flood for exactly N frames then prints the summary and exits;
  plain `NUKE` stays infinite. Canonical pps/fps benchmark for the wildcard mode.
- **Comma multi-select**: at `Select target`, input `1,3,7` (or `1 3 7`) to lock
  *N networks at once* into the spoof set (deduped, freq-sorted, first one gets
  the single-target LOCK_* state so existing attacks keep working).
- **SSID-pattern target matching**: at `Select target`, `S<pattern>` matches
  detected AP SSIDs and returns the *same target-ID array* the comma-select
  feeds to `lock_select` — so one keystroke locks the whole set for a scheduled
  burst (`Stest_ap_*`, `SThe Mill*`). Matcher auto-selects the engine: pattern
  contains regex-only metachars (`. ^ $ + | ( ) { }`) → ERE (`S^OH`,
  `SThe Mill.*`); otherwise bash glob (`Stest_ap_*`). `S~<regex>` forces ERE.
- **Scheduled bursts of any menu attack**: menu option `13` with syntax
  `13 <attack#> <frames> [pps]`, or shorthand `<a#>s <frames> [pps]`
  (`5s 200 150` = attack 5 for 200 frames at 150 pps). Drives the chosen attack
  through the scheduler so each mode's pps/fps can be measured under the same
  deadline pacing (target vs actual shown live; `+/-` adjust while running).
- `SCHED_DRY=1` env (any run): counts frames without transmitting — zero-RF
  benchmarking of script-path throughput.

Verified (2026-10-07): `NUKE 30` dry 30/30 + summary; `${SCHED_SCOPE}` test run
YES → `1,2` multi-lock (2 targets) → `13 1 40 100` 40/40 → `5s 30 150` 30/30;
infinite NUKE still runs with live `-` pacing and clean `q` summary (92pps);
real-RF bounded `NUKE 60` (fake BSSID) 60/60 accepted; manual fake AP + `13 3
60 120` 60/60 accepted. SSID matching (dry): `S*Mill*` → 12 ids multi-locked,
`S^OH` (auto-detected ERE) → 15 ids multi-locked, no-match reprompt + fallback
single-lock clean. Bugfixes along the way: bash 5.3 `local`-statement
self-reference tripped `set -u` (`t=${ARR[$i]}` next to `i=$1` — split the
declarations); a top-level `local` in the menu-choice block (menu loop is not a
function — use plain assignment); re-added the dropped `next/now_t/total_t0`
init line (would have been `unbound variable` at frame 1).

### Python port + injector hardening (2026-10-08)

`op12-mgmt-poc.py` is now the canonical driver — straight-Python port of the
720-line bash script (stdlib only, same flow/frame bytes/scheduler semantics).
Stabilizations over the bash version: every prompt validates (typing `NUKE` at
*any* prompt dispatches to NUKE mode instead of the old line-299 `unbound
variable` crash); numeric/MAC/freq/hex inputs re-prompt with reasons
(mgmt ≥25 B, tool cap ≤1600 B); empty-cache rescan keeps the previous spoof set
(the old code cleared first, then divided by zero); pacing via
`monotonic_ns` deadlines + `select()` key poll (tty cbreak when interactive);
all subprocesses have timeouts; `--self-test` runs 30+ hardware-free checks
(frame vectors byte-identical to bash, matcher, lock/spoof/scheduler/nuke
semantics); `BSS_FIXTURE` feeds recorded scan dumps for tests/demos.
`--doctor` checks the stack non-disruptively (privilege/iface/link state,
cfg80211 build marker, harmless TX acceptance, spoofed-SA acceptance, AP
PMF caps, neighbor observability); `--doctor-disruptive` adds a one-frame
unicast self-deauth with reconnect watch as the observable TX-effect proof.

### --stdio daemon + multi-freq notes (2026-10-08)

`nl80211_inject --stdio <ifname>` holds one netlink socket and serves one
frame per stdin line (`[fast|full ]FREQ [HEX]` → `OK ...`/`ERR ...`; a bad
line never kills it). The Python driver uses it by default (one daemon per
iface, transparent one-shot fallback, `--no-daemon` to force the old path).
Measured, 60 harmless fast frames: single-shot 276 fps @ 10x the CPU
(user+sys), daemon 590 fps — at the 100 pps burst target both keep up, the
daemon just leaves headroom and no fork churn; live scheduler burst through
the daemon: 30/30 accepted @ 118 actual vs 120 target pps. Multi-freq is
native: every frame carries its own `NL80211_ATTR_WIPHY_FREQ`, rotation is
freq-sorted (channel-sticky), implicit ROC confirmed (2412/5180/5955
accepted, `OFFCHAN` flag unnecessary). No adb/Android-side pack: the
container already owns the hot path; `svc`/`cmd` add nothing worth an adb
transport dependency. Monitor mode stays a dead end at any vif count — the
monitor data path is RX-only with no radiotap→TX wiring, STA+monitor won't
coexist, and a radio can't capture its own TX anyway; mgmt-tx on a managed
vdev IS the injection surface.
Key field lessons (2026-10-08): "nothing happens" with a healthy driver most
often means (a) the link is simply down — the supplicant can leave the
network on its own (`REASON_DEAUTH_NETWORK_LEAVING`, not our frames), and
this container cannot drive reassociation (no `svc`/`cmd`, `wpa_cli`
refused) — rejoin from the phone UI, then re-run doctor; or (b) there is no
observable victim — one radio cannot witness its own spoofed frames take
effect (the transmitter never receives its own TX; the AP ignores self-SA),
so spoofed broadcast "no effect" with no second station/sniffer is expected,
not evidence of failure. Legitimate-SA unicast is the positive control
(instant disconnect + ~1-3s reconnect, dmesg-confirmed).
`nl80211_inject.c` hardened in place (originals backed up as
`.orig-20261008`/`.bak-20261008`): bounds-checked `add_attr`, `nla_ok`
validation on all three netlink attribute walks, EINTR-retry recv, reply-length
guards, TX cookie decoding, strict freq parsing (0 still passes through to the
kernel's EINVAL), `--help`/`--wait N` flags. Output contract unchanged
(`RESULT|TXSTATUS|bad hexframe|no such iface`), verified on-air (B0 baseline
accepted + TXSTATUS, cookie=0x108; `--fast` path clean).

---

## PERSISTENT PARTITION FLASH — patched cfg80211 in `vendor_dlkm_b` (2026-10-12/13)

Supersedes the Magisk bind-mount delivery above. The patched `cfg80211.ko` (the
two neutralised mlme gates: STA/non-public-action at `mlme.c:766`, SA
anti-spoof at `mlme.c:822`) is now written directly into the `vendor_dlkm_b`
partition with verity disabled, so it loads on every boot with no runtime
bind-mount.

Flash + boot (lh-laptop/loch-nuc):
- `vendor_dlkm_b` resized + written; `vbmeta_b` (verity-disabled) written.
- Boot `sys.boot_completed=1` in ~18 s, active slot `_b`, no bootloop.
- `adb reboot fastboot` -> fastbootd works for logical-partition flash; the
  earlier "fastboot broken" was only the key-combo bootloader-mode path.

On-device state after boot (verified 2026-10-13):
- Kernel base is now **`6.1.118-android14-11-o-g818f2506c9e7`** (the earlier
  notes were written against `6.1.57` — refresh references).
- `/vendor_dlkm/lib/modules/cfg80211.ko` vermagic
  **`6.1.118-android14-11-o-maybe-dirty`** (patched build; 2 067 752 B).
- `cfg80211` loaded with `holders … 2 qca_cld3_kiwi_v2,mac80211`.
- **CRC gate held:** `mac80211`, `qca_cld3_kiwi_v2`, `bluetooth`, `nfc`,
  `rfkill` all loaded against the patched module — zero symbol drift.
- WiFi STA enabled (`wlan0` = 192.168.1.173), BT + NFC up, no module
  unknown-symbol / disagrees-about-version errors. Verity disabled (the
  modified vendor_dlkm mounts).

Functional proof (non-disruptive, 2026-10-13, SELinux **Enforcing**, magisk
root, `wlan0` MAC `2a:b9:96:ac:74:18`, on-channel 5220 MHz; vendored
`nl80211_inject.arm64`):
- default vendor action -> accepted + `FRAME_TX_STATUS` (baseline path).
- **spoofed-SA** public action (cat 04, bogus DA/BSSID) -> accepted + TXSTATUS
  (stock: `EINVAL` @ `mlme.c:822`).
- **non-public** action (cat 00, BSSID != our AP) -> accepted + TXSTATUS
  (stock: `ENOTCONN` @ `mlme.c:766`).
Both gates therefore neutralised end-to-end on the persistent flash.

Recovery: GOLDEN + stock vbmeta staged on loch-nuc -> two-command `fastboot`
rollback to 100 % stock + verity.

App integration: the Android-namespace harness for this (`apk/engine/mgmt_tx.py`
+ `apk/engine/phycycle.py`, built as the side-by-side `org.deadnet.deadnetmgmt`
APK) is tracked on branch `feature/mgmt-replace-arp`; see `apk/MGMT_PORT.md`.
Roadmap there: build full mgmt-path support into DeadNet (selectable ARP vs
mgmt emission backend).
