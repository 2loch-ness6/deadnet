---
name: op12-docker-build-recipe
description: "PROVEN recipe to build a Docker-enabled OnePlus 12 kernel that boots with working WiFi/data (C6, verified on-device 2026-09-16)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 0bae6779-0fb4-4029-ae3e-60cee0459e9d
  modified: 2026-09-16T07:43:56.460Z
---

**PROVEN WORKING recipe (build "C6", flashed + verified on-device 2026-09-16):** a Docker-config-enabled OnePlus 12 (CPH2581) kernel that boots first-try with WiFi + cellular data intact and stock vendor_dlkm+system_dlkm all loading clean. See [[op12-device-facts]], [[op12-kernel-build-setup]], [[op12-current-state]]. Supersedes the old force-load recipe (that CAUSED a pre-console bootloop — see [[op12-docker-cfi-lto-invariant]]).

## The core principle (what took ~9 builds to learn)
DO NOT force-load. Force-loading (neuter check_version/same_magic + MODULE_FORCE_LOAD) does NOT fix ABI — it silences the CRC check while stock modules read/write STALE struct offsets → memory corruption → silent pre-console reset. The RIGHT approach keeps the kernel **KMI-byte-compatible** with the stock modules so they load through NORMAL validation, no bypass:
1. **Enable core Docker configs WITHOUT drifting struct CRCs** by parking new struct fields in `ANDROID_KABI_RESERVE` padding slots (DroidSpaces-OSS patches). CRC stays byte-identical under `__GENKSYMS__`.
2. **Fix networking** (stock's dead-WiFi cause) by DELETING the protected-exports lists, not by disabling module signing. The EACCES on system_dlkm was `MODULE_SIG_PROTECT`/protected-exports (MODULE_SIG_FORCE is OFF → signatures never block, only taint).
3. **Prove it before flashing** with a CRC gate vs the exact symbols stock modules import.

## The exact C6 changes (all under /srv/op12-kernel/kernel_platform; start from STOCK — revert any prior force-load hacks first)
1. **DELETE protected-exports** (networking fix): `rm -rf common/android/abi_gki_protected_exports_*` (aarch64 + x86_64). This is WildKernel's method; functionally == neutering gki_module.c but clean. Lets Google-signed system_dlkm load (rfkill/cfg80211 → WiFi/BT radios come up).
2. **SYSVIPC KABI padding** (DroidSpaces 6_7_8) in `common/include/linux/sched.h`: comment out the normal `struct sysv_sem sysvsem; struct sysv_shm sysvshm;` in the `#ifdef CONFIG_SYSVIPC` block, and in the task_struct reserve block replace `ANDROID_KABI_RESERVE(6/7/8)` with `#ifdef CONFIG_SYSVIPC / ANDROID_KABI_USE(6, struct sysv_sem sysvsem); _ANDROID_KABI_REPLACE(ANDROID_KABI_RESERVE(7); ANDROID_KABI_RESERVE(8), struct sysv_shm sysvshm); #else ...RESERVE(6/7/8)... #endif`. VERIFY slots 6/7/8 are still plain ANDROID_KABI_RESERVE (unused) first — in this tree they are (slot 1 = saved_state used, 2-8 free); fallback variants 3_4_5 / 1_2_3 exist. Macros ANDROID_KABI_USE / _ANDROID_KABI_REPLACE live in common/include/linux/android_kabi.h. Canary: after build, init_task CRC must stay 0xd567d551 (= task_struct layout unchanged).
3. **Minimal Docker config delta** appended to `common/arch/arm64/configs/gki_defconfig`: `CONFIG_SYSVIPC=y`, `CONFIG_IPC_NS=y`, `CONFIG_PID_NS=y`, `CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y`. (Stock ALREADY has NAMESPACES/NET_NS/CGROUPS/MEMCG/VETH/BRIDGE/OVERLAY_FS =y — don't re-add.) DROPPED USER_NS in pass 1: from_kuid isn't in any KMI list + cred.h has 0 reserve slots (can't pad) → rootful Docker works without it. NEVER enable: MEMCG_SWAP, CFS_BANDWIDTH, IPVLAN, CGROUP_DEVICE (device-confirmed OP12 bootloop / kABI hazard).
4. **Boot-safe build-time flags** in `msm-kernel/build_with_bazel.py` (`self.user_opts.extend`): `--//build/kernel/kleaf/impl:force_disable_trim=true` (keeps non-KMI symbols like from_kuid exported so vendor modules link — orthogonal to the CRC gate, which checks CRC match not presence), `--//build/kernel/kleaf:kmi_symbol_list_violations_check=false`, `--//build/kernel/kleaf:kmi_symbol_list_strict_mode=false`. These are BUILD-TIME ONLY, boot-safe, NOT the force-LOAD.
5. **check_defconfig relaxation** (build-time): `common/build/kernel/_setup_env.sh` `check_defconfig()` → `return 0` at top (our added configs make gki_defconfig non-canonical). (WildKernel does the equiv via `sed '2s/check_defconfig//' build.config.gki`.)
6. **version.c + gki_module.c stay STOCK.** No MODULE_FORCE_LOAD, no CFI_PERMISSIVE, no re-key handling needed (Image-only shipping).

## Build + date
`cd /srv/op12-kernel/kernel_platform && export PATH="$HOME/bin:$PATH" && export SOURCE_DATE_EPOCH=$(date +%s) && python3 build_with_bazel.py -t pineapple gki` (~24 min on 32 vCPU / 32 GiB). Output: `out/msm-kernel-pineapple-gki/dist/{Image,Module.symvers}`. vermagic = `6.1.57-android14-11-o-ge02429a7e0f3-dirty` (flags tail matches stock; same_magic skips release token w/ CRCs present).

## MANDATORY CRC GATE before flashing (this is what makes it safe)
Gate C6's Module.symvers vs `/srv/op12-kernel/vendor-ref/stock_modversions.txt` (4332 "<crc> <sym>" pairs = every symbol imported by all 396 on-device stock modules, staged by lh-laptop). Script: `/home/lochness/.claude/jobs/*/tmp/crc_gate_c6.py` (compare CRCs as ints). PASS = 0 imported-symbol drift + canaries OK: init_task=0xd567d551, module_layout=0xea759d7f, rfkill_alloc=0x6a3675f4, cfg80211_connect_done=0x6699ba8e, register_netdevice=0xb4bdff70. "Absent from C6" symbols are fine if provided by a peer stock module (lh-laptop confirmed 553/553 resolve inter-module). Run TWO independent gates (build server + lh-laptop) before flash.

## Package + flash + verify
- `python3 tools/mkbootimg/mkbootimg.py --header_version 4 --os_version 14.0.0 --os_patch_level 2024-08 --kernel dist/Image --output out/boot-op12-docker-c6-<sha>.img` (kernel-only v4, same params as booting stockA; do NOT hand-roll a custom magic header — Helios OP12 brick).
- lh-laptop pulls (scp, pw before5), verifies sha, stages GOLDEN, `fastboot flash boot_a`, reboot.
- VERIFY ON-DEVICE (not boot-alone): wlan0 up + WiFi connect, `ping 8.8.8.8`, `dmesg | grep -iE "Unknown symbol|disagrees about version|failed to load"` must be clean, /proc/1/ns has ipc+pid, then a rootful container. GOLDEN restore = `fastboot flash boot_a GOLDEN_boot_a_OP-Wild.img` if bootloop.

## Pass 2 (todo): container networking incrementally (NF_TABLES/NF_NAT/IP_NF_MASQUERADE/VXLAN/IP_VS/BRIDGE_NETFILTER) re-gating each batch; USER_NS for rootless (needs cred kABI-padding). Validate full set with moby contrib/check-config.sh.
