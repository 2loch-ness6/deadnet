---
name: op12-device-facts
description: OnePlus 12 (CPH2581) hardware/firmware facts for kernel builds
metadata: 
  node_type: memory
  type: project
  originSessionId: 9ae18892-4b0b-4c44-9654-4b5dad3f5faa
  modified: 2026-09-16T01:13:00.283Z
---

Target device for kernel builds is a **OnePlus 12, model CPH2581** (global/EU, region "ossi", product device OP595DL1).

- Codename **waffle**; SoC **SM8650**, QCOM build-target platform name **pineapple** (NOT "waffle" as the build target).
- Firmware **CPH2581_14.0.0.840 (EX01)**, **Android 14**, GKI **android14-6.1**, kernel base **6.1.57**. Active slot **_a** (boot_a = /dev/block/sde13).
- Bootloader is **UNLOCKED** (verifiedbootstate=orange). getprop shows locked/green but that is **Magisk prop-spoofing** (playintegrityfix/tricky_store); ground truth is `/proc/bootconfig` which resetprop cannot fake. So NO AVB/signing blocker — unsigned custom boot images boot fine.
- Root is **Magisk** (patches init_boot, independent of the kernel/boot image). Do NOT integrate KernelSU/SUSFS — user wants a plain kernel.
- `boot` partition is **KERNEL-ONLY, header v4, ramdisk_size=0**. Ramdisk lives in init_boot_a / vendor_boot_a. Package a build by swapping the built `Image` into a GOLDEN stock boot.img via `mkbootimg --header_version 4`.
- **`fastboot boot <img>` is a NO-OP** on this device — cannot test transiently. Must `fastboot flash boot` / dd to slot _a, keep GOLDEN backup for bootloop recovery.
- Stock GKI KMI vermagic (336 vendor_dlkm modules): `6.1.57-android14-11-g41519d41cdba SMP preempt mod_unload modversions aarch64`.

See [[op12-kernel-build-setup]] and [[op12-docker-cfi-lto-invariant]].
