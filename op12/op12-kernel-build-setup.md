---
name: op12-kernel-build-setup
description: How/where the OnePlus 12 kernel is cloned and built on the Debian build server
metadata: 
  node_type: memory
  type: project
  originSessionId: 9ae18892-4b0b-4c44-9654-4b5dad3f5faa
  modified: 2026-09-16T01:13:22.764Z
---

OnePlus 12 kernel is built on the Debian x86 box **statick-dev** (session "kernal-build-server"), NOT on-device.

- Build root: **`/srv/op12-kernel`** (root `/` is only 40G/91% full — always build under /srv, which has ~57G free).
- Source: OnePlusOSS official, repo-based. `repo` tool installed at `~/bin/repo`.
  - `repo init --depth=1 -u https://github.com/OnePlusOSS/kernel_manifest.git -b oneplus/sm8650 -m oneplus_12_u.xml`
  - Manifest letter = Android version: **`oneplus_12_u.xml` = Android 14** (u_14.0.0), `_v` = 15, `_b` = 16. Device is Android 14 → use **u**.
  - Layout: `kernel_platform/{common,msm-kernel}`, target `//msm-kernel:pineapple_gki_dist` (bazel/kleaf). OEM `build_with_bazel` flow works on x86 (bundled prebuilts/clang r487747c / clang-17); it only fails on-device/arm64.
- Toolchain: use the **tree's bundled AOSP clang r487747c (clang 17.0.x)** — matters for KMI CRC matching. Do NOT use Debian clang.
- Host deps installed: git curl python-is-python3 bc bison flex libssl-dev libelf-dev build-essential libncurses-dev zip unzip rsync ccache cpio kmod. Passwordless sudo available.
- Peer sessions in this effort: **oneplus12** (device agent, has assets at /home/kali/docker-kernel-work/), **lh-laptop** (adb/flashing host, holds GOLDEN_boot backup, pulls artifacts via scp). Build-server tailnet IP 100.103.68.52, sshd on :22.

See [[op12-device-facts]] and [[op12-docker-cfi-lto-invariant]].
