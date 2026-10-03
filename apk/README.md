# Deadnet APK
<p align="center"><img src="https://github.com/user-attachments/assets/c85eccf8-bbf8-4904-9327-9e1c2e064eea" width="450" ></p>

A simple Android app that runs Deadnet directly on Android devices. </br> </br>

The APK is stored inside [bin](https://github.com/flashnuke/deadnet/tree/main/apk/bin) directory, but can be built manually as well.
</br>The attack is written in C++ and compiled into native binaries that are run explicitly by the Python app (see the `Notes.Permissions` section for more). </br>

# Requirements
* Device must be rooted.
* Most modern devices are ARM64. The native binaries are compiled for the following machine architecture types: (ARM, ARM64, x86, x86_64), see the building section in order to compile for a different architecture type.

# Usage
* Grant permissions.
* Use the buttons - `Start`, `Stop` and `Refresh` (to refresh the current wifi connection info).
* In case of an error, use the `Debug Logs` button to fetch the logs, and feel free to open a new [issue](https://github.com/flashnuke/deadnet/issues) with the debug logs included.

### Live survival gauges
While an attack is running, three live gauges show whether it is actually working, updated ~2x/second from a passive
sniffer (`sniff.cpp`) that reads **only** Ethernet/IP/ARP header metadata on the interface - never packet payloads:

* **ARP Tx** (left) - rate of ARP poison frames we are transmitting (our output).
* **SURVIVING** (centre) - rate of packets still flowing to/from the *real* gateway MAC from other hosts. When this
  drops to **0 p/s** the gauge reads **`DeadNet CONFIRMED`** - nothing is getting through. Any non-zero reading means
  traffic (e.g. HTTPS/TLS on port 443) is still leaking past the attack.
* **ARP Rx + evidence** (right) - ARP chatter we receive plus frames other hosts are sending to dead/spoofed MACs,
  i.e. evidence their ARP caches are poisoned the way we want.

> **Note on Wi-Fi visibility:** on an encrypted managed Wi-Fi network a client cannot see other stations' unicast
> frames (each station has its own pairwise key), so the SURVIVING gauge mainly reflects broadcast/multicast and
> gateway-visible traffic. It is most accurate on open networks, hotspots, or wired links. The ARP gauges always work.

### Permissions
* Some parts were compiled into native binaries due to a lack of permissions that restrict the Python interpreter from directly creating raw sockets, even when running as root.
* `ACCESS_FINE_LOCATION` permission is required in order to access SSID data (i.e. wifi network name).

# Building manually
Steps to build the app manually. </br>
The following tools are required:
* NDK tools (to build the `.cpp` binaries)
* Buildozer (to build the APK)

### Cloning the library
```bash
# clone the project
git clone https://github.com/flashnuke/deadnet.git
```

### Compiling the C++ Binaries
The C++ binaries source code files (`src/arp.cpp` for the ARP poisoning and `src/nra.cpp` for the dead router attack) should be compiled by NDK:
```bash
cd /tmp  # DO NOT CLONE NDK INTO THE PROJECT DIRECTORY! it will mess with the build process
mkdir android-ndk && cd android-ndk
wget https://dl.google.com/android/repository/android-ndk-r26d-linux.zip
unzip android-ndk-r26d-linux.zip
export NDK_PATH=$(pwd)/android-ndk-r26d # NDK_PATH example: "NDK_PATH=/tmp/my-android-toolchain"

# compile binaries
cd <path_to_deadnet_root>/apk
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -static -o assets/nra.arm64 src/nra.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi29-clang++ -static -o assets/nra.arm src/nra.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android29-clang++ -static -o assets/nra.x86 src/nra.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang++ -static -o assets/nra.x86_64 src/nra.cpp

$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -static -o assets/arp.arm64 src/arp.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi29-clang++ -static -o assets/arp.arm src/arp.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android29-clang++ -static -o assets/arp.x86 src/arp.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang++ -static -o assets/arp.x86_64 src/arp.cpp

$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ -static -O2 -o assets/sniff.arm64 src/sniff.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi29-clang++ -static -O2 -o assets/sniff.arm src/sniff.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android29-clang++ -static -O2 -o assets/sniff.x86 src/sniff.cpp
$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang++ -static -O2 -o assets/sniff.x86_64 src/sniff.cpp
```

The compiled binaries will be stored under `./assets`.

### Building the APK
```bash
# navigate to the apk directory
cd <path_to_deadnet_root>/apk

# make sure you have python 3.10 installed
python3.10 --version
python3.10 -m venv venv
source venv/bin/activate

# install buildozer - refer to ths official for more https://buildozer.readthedocs.io/en/latest/installation.html

# build the apk 
buildozer android debug # build in debug mode
```
The compiled APK will be stored under `./bin`.

# Debugging
### Debug Logs
Quick debugging can be done using the `Debug Logs` button, which will display useful logs. </br>
### ADB logcat
If a more thorough debug process is needed, `adb` is the right for that. </br>
Connecting the device to ADB and running `adb logcat` would show all the logs, which can be filtered further by using `adb logcat | grep -E 'python|DeadNet'`.

# Disclaimer

This tool is only for testing and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. I assume no liability and am not responsible for any misuse or damage caused by this tool and software.

Distributed under the GNU License.
