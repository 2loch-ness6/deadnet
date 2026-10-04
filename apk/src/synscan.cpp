// ====================================================================================================================
//  DeadNet native TCP SYN scanner  (synscan.cpp)
// --------------------------------------------------------------------------------------------------------------------
//  Single-target raw-socket TCP SYN scanner for the multi-card redesign's P2 (fingerprint) phase. Android's Python
//  can't open raw sockets without native help, so this does the work and the Python layer (engine/portscan.py) fans
//  out one process per target and parses the result lines.
//
//  argv:  <iface> <target_ip> <ports_csv> <timeout_ms>
//      iface      egress interface (SO_BINDTODEVICE); also the source-IP lookup key (getifaddrs).
//      target_ip  single IPv4 target (dotted quad).
//      ports_csv  comma-separated port list, e.g. "22,80,443,8080".
//      timeout_ms how long to wait for replies AFTER the last SYN is sent.
//
//  Method: one raw IPv4 socket (IPPROTO_TCP, IP_HDRINCL) both forges SYN packets and receives the replies. Source IP
//  is the iface's primary IPv4 (getifaddrs); source port is randomized once per run; each port gets a hand-built IP +
//  TCP header with a proper TCP checksum over the pseudo-header. We then listen: a SYN/ACK => open, a RST => closed.
//  Ports that never answer within the timeout are simply omitted (filtered) -- the Python side treats absence as such.
//
//  Output (one line per responsive port, flushed immediately):
//      PORT=<n> STATE=open
//      PORT=<n> STATE=closed
//
//  SIGINT/SIGTERM -> clean exit. Self-contained in the style of sniff.cpp (no STL, plain C arrays).
//
// --------------------------------------------------------------------------------------------------------------------
//  BUILD (NDK r26d, Android 29, static, stripped) -- run from apk/ :
//    LLVM=/srv/deadnet-build/ndk/android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin
//    $LLVM/aarch64-linux-android29-clang++    -O2 -static -s src/synscan.cpp -o assets/synscan.arm64
//    $LLVM/armv7a-linux-androideabi29-clang++ -O2 -static -s src/synscan.cpp -o assets/synscan.arm
//    $LLVM/i686-linux-android29-clang++       -O2 -static -s src/synscan.cpp -o assets/synscan.x86
//    $LLVM/x86_64-linux-android29-clang++     -O2 -static -s src/synscan.cpp -o assets/synscan.x86_64
// ====================================================================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

// TCP flag bits (avoid relying on any particular tcphdr layout)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10

static volatile sig_atomic_t g_run = 1;
static void on_signal(int sig) { (void)sig; g_run = 0; }

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

#pragma pack(push, 1)
// Minimal IPv4 header (20 bytes, no options).
struct ip4_hdr {
    uint8_t  ihl_version;   // low nibble = IHL (words), high nibble = version
    uint8_t  tos;
    uint16_t tot_len;       // network order
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
// Minimal TCP header (20 bytes, no options).
struct tcp_hdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  data_off;      // high nibble = data offset in 32-bit words
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
// Pseudo-header for the TCP checksum.
struct tcp_pseudo {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;       // network order
};
#pragma pack(pop)

// Standard Internet 16-bit one's-complement checksum.
static uint16_t cksum16(const void *data, size_t len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// Look up the iface's primary IPv4 address (network order). Returns 0 on success.
static int iface_ipv4(const char *iface, uint32_t *out_be) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return -1;
    int rc = -1;
    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(p->ifa_name, iface) != 0) continue;
        *out_be = ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
        rc = 0;
        break;
    }
    freeifaddrs(ifa);
    return rc;
}

int main(int argc, char *argv[]) {
    // args: <iface> <target_ip> <ports_csv> <timeout_ms>
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <target_ip> <ports_csv> <timeout_ms>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface    = argv[1];
    const char *target_s = argv[2];
    const char *ports_s  = argv[3];
    long timeout_ms = atol(argv[4]);
    if (timeout_ms <= 0) timeout_ms = 800;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct in_addr target_in;
    if (inet_pton(AF_INET, target_s, &target_in) != 1) {
        fprintf(stderr, "bad target_ip: %s\n", target_s);
        return EXIT_FAILURE;
    }
    uint32_t target_be = target_in.s_addr;

    uint32_t src_be = 0;
    if (iface_ipv4(iface, &src_be) != 0) {
        fprintf(stderr, "no IPv4 address on iface %s\n", iface);
        return EXIT_FAILURE;
    }

    // Parse the port CSV into a scanned-port bitmap and an ordered list (for the send loop).
    static uint8_t scanned[65536];
    static uint8_t reported[65536];
    static uint16_t port_list[65536];
    int n_ports = 0;
    {
        // strtok mutates its input; work on a copy.
        char *csv = strdup(ports_s);
        if (!csv) { fprintf(stderr, "oom\n"); return EXIT_FAILURE; }
        for (char *tok = strtok(csv, ","); tok; tok = strtok(NULL, ",")) {
            while (*tok == ' ') tok++;
            long v = atol(tok);
            if (v <= 0 || v > 65535) continue;
            if (scanned[v]) continue;        // de-dupe
            scanned[v] = 1;
            port_list[n_ports++] = (uint16_t)v;
        }
        free(csv);
    }
    if (n_ports == 0) {
        fprintf(stderr, "no valid ports in: %s\n", ports_s);
        return EXIT_FAILURE;
    }

    // One raw TCP socket: forge (IP_HDRINCL) and receive replies.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("socket"); return EXIT_FAILURE; }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL");
        close(sock);
        return EXIT_FAILURE;
    }
    // Pin egress/ingress to the requested interface (matches the iface source-IP lookup above).
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, (socklen_t)(strlen(iface) + 1));

    // Randomize source port + initial sequence once per run.
    srand((unsigned)(now_ms() ^ (getpid() << 16)));
    uint16_t sport = (uint16_t)(1024 + (rand() % 64000));
    uint16_t sport_be = htons(sport);
    uint32_t base_seq = ((uint32_t)rand() << 16) ^ (uint32_t)rand();

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = target_be;

    // Send a SYN to every requested port.
    for (int i = 0; i < n_ports && g_run; i++) {
        uint16_t port = port_list[i];

        unsigned char pkt[sizeof(struct ip4_hdr) + sizeof(struct tcp_hdr)];
        memset(pkt, 0, sizeof(pkt));
        struct ip4_hdr *ip  = (struct ip4_hdr *)pkt;
        struct tcp_hdr *tcp = (struct tcp_hdr *)(pkt + sizeof(struct ip4_hdr));

        ip->ihl_version = (4 << 4) | 5;
        ip->tos         = 0;
        ip->tot_len     = htons((uint16_t)sizeof(pkt));
        ip->id          = htons((uint16_t)(base_seq + i));
        ip->frag_off    = 0;
        ip->ttl         = 64;
        ip->protocol    = IPPROTO_TCP;
        ip->check       = 0;
        ip->saddr       = src_be;
        ip->daddr       = target_be;
        ip->check       = cksum16(ip, sizeof(struct ip4_hdr));

        tcp->source   = sport_be;
        tcp->dest     = htons(port);
        tcp->seq      = htonl(base_seq + (uint32_t)port);
        tcp->ack_seq  = 0;
        tcp->data_off = (5 << 4);          // 20-byte header, no options
        tcp->flags    = TH_SYN;
        tcp->window   = htons(1024);
        tcp->check    = 0;
        tcp->urg_ptr  = 0;

        // TCP checksum over pseudo-header + TCP header.
        unsigned char cbuf[sizeof(struct tcp_pseudo) + sizeof(struct tcp_hdr)];
        struct tcp_pseudo ph;
        ph.saddr    = src_be;
        ph.daddr    = target_be;
        ph.zero     = 0;
        ph.protocol = IPPROTO_TCP;
        ph.tcp_len  = htons((uint16_t)sizeof(struct tcp_hdr));
        memcpy(cbuf, &ph, sizeof(ph));
        memcpy(cbuf + sizeof(ph), tcp, sizeof(struct tcp_hdr));
        tcp->check = cksum16(cbuf, sizeof(cbuf));

        (void)sendto(sock, pkt, sizeof(pkt), 0, (struct sockaddr *)&dst, sizeof(dst));
    }

    // Collect replies until the timeout expires or every scanned port has answered.
    int remaining = n_ports;
    long long deadline = now_ms() + timeout_ms;
    unsigned char rbuf[1500];

    while (g_run && remaining > 0) {
        long long t = now_ms();
        if (t >= deadline) break;
        int wait = (int)(deadline - t);

        struct pollfd pfd = { sock, POLLIN, 0 };
        int pr = poll(&pfd, 1, wait);
        if (pr < 0) {
            if (errno == EINTR) continue;   // signal; g_run re-checked at loop top
            break;
        }
        if (pr == 0) break;                 // timed out
        if (!(pfd.revents & POLLIN)) continue;

        // Drain everything currently queued.
        for (;;) {
            ssize_t n = recv(sock, rbuf, sizeof(rbuf), MSG_DONTWAIT);
            if (n < 0) break;
            if (n < (ssize_t)sizeof(struct ip4_hdr)) continue;

            struct ip4_hdr *ip = (struct ip4_hdr *)rbuf;
            if (ip->protocol != IPPROTO_TCP) continue;
            if (ip->saddr != target_be || ip->daddr != src_be) continue;   // not our target<->us

            int ihl = (ip->ihl_version & 0x0F) * 4;
            if (ihl < (int)sizeof(struct ip4_hdr)) continue;
            if (n < (ssize_t)(ihl + (int)sizeof(struct tcp_hdr))) continue;

            struct tcp_hdr *tcp = (struct tcp_hdr *)(rbuf + ihl);
            if (tcp->dest != sport_be) continue;         // not addressed to our scan source port

            uint16_t port = ntohs(tcp->source);
            if (!scanned[port] || reported[port]) continue;

            const char *state = NULL;
            if (tcp->flags & TH_RST) {
                state = "closed";
            } else if ((tcp->flags & TH_SYN) && (tcp->flags & TH_ACK)) {
                state = "open";
            }
            if (!state) continue;

            reported[port] = 1;
            remaining--;
            printf("PORT=%u STATE=%s\n", (unsigned)port, state);
            fflush(stdout);

            if (remaining <= 0) break;
        }
    }

    close(sock);
    return EXIT_SUCCESS;
}
