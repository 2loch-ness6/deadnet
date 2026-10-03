#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>

//   --------------------------------------------------------------------------------------------------------------------
//   DeadNet survival monitor
//   --------------------------------------------------------------------------------------------------------------------
//   Passive AF_PACKET sniffer. Reads ONLY Ethernet/IP/ARP header metadata (never payload) and, once per interval,
//   prints a single counter line to stdout. The Python layer turns these into the three live gauges:
//
//     ARP_TX  -> ARP frames whose source MAC is ours              (our poison output rate)
//     SURV    -> IP frames to/from the REAL gateway MAC, where the other endpoint is NOT us
//                (i.e. OTHER hosts still reaching the gateway -> traffic "surviving" the attack; 0 == DeadNet CONFIRMED)
//     ARP_RX  -> ARP frames NOT sourced by us                     (ARP chatter on the link)
//     EVID    -> IP frames sent to a bogus locally-administered (dead) unicast MAC that is not us
//                (poisoned victims transmitting into the void -> evidence their ARP cache is set the way we want)
//
//   Output line (one per interval, space separated, newline terminated, flushed):
//     TS=<epoch_ms> ARP_TX=<n> ARP_RX=<n> SURV=<n> SURV_BYTES=<n> EVID=<n> TOTAL=<n>
//   --------------------------------------------------------------------------------------------------------------------

#define SNAP_LEN 64  // we only need L2/L3 headers, never payload

static volatile sig_atomic_t g_run = 1;

static void on_signal(int sig) {
    (void)sig;
    g_run = 0;
}

// parse "aa:bb:cc:dd:ee:ff" into 6 bytes
static int parse_mac(const char *str, unsigned char *bytes) {
    int vals[6];
    if (6 == sscanf(str, "%x:%x:%x:%x:%x:%x",
                    &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5])) {
        for (int i = 0; i < 6; i++) bytes[i] = (unsigned char)vals[i];
        return 0;
    }
    return -1;
}

static int mac_eq(const unsigned char *a, const unsigned char *b) {
    return memcmp(a, b, ETH_ALEN) == 0;
}

static int is_multicast(const unsigned char *mac) {
    return (mac[0] & 0x01) != 0;  // group bit (covers broadcast too)
}

static int is_locally_administered(const unsigned char *mac) {
    return (mac[0] & 0x02) != 0;  // LAA bit -> the spoofed/dead MACs we flood
}

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

int main(int argc, char *argv[]) {
    // args: <iface> <gateway_mac> <our_mac> <interval_ms>
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <gateway_mac> <our_mac> <interval_ms>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    unsigned char gw_mac[6], our_mac[6];
    if (parse_mac(argv[2], gw_mac) || parse_mac(argv[3], our_mac)) {
        fprintf(stderr, "bad MAC argument\n");
        return EXIT_FAILURE;
    }
    long interval_ms = atol(argv[4]);
    if (interval_ms <= 0) interval_ms = 500;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int ifindex = if_nametoindex(iface);
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return EXIT_FAILURE;
    }

    // bind to the interface so we only see its frames
    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return EXIT_FAILURE;
    }

    // best-effort promiscuous mode so we can observe frames not addressed to us
    // (on managed Wi-Fi the AP may still withhold other stations' unicast; that is expected)
    struct packet_mreq mr = {0};
    mr.mr_ifindex = ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    unsigned long arp_tx = 0, arp_rx = 0, surv = 0, surv_bytes = 0, evid = 0, total = 0;
    long long next_emit = now_ms() + interval_ms;
    unsigned char buf[SNAP_LEN];

    while (g_run) {
        struct pollfd pfd = { sock, POLLIN, 0 };
        int pr = poll(&pfd, 1, (int)interval_ms);
        if (pr < 0) {
            if (g_run) continue;  // interrupted by signal
            break;
        }

        if (pr > 0 && (pfd.revents & POLLIN)) {
            // drain everything currently queued
            for (;;) {
                ssize_t n = recv(sock, buf, sizeof(buf), MSG_TRUNC | MSG_DONTWAIT);
                if (n < 0) break;
                if (n < (ssize_t)sizeof(struct ether_header)) continue;

                struct ether_header *eh = (struct ether_header *)buf;
                const unsigned char *dst = eh->ether_dhost;
                const unsigned char *src = eh->ether_shost;
                unsigned short etype = ntohs(eh->ether_type);

                total++;

                if (etype == ETHERTYPE_ARP) {
                    if (mac_eq(src, our_mac)) arp_tx++;
                    else                      arp_rx++;
                } else if (etype == ETHERTYPE_IP || etype == ETHERTYPE_IPV6) {
                    int to_gw   = mac_eq(dst, gw_mac);
                    int from_gw = mac_eq(src, gw_mac);
                    int involves_us = mac_eq(dst, our_mac) || mac_eq(src, our_mac);

                    // another host still talking to the real gateway -> traffic survived the attack
                    if ((to_gw || from_gw) && !involves_us) {
                        surv++;
                        surv_bytes += (unsigned long)n;  // MSG_TRUNC gives true on-wire length
                    }
                    // poisoned victim shipping frames to a dead/spoofed unicast MAC
                    else if (!is_multicast(dst) && is_locally_administered(dst)
                             && !mac_eq(dst, our_mac) && !mac_eq(src, our_mac)) {
                        evid++;
                    }
                }
            }
        }

        long long t = now_ms();
        if (t >= next_emit) {
            printf("TS=%lld ARP_TX=%lu ARP_RX=%lu SURV=%lu SURV_BYTES=%lu EVID=%lu TOTAL=%lu\n",
                   t, arp_tx, arp_rx, surv, surv_bytes, evid, total);
            fflush(stdout);
            arp_tx = arp_rx = surv = surv_bytes = evid = total = 0;
            next_emit = t + interval_ms;
        }
    }

    setsockopt(sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mr, sizeof(mr));
    close(sock);
    return EXIT_SUCCESS;
}
