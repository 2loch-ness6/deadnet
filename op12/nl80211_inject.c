// nl80211_inject.c — minimal nl80211 management-frame injector (raw netlink, no libnl)
//
// Purpose: probe the WCN7850 (kiwi) mgmt-TX ceiling. Sends NL80211_CMD_FRAME with a
// caller-supplied raw 802.11 management frame on a given interface + frequency, then
// prints the kernel's reply (ACK, or the TX cookie / error). Pair with a sniffer to see
// what actually hits the air and whether firmware rewrote seq/addr/etc.
//
// Build (host):
//   $NDK/.../aarch64-linux-android31-clang -O2 -static-libgcc nl80211_inject.c -o nl80211_inject
//   (glibc host/container: cc -O2 -Wall nl80211_inject.c -o nl80211_inject)
// Run (device, as root, SELinux permissive):
//   ./nl80211_inject [--fast] [--wait N] <ifname> <freq_mhz> [hexframe]
//   e.g.  ./nl80211_inject wlan0 5745
//         ./nl80211_inject wlan0 5745 d000...<hex>...
//         ./nl80211_inject --fast wlan0 5745 <hex>   (fire-and-forget, no TXSTATUS wait)
//         ./nl80211_inject --wait 5 wlan0 5745 <hex> (wait up to 5s for TXSTATUS)
//
// --stdio: persistent-socket daemon. Opens netlink ONCE, then serves one frame per
// stdin line and answers on stdout. Removes the fork+exec+socket-setup cost that
// otherwise dominates paced floods (the scheduler's per-frame overhead).
//   ./nl80211_inject --stdio [--fast] [--wait N] <ifname>
//   request line:  [fast |full ]FREQ [HEX]     (HEX empty = default frame;
//                                               fast|full overrides the default mode)
//   reply line:    OK cookie=0x... ack=yes|no   (status waited)
//                  OK cookie=0x... fast          (--fast, no status wait)
//                  OK ack                        (synchronous ACK, no cookie)
//                  ERR bad|rejected|local|truncated ...
// Blank lines are ignored; EOF exits 0. Diagnostics go to stderr (stdout is pure
// protocol). One malformed line never kills the daemon.
//
// ROC (remain-on-channel), env-gated so default behaviour is unchanged:
//   ROC=1          park the radio on the target freq (NL80211_CMD_REMAIN_ON_CHANNEL)
//                  before transmitting. This is REQUIRED for an UNASSOCIATED
//                  interface to actually radiate: without a channel context the
//                  firmware fakes acceptance (a canned, repeating cookie + fake
//                  ACK) and drops the frame. With ROC the cookie is a real,
//                  sequential TX handle and the frame hits the air.
//   ROC_MS=<ms>    ROC duration per arm (100..10000, default 5000). In --stdio the
//                  ROC is re-armed automatically before it lapses and on any
//                  channel change, and cancelled on clean exit.
// OFFCHANNEL_TX_OK is set automatically whenever ROC is active (the TX is
// off-channel relative to the — absent — operating channel).
//
// KIWI/WCN7850 FINDING (2026-10-16, A/B-measured against an owned ESP32 AP +
// associated victim): this driver implements remain-on-channel via its SCAN
// engine. cfg80211 returns a ROC cookie synchronously (looks like success), but
// the firmware then rejects the underlying off-channel scan —
//   kiwi_v2: [E:OSIF] wlan_is_scan_allowed: Simultaneous scan disabled, reject scan
// — so the radio never reliably parks. A 12s ROC deauth flood from an
// UNASSOCIATED phone moved the victim's ping loss only 0-5%, vs 77% from the
// SAME frame when the phone was ASSOCIATED (real channel context). `iw set
// channel` on the managed iface likewise returns EBUSY. Conclusion: on this
// chip, reliable mgmt-TX needs channel context via ASSOCIATION; ROC here is a
// no-op for injection. The code is retained (gated, harmless) for other chips /
// future firmware where scan-based ROC isn't gated this way.
//
// Default frame = vendor-specific action (category 0x7f) with a locally-administered,
// spoofed source and broadcast DA, carrying the ASCII tag "INJECTTEST" so you can grep
// for it in a capture. Harmless: no peer state machine reacts to a vendor-specific action.
//
// Output contract, single-shot mode (parsers depend on these; keep substrings stable):
//   "no such iface %s" | "bad hexframe" | "bad freq" |
//   "RESULT: ACK (accepted)" | "RESULT: accepted for TX, cookie reply" |
//   "RESULT: error %d (%s)" | "TXSTATUS: ... ACK=yes|no"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define BUFSZ 8192

static int nl_fd = -1;
static unsigned int nl_seq = 0;
static int mlme_mcast_grp = -1;   // id of nl80211 "mlme" multicast group (FRAME_TX_STATUS)

// Remain-on-channel (ROC) config, set from env in main() (ROC=1, ROC_MS=<ms>).
// ROC parks the radio on the target channel so an UNASSOCIATED interface gains a
// channel context; without it the firmware fakes acceptance (canned cookie) and
// the frame never radiates. See do_roc().
static int g_roc_mode = 0;
static unsigned g_roc_ms = 2000;  // duration per ROC arm (ms); WCN7850 caps this at 2000.
                                  // A new ROC cannot overlap an active one (EBUSY), so we
                                  // re-arm only after the current window lapses.
#define ROC_MS_MAX 2000u

// --- tiny netlink attribute helpers (all lengths NLA/NLMSG aligned) ---
// Returns 0 on success, -1 if the attribute would overflow the buffer.
static int add_attr(struct nlmsghdr *nlh, int maxlen, int type,
                    const void *data, int len) {
    int alen = NLA_HDRLEN + len;
    int off = NLMSG_ALIGN(nlh->nlmsg_len);
    if (len < 0 || off + NLA_ALIGN(alen) > maxlen)
        return -1;
    struct nlattr *na = (struct nlattr *)((char *)nlh + off);
    na->nla_type = type;
    na->nla_len = alen;
    if (len) memcpy((char *)na + NLA_HDRLEN, data, len);
    nlh->nlmsg_len = off + NLA_ALIGN(alen);
    return 0;
}

// True iff na points at a complete attribute inside `remaining` bytes.
// All netlink attribute walks in this tool must use this — a short or corrupt
// kernel reply must never send the parser walking off the buffer.
static int nla_ok(const struct nlattr *na, int remaining) {
    if (remaining < (int)NLA_HDRLEN)
        return 0;
    if (na->nla_len < NLA_HDRLEN)
        return 0;
    if ((int)na->nla_len > remaining)
        return 0;
    return 1;
}

// recv() that retries on EINTR (a caught signal must not look like a dead kernel).
static ssize_t xrecv(char *buf, size_t len) {
    ssize_t r;
    do {
        r = recv(nl_fd, buf, len, 0);
    } while (r < 0 && errno == EINTR);
    return r;
}

// True iff rh is a complete netlink header inside a datagram of rlen bytes.
static int hdr_ok(const struct nlmsghdr *rh, ssize_t rlen) {
    if (rlen < (ssize_t)NLMSG_HDRLEN)
        return 0;
    if (rh->nlmsg_len < NLMSG_HDRLEN)
        return 0;
    if (rh->nlmsg_len > (unsigned)rlen)
        return 0;
    return 1;
}

static void usage(const char *prog) {
    printf("usage: %s [--fast] [--wait SECS] <ifname> <freq_mhz> [hexframe]\n"
           "       %s --stdio [--fast] [--wait SECS] <ifname>  (one frame per stdin line)\n"
           "  --fast     exit on the TX ACK, do NOT wait for FRAME_TX_STATUS\n"
           "  --wait N   wait up to N seconds for TXSTATUS (default 2, 1..60)\n"
           "  --stdio    persistent socket: request 'FREQ [HEX]' per line,\n"
           "             reply 'OK ...' / 'ERR ...' per line (see source header)\n"
           "  hexframe   even-length hex (spaces/colons ok); default = harmless\n"
           "             vendor-action frame tagged INJECTTEST\n", prog, prog);
}

// Harmless default probe frame (vendor action, spoofed SA, bcast DA, INJECTTEST tag).
static int default_frame(unsigned char *out) {
    static const unsigned char def[] = {
        0xd0, 0x00,                         // FC: mgmt / action
        0x00, 0x00,                         // duration
        0xff,0xff,0xff,0xff,0xff,0xff,       // addr1 DA = broadcast
        0x02,0x11,0x22,0x33,0x44,0x55,       // addr2 SA = spoofed (locally administered)
        0x02,0x11,0x22,0x33,0x44,0x55,       // addr3 BSSID = spoofed
        0x00, 0x00,                         // seq ctrl (fw expected to set)
        0x7f,                               // action category = vendor specific
        0xde,0xad,0xbe,                     // fake OUI
        'I','N','J','E','C','T','T','E','S','T'
    };
    memcpy(out, def, sizeof(def));
    return (int)sizeof(def);
}

// Resolve a generic-netlink family id by name (e.g. "nl80211") via the genl controller.
static int resolve_family(const char *name) {
    char buf[BUFSZ];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++nl_seq;
    nlh->nlmsg_pid = (unsigned)getpid();
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = CTRL_CMD_GETFAMILY;
    gnlh->version = 1;
    if (add_attr(nlh, BUFSZ, CTRL_ATTR_FAMILY_NAME, name, (int)strlen(name) + 1) < 0) {
        fprintf(stderr, "getfamily: request too large\n");
        return -1;
    }

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) != (ssize_t)nlh->nlmsg_len) {
        perror("send getfamily");
        return -1;
    }

    ssize_t rlen = xrecv(buf, sizeof(buf));
    if (rlen < 0) { perror("recv getfamily"); return -1; }

    struct nlmsghdr *rh = (struct nlmsghdr *)buf;
    if (!hdr_ok(rh, rlen)) { fprintf(stderr, "getfamily: short/truncated reply\n"); return -1; }
    if (rh->nlmsg_type == NLMSG_ERROR) {
        if (rlen < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            fprintf(stderr, "getfamily: short error reply\n");
            return -1;
        }
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
        fprintf(stderr, "getfamily: kernel error %d (%s)\n",
                e->error, e->error ? strerror(-e->error) : "ACK");
        return -1;
    }
    if (rlen < (ssize_t)NLMSG_LENGTH(GENL_HDRLEN)) {
        fprintf(stderr, "getfamily: short genl reply\n");
        return -1;
    }

    struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(rh) + GENL_HDRLEN);
    int alen = (int)rh->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
    int famid = -1;
    while (nla_ok(na, alen)) {
        if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
            if (na->nla_len == NLA_HDRLEN + 2)
                famid = *(uint16_t *)((char *)na + NLA_HDRLEN);
        } else if (na->nla_type == CTRL_ATTR_MCAST_GROUPS) {
            // nested array of groups; each a nested {GRP_NAME, GRP_ID}
            struct nlattr *grp = (struct nlattr *)((char *)na + NLA_HDRLEN);
            int glen = (int)na->nla_len - (int)NLA_HDRLEN;
            while (nla_ok(grp, glen)) {
                struct nlattr *p = (struct nlattr *)((char *)grp + NLA_HDRLEN);
                int plen = (int)grp->nla_len - (int)NLA_HDRLEN;
                const char *gname = NULL; int gid = -1;
                while (nla_ok(p, plen)) {
                    if (p->nla_type == CTRL_ATTR_MCAST_GRP_NAME)
                        gname = (const char *)p + NLA_HDRLEN;
                    else if (p->nla_type == CTRL_ATTR_MCAST_GRP_ID) {
                        if (p->nla_len == NLA_HDRLEN + 4)
                            gid = (int)*(uint32_t *)((char *)p + NLA_HDRLEN);
                    }
                    int ps = NLA_ALIGN(p->nla_len);
                    plen -= ps; p = (struct nlattr *)((char *)p + ps);
                }
                if (gname && !strcmp(gname, "mlme")) mlme_mcast_grp = gid;
                int gs = NLA_ALIGN(grp->nla_len);
                glen -= gs; grp = (struct nlattr *)((char *)grp + gs);
            }
        }
        int step = NLA_ALIGN(na->nla_len);
        alen -= step;
        na = (struct nlattr *)((char *)na + step);
    }
    if (famid < 0) fprintf(stderr, "family id not found\n");
    return famid;
}

// Open + bind + resolve + join mlme. Banner to stdout (cli) or stderr (stdio).
// Returns 0 ok (fills *ifindex_out, *fam_out), -1 on failure (fd closed).
static int nl_setup(const char *ifname, unsigned *ifindex_out, int *fam_out, int banner_stdout) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "no such iface %s\n", ifname); return -1; }

    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_fd < 0) { perror("socket"); return -1; }
    struct sockaddr_nl local = {0};
    local.nl_family = AF_NETLINK;
    if (bind(nl_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        close(nl_fd); nl_fd = -1;
        return -1;
    }

    int fam = resolve_family("nl80211");
    if (fam < 0) { close(nl_fd); nl_fd = -1; return -1; }

    // Join the "mlme" multicast group so we receive NL80211_CMD_FRAME_TX_STATUS.
    if (mlme_mcast_grp >= 0) {
        if (setsockopt(nl_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                       &mlme_mcast_grp, sizeof(mlme_mcast_grp)) < 0)
            perror("add mlme membership");
    } else {
        fprintf(stderr, "warning: mlme mcast group not found; TX status may not arrive\n");
    }

    *ifindex_out = ifindex;
    *fam_out = fam;
    if (banner_stdout)
        printf("nl80211 family id = %d, ifindex(%s) = %u\n", fam, ifname, ifindex);
    else
        fprintf(stderr, "stdio ready: family id = %d, ifindex(%s) = %u\n", fam, ifname, ifindex);
    return 0;
}

static int hex2bin(const char *hex, unsigned char *out, int outmax) {
    int n = 0;
    while (hex[0] && hex[1]) {
        if (hex[0] == ' ' || hex[0] == ':') { hex++; continue; }
        if (n >= outmax) return -1;
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1) return -1;
        out[n++] = (unsigned char)v;
        hex += 2;
    }
    return n;
}

enum txr { TX_ACCEPTED_ACK, TX_ACCEPTED_COOKIE, TX_REJECTED, TX_LOCALERR, TX_TRUNCATED };
struct txres {
    enum txr kind;
    int err;                       // kernel errno (TX_REJECTED) or errno (TX_LOCALERR)
    unsigned long long cookie;     // TX_ACCEPTED_COOKIE
    int acked;                     // FRAME_TX_STATUS ACK flag (0/1), valid if got_status
    int got_status;                // 1 if a TXSTATUS event arrived (fast=0 only)
};

// Transmit one frame and (unless fast) wait up to wait_secs for FRAME_TX_STATUS.
// Prints nothing except warnings to stderr; the caller formats the result.
static struct txres do_tx(int fam, unsigned ifindex, unsigned freq,
                          const unsigned char *frame, int flen,
                          int fast, long wait_secs) {
    struct txres r;
    memset(&r, 0, sizeof(r));
    char buf[BUFSZ];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = fam;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++nl_seq;
    nlh->nlmsg_pid = (unsigned)getpid();
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = NL80211_CMD_FRAME;
    gnlh->version = 0;

    if (add_attr(nlh, BUFSZ, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex)) < 0 ||
        add_attr(nlh, BUFSZ, NL80211_ATTR_WIPHY_FREQ, &freq, sizeof(freq)) < 0 ||
        add_attr(nlh, BUFSZ, NL80211_ATTR_FRAME, frame, flen) < 0) {
        r.kind = TX_LOCALERR; r.err = E2BIG;
        return r;
    }
    // Request off-channel TX if asked (env OFFCHAN=1) or whenever ROC is active:
    // with a live remain-on-channel, an unassociated iface has no "operating"
    // channel, so the driver treats the TX as off-channel and expects this flag.
    const char *offchan = getenv("OFFCHAN");
    if ((offchan && atoi(offchan)) || g_roc_mode) {
        if (add_attr(nlh, BUFSZ, NL80211_ATTR_OFFCHANNEL_TX_OK, NULL, 0) < 0) {
            r.kind = TX_LOCALERR; r.err = E2BIG;
            return r;
        }
    }

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) != (ssize_t)nlh->nlmsg_len) {
        r.kind = TX_LOCALERR; r.err = errno;
        return r;
    }

    // 1st recv: synchronous reply (cookie) or NLMSG_ERROR.
    ssize_t rlen = xrecv(buf, sizeof(buf));
    if (rlen < 0) { r.kind = TX_LOCALERR; r.err = errno; return r; }
    struct nlmsghdr *rh = (struct nlmsghdr *)buf;
    if (!hdr_ok(rh, rlen)) { r.kind = TX_TRUNCATED; return r; }
    if (rh->nlmsg_type == NLMSG_ERROR) {
        if (rlen < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            r.kind = TX_TRUNCATED;
            return r;
        }
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
        if (e->error == 0) { r.kind = TX_ACCEPTED_ACK; }
        else { r.kind = TX_REJECTED; r.err = e->error; }
        return r;
    }
    // Cookie reply: pull the u64 TX cookie when present (lets logs correlate
    // this acceptance with its later FRAME_TX_STATUS).
    if (rh->nlmsg_len >= NLMSG_LENGTH(GENL_HDRLEN)) {
        struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(rh) + GENL_HDRLEN);
        int alen = (int)rh->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
        while (nla_ok(na, alen)) {
            if (na->nla_type == NL80211_ATTR_COOKIE &&
                na->nla_len == NLA_HDRLEN + 8)
                memcpy(&r.cookie, (char *)na + NLA_HDRLEN, 8);
            int step = NLA_ALIGN(na->nla_len);
            alen -= step;
            na = (struct nlattr *)((char *)na + step);
        }
    }
    r.kind = TX_ACCEPTED_COOKIE;

    if (fast)
        return r;

    // 2nd phase: wait up to wait_secs for NL80211_CMD_FRAME_TX_STATUS
    // (the on-air / ACK signal).
    struct timeval tv = { .tv_sec = (time_t)wait_secs, .tv_usec = 0 };
    setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        rlen = xrecv(buf, sizeof(buf));
        if (rlen < 0)
            return r;   // accepted, but no status event (caller reports timeout)
        struct nlmsghdr *h = (struct nlmsghdr *)buf;
        if (!hdr_ok(h, rlen))
            continue;                            // truncated datagram: ignore
        if (h->nlmsg_type != fam) continue;      // not an nl80211 event
        if (rlen < (ssize_t)NLMSG_LENGTH(GENL_HDRLEN))
            continue;
        struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(h);
        if (g->cmd != NL80211_CMD_FRAME_TX_STATUS) continue;
        // scan attrs for NL80211_ATTR_ACK (flag => acked by peer)
        struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(h) + GENL_HDRLEN);
        int alen = (int)h->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
        while (nla_ok(na, alen)) {
            if (na->nla_type == NL80211_ATTR_ACK) r.acked = 1;
            int step = NLA_ALIGN(na->nla_len);
            alen -= step;
            na = (struct nlattr *)((char *)na + step);
        }
        r.got_status = 1;
        return r;
    }
}

static long long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Drain any queued multicast events (FRAME_TX_STATUS, ROC ready/expired) and
// stale replies so the next synchronous reply read is unambiguous. Non-blocking.
static void nl_drain(void) {
    char tmp[BUFSZ];
    while (recv(nl_fd, tmp, sizeof(tmp), MSG_DONTWAIT) >= 0)
        ;   // discard until EAGAIN/EWOULDBLOCK
}

// Park the radio on `freq` for duration_ms via NL80211_CMD_REMAIN_ON_CHANNEL.
// This gives an UNASSOCIATED station a channel context, which is the missing
// ingredient for mgmt-TX to actually radiate off the operating channel. The
// socket is also joined to the mlme mcast group, so command replies are
// demultiplexed from async events by matching nlmsg_seq. Returns 0 (fills
// *cookie_out when present) on success, -1 on error (errno set).
static int do_roc(int fam, unsigned ifindex, unsigned freq, unsigned duration_ms,
                  unsigned long long *cookie_out) {
    nl_drain();
    char buf[BUFSZ];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = fam;
    nlh->nlmsg_flags = NLM_F_REQUEST;   // no ACK: exactly one reply (cookie) or NLMSG_ERROR
    unsigned myseq = ++nl_seq;
    nlh->nlmsg_seq = myseq;
    nlh->nlmsg_pid = (unsigned)getpid();
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = NL80211_CMD_REMAIN_ON_CHANNEL;
    gnlh->version = 0;
    if (add_attr(nlh, BUFSZ, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex)) < 0 ||
        add_attr(nlh, BUFSZ, NL80211_ATTR_WIPHY_FREQ, &freq, sizeof(freq)) < 0 ||
        add_attr(nlh, BUFSZ, NL80211_ATTR_DURATION, &duration_ms, sizeof(duration_ms)) < 0) {
        errno = E2BIG;
        return -1;
    }
    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) != (ssize_t)nlh->nlmsg_len)
        return -1;

    // Bounded, time-limited read for our reply; skip async events (other seq).
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int rc = -1;
    for (int i = 0; i < 8192; i++) {
        ssize_t rlen = xrecv(buf, sizeof(buf));
        if (rlen < 0) { rc = -1; break; }        // timeout/error (errno set)
        struct nlmsghdr *rh = (struct nlmsghdr *)buf;
        if (!hdr_ok(rh, rlen)) continue;
        if (rh->nlmsg_seq != myseq) continue;    // async mcast event or other reply
        if (rh->nlmsg_type == NLMSG_ERROR) {
            if (rlen < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) { errno = EBADMSG; rc = -1; break; }
            struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
            if (e->error == 0) { rc = 0; break; } // bare ACK, no cookie
            errno = -e->error; rc = -1; break;
        }
        if (cookie_out && rh->nlmsg_len >= NLMSG_LENGTH(GENL_HDRLEN)) {
            struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(rh) + GENL_HDRLEN);
            int alen = (int)rh->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);
            while (nla_ok(na, alen)) {
                if (na->nla_type == NL80211_ATTR_COOKIE && na->nla_len == NLA_HDRLEN + 8)
                    memcpy(cookie_out, (char *)na + NLA_HDRLEN, 8);
                int step = NLA_ALIGN(na->nla_len);
                alen -= step;
                na = (struct nlattr *)((char *)na + step);
            }
        }
        rc = 0;
        break;
    }
    // Restore blocking behaviour for the proven do_tx fast path.
    struct timeval z = { .tv_sec = 0, .tv_usec = 0 };
    setsockopt(nl_fd, SOL_SOCKET, SO_RCVTIMEO, &z, sizeof(z));
    return rc;
}

// Best-effort release of an active ROC (NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL).
// Does not wait for a reply — the radio also frees the channel when the ROC
// duration lapses, so this just returns it sooner on clean exit.
static void do_cancel_roc(int fam, unsigned ifindex, unsigned long long cookie) {
    char buf[BUFSZ];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = fam;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++nl_seq;
    nlh->nlmsg_pid = (unsigned)getpid();
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    gnlh->cmd = NL80211_CMD_CANCEL_REMAIN_ON_CHANNEL;
    gnlh->version = 0;
    if (add_attr(nlh, BUFSZ, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex)) < 0 ||
        add_attr(nlh, BUFSZ, NL80211_ATTR_COOKIE, &cookie, sizeof(cookie)) < 0)
        return;
    (void)send(nl_fd, nlh, nlh->nlmsg_len, 0);
}

static unsigned parse_freq(const char *s, int *ok) {
    char *ep = NULL;
    // NOTE: 0 passes through (kernel answers EINVAL — the surface matrix
    // depends on that); only non-numeric / absurd values are rejected.
    unsigned long f = strtoul(s, &ep, 10);
    if (!ep || ep == s || *ep || f > 20000) { *ok = 0; return 0; }
    *ok = 1;
    return (unsigned)f;
}

// --stdio servant: one "FREQ [HEX]" (or "[fast|full ]FREQ [HEX]") per stdin
// line, one "OK ..."/"ERR ..." per stdout line. Never dies on a bad line.
static int stdio_loop(const char *ifname, int dflt_fast, long wait_secs) {
    unsigned ifindex = 0;
    int fam = 0;
    if (nl_setup(ifname, &ifindex, &fam, 0) < 0)
        return 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    // ROC state: keep the radio parked on the freq we're injecting on, re-arming
    // before the current window lapses. On a channel change we re-arm immediately.
    unsigned roc_freq = 0;
    long long roc_deadline_ms = 0;
    unsigned long long roc_cookie = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, stdin)) >= 0) {
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
            line[--n] = 0;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p)
            continue;   // blank line: ignore (keeps the stream in sync)
        int ffast = dflt_fast;
        if (!strncmp(p, "fast ", 5)) { ffast = 1; p += 5; }
        else if (!strncmp(p, "full ", 5)) { ffast = 0; p += 5; }
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) { printf("ERR bad line\n"); continue; }
        char *ep = NULL;
        unsigned long f = strtoul(p, &ep, 10);
        if (ep == p || f > 20000) { printf("ERR bad freq\n"); continue; }
        // collect hex nibbles (separators skipped); empty = default frame
        static char hex[2 * 1600 + 1024];
        int hl = 0;
        for (char *q = ep; *q && hl < (int)sizeof(hex) - 1; q++) {
            if (*q == ' ' || *q == '\t' || *q == ':' || *q == '\n' || *q == '\r')
                continue;
            hex[hl++] = *q;
        }
        hex[hl] = 0;
        unsigned char frame[1600];
        int flen;
        if (hl == 0) {
            flen = default_frame(frame);
        } else {
            flen = hex2bin(hex, frame, (int)sizeof(frame));
            if (flen < 0) { printf("ERR bad hexframe\n"); continue; }
        }
        // Ensure a live remain-on-channel on this freq before transmitting, so an
        // unassociated interface actually radiates. A ROC cannot overlap an active
        // one (EBUSY), so we re-arm only once the current window has lapsed (or on
        // a channel change). EBUSY means the kernel's ROC outlives our clock — still
        // covered, just check again shortly. A genuine failure is throttled so a
        // persistent error can never storm the log or spin the loop.
        if (g_roc_mode) {
            long long t = now_ms();
            if ((unsigned)f != roc_freq || t >= roc_deadline_ms) {
                unsigned long long c = roc_cookie;
                int rr = do_roc(fam, ifindex, (unsigned)f, g_roc_ms, &c);
                if (rr == 0) {
                    roc_freq = (unsigned)f;
                    roc_cookie = c;
                    roc_deadline_ms = t + (long long)g_roc_ms;
                    usleep(15000);   // let the radio settle on-channel after a (re)arm
                } else if (errno == EBUSY) {
                    roc_freq = (unsigned)f;
                    roc_deadline_ms = t + 150;   // still on-channel; recheck soon
                } else {
                    roc_freq = (unsigned)f;
                    roc_deadline_ms = t + 500;   // throttle a real failure
                    fprintf(stderr, "roc arm failed on %u MHz: %s\n",
                            (unsigned)f, strerror(errno));
                }
            }
        }
        struct txres r = do_tx(fam, ifindex, (unsigned)f, frame, flen, ffast, wait_secs);
        switch (r.kind) {
        case TX_ACCEPTED_ACK:
            printf("OK ack\n");
            break;
        case TX_ACCEPTED_COOKIE:
            if (ffast)
                printf("OK cookie=0x%llx fast\n", r.cookie);
            else if (r.got_status)
                printf("OK cookie=0x%llx ack=%s\n", r.cookie, r.acked ? "yes" : "no");
            else
                printf("OK cookie=0x%llx no-status\n", r.cookie);
            break;
        case TX_REJECTED:
            printf("ERR rejected e%d (%s)\n", r.err, strerror(-r.err));
            break;
        case TX_TRUNCATED:
            printf("ERR truncated reply\n");
            break;
        default:
            printf("ERR local %s\n", strerror(r.err));
            break;
        }
    }
    free(line);
    if (g_roc_mode && roc_freq)
        do_cancel_roc(fam, ifindex, roc_cookie);   // release the channel on clean exit
    close(nl_fd);
    nl_fd = -1;
    return 0;
}

int main(int argc, char **argv) {
    // --fast: fire-and-forget — exit on the TX ACK, do NOT wait for
    // FRAME_TX_STATUS. Used by nuke mode for sustained-rate floods where
    // the 40ms status wait would cap actual pps at ~25.
    int fast = 0, stdio = 0;
    long wait_secs = 2;
    while (argc > 1) {
        if (!strcmp(argv[1], "--fast")) {
            fast = 1;
        } else if (!strcmp(argv[1], "--stdio")) {
            stdio = 1;
        } else if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[1], "--wait")) {
            if (argc < 3) { fprintf(stderr, "--wait needs a seconds value\n"); return 2; }
            char *ep = NULL;
            long w = strtol(argv[2], &ep, 10);
            if (!ep || *ep || w < 1 || w > 60) {
                fprintf(stderr, "bad --wait value '%s' (1..60)\n", argv[2]);
                return 2;
            }
            wait_secs = w;
            argc--; argv++;
        } else {
            break;
        }
        argc--; argv++;
    }
    const char *ifname = argc > 1 ? argv[1] : "wlan0";

    // ROC config (shared by both --stdio and single-shot paths).
    const char *roc_env = getenv("ROC");
    g_roc_mode = (roc_env && atoi(roc_env)) ? 1 : 0;
    const char *roc_ms_env = getenv("ROC_MS");
    if (roc_ms_env) {
        int v = atoi(roc_ms_env);
        if (v >= 100 && v <= (int)ROC_MS_MAX) g_roc_ms = (unsigned)v;
    }

    if (stdio)
        return stdio_loop(ifname, fast, wait_secs);

    unsigned freq = 5745;
    if (argc > 2) {
        int ok = 0;
        freq = parse_freq(argv[2], &ok);
        if (!ok) {
            fprintf(stderr, "bad freq '%s'\n", argv[2]);
            return 2;
        }
    }

    // Default probe frame: vendor-specific action, spoofed SA, broadcast DA, tag "INJECTTEST".
    unsigned char frame[1600];
    int flen;
    if (argc > 3) {
        flen = hex2bin(argv[3], frame, (int)sizeof(frame));
        if (flen < 0) { fprintf(stderr, "bad hexframe\n"); return 2; }
    } else {
        flen = default_frame(frame);
    }

    unsigned ifindex = 0;
    int fam = 0;
    // NOTE: banner keeps the legacy one-line shape ("nl80211 family id = ...,
    // freq = ..., frame_len = ...") — parsers only grep the RESULT/TXSTATUS lines.
    if (nl_setup(ifname, &ifindex, &fam, 1) < 0)
        return (nl_fd == -1 && ifindex == 0) ? 2 : 1;
    printf(", freq = %u, frame_len = %d\n", freq, flen);

    unsigned long long roc_cookie = 0;
    if (g_roc_mode) {
        if (do_roc(fam, ifindex, freq, g_roc_ms, &roc_cookie) < 0) {
            fprintf(stderr, "ROC arm failed on %u MHz: %s\n", freq, strerror(errno));
        } else {
            printf("ROC: parked on %u MHz for %u ms (cookie=0x%llx)\n",
                   freq, g_roc_ms, roc_cookie);
            usleep(15000);   // settle on-channel before the TX
        }
    }

    struct txres r = do_tx(fam, ifindex, freq, frame, flen, fast, wait_secs);
    int rc = 0;
    switch (r.kind) {
    case TX_ACCEPTED_ACK:
        printf("RESULT: ACK (accepted)\n");
        break;
    case TX_ACCEPTED_COOKIE:
        if (r.cookie)
            printf("RESULT: accepted for TX, cookie reply (cookie=0x%llx)\n", r.cookie);
        else
            printf("RESULT: accepted for TX, cookie reply\n");
        break;
    case TX_REJECTED:
        printf("RESULT: error %d (%s) — rejected before firmware\n",
               r.err, strerror(-r.err));
        break;
    case TX_TRUNCATED:
        fprintf(stderr, "RESULT: short/truncated reply — rejected before firmware\n");
        break;
    default:
        perror("send frame");
        rc = 1;
        break;
    }
    if (r.kind == TX_ACCEPTED_ACK || r.kind == TX_ACCEPTED_COOKIE) {
        if (fast) {
            printf("TXSTATUS: --fast (skipped)\n");
        } else if (r.got_status) {
            printf("TXSTATUS: FRAME_TX_STATUS received — firmware transmitted the frame; ACK=%s\n",
                   r.acked ? "yes (peer acknowledged)" : "no (expected for broadcast/no-peer)");
        } else {
            printf("TXSTATUS: none within %lds (no status event delivered)\n", wait_secs);
        }
    }
    if (g_roc_mode && roc_cookie)
        do_cancel_roc(fam, ifindex, roc_cookie);
    close(nl_fd);
    return rc;
}
