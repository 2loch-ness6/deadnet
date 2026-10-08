// lpc_ctl.c — start/stop qcacld Local Packet Capture via QCA vendor command
// SET_MONITOR_MODE (subcmd 202). Sends to a monitor-type interface (e.g. mon0).
//
//   ./lpc_ctl <mon_ifname> start   # MGMT/DATA/CTRL tx+rx = ALL
//   ./lpc_ctl <mon_ifname> stop    # empty config = stop
//
// QCA_NL80211_VENDOR_ID=0x1374, subcmd=202. Frame-type attrs 1..6, value BIT(0)=ALL.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define BUFSZ 4096
#define QCA_VENDOR_ID 0x1374
#define QCA_SUBCMD_SET_MONITOR_MODE 202

static int nl_fd;
static unsigned int nl_seq = 0;

static void add_attr(struct nlmsghdr *nlh, int type, const void *data, int len) {
    struct nlattr *na = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    int alen = NLA_HDRLEN + len;
    na->nla_type = type;
    na->nla_len = alen;
    if (len) memcpy((char *)na + NLA_HDRLEN, data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(alen);
}

// begin a nested attr, return ptr to patch length later
static struct nlattr *nest_start(struct nlmsghdr *nlh, int type) {
    struct nlattr *na = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    na->nla_type = type | NLA_F_NESTED;
    na->nla_len = NLA_HDRLEN;  // patched in nest_end
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;
    return na;
}
static void nest_end(struct nlmsghdr *nlh, struct nlattr *na) {
    na->nla_len = (char *)nlh + nlh->nlmsg_len - (char *)na;
}

static int resolve_family(const char *name) {
    char buf[BUFSZ]; memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++nl_seq; nlh->nlmsg_pid = getpid();
    struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(nlh);
    g->cmd = CTRL_CMD_GETFAMILY; g->version = 1;
    add_attr(nlh, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) { perror("send"); return -1; }
    int rlen = recv(nl_fd, buf, sizeof(buf), 0);
    if (rlen < 0) { perror("recv"); return -1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)buf;
    if (rh->nlmsg_type == NLMSG_ERROR) return -1;
    struct nlattr *na = (struct nlattr *)((char *)NLMSG_DATA(rh) + GENL_HDRLEN);
    int alen = rh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
    while (alen > 0) {
        if (na->nla_type == CTRL_ATTR_FAMILY_ID)
            return *(uint16_t *)((char *)na + NLA_HDRLEN);
        int step = NLA_ALIGN(na->nla_len); alen -= step;
        na = (struct nlattr *)((char *)na + step);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <mon_ifname> start|stop\n", argv[0]); return 2; }
    const char *ifname = argv[1];
    int start = !strcmp(argv[2], "start");

    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) { fprintf(stderr, "no iface %s\n", ifname); return 2; }

    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (nl_fd < 0) { perror("socket"); return 1; }
    struct sockaddr_nl local = {0}; local.nl_family = AF_NETLINK;
    if (bind(nl_fd, (struct sockaddr *)&local, sizeof(local)) < 0) { perror("bind"); return 1; }

    int fam = resolve_family("nl80211");
    if (fam < 0) { fprintf(stderr, "no nl80211 family\n"); return 1; }

    char buf[BUFSZ]; memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = fam;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++nl_seq; nlh->nlmsg_pid = getpid();
    struct genlmsghdr *g = (struct genlmsghdr *)NLMSG_DATA(nlh);
    g->cmd = NL80211_CMD_VENDOR; g->version = 0;

    uint32_t vid = QCA_VENDOR_ID, sub = QCA_SUBCMD_SET_MONITOR_MODE;
    add_attr(nlh, NL80211_ATTR_IFINDEX, &ifindex, sizeof(ifindex));
    add_attr(nlh, NL80211_ATTR_VENDOR_ID, &vid, sizeof(vid));
    add_attr(nlh, NL80211_ATTR_VENDOR_SUBCMD, &sub, sizeof(sub));

    struct nlattr *vdata = nest_start(nlh, NL80211_ATTR_VENDOR_DATA);
    if (start) {
        uint32_t all = 1; // BIT(0) = *_FRAME_TYPE_ALL
        for (int attr = 1; attr <= 6; attr++)   // DATA_TX,DATA_RX,MGMT_TX,MGMT_RX,CTRL_TX,CTRL_RX
            add_attr(nlh, attr, &all, sizeof(all));
    }
    // stop = empty vendor data (no frame-type attrs set)
    nest_end(nlh, vdata);

    if (send(nl_fd, nlh, nlh->nlmsg_len, 0) < 0) { perror("send vendor"); return 1; }
    int rlen = recv(nl_fd, buf, sizeof(buf), 0);
    if (rlen < 0) { perror("recv"); return 1; }
    struct nlmsghdr *rh = (struct nlmsghdr *)buf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(rh);
        if (e->error == 0) printf("LPC %s: OK (ACK)\n", start ? "start" : "stop");
        else printf("LPC %s: error %d (%s)\n", start ? "start" : "stop",
                    e->error, strerror(-e->error));
    } else {
        printf("LPC %s: reply type %d len %d\n", start ? "start" : "stop", rh->nlmsg_type, rlen);
    }
    close(nl_fd);
    return 0;
}
