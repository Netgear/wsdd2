// gcc -Wall -Wextra -g -O0 -DMAIN -o nl_debug nl_debug.c && ./nl_debug
//#define _POSIX_C_SOURCE 200809

#include <stdio.h> // printf()
#include <stdarg.h> // va_start(), ...
#include <unistd.h> // close()
#include <string.h> // memset()
#include <ctype.h> // isprint()
#include <errno.h> // errno

//#include <fcntl.h> // F_GETFL
//#include <time.h> // time()
//#include <netdb.h> // getnameinfo()
//#include <net/if.h> // if_indextoname()
//#include <linux/if.h> // IFF_UP, ...

#include <sys/socket.h> // PF_NETLINK
#include <netinet/in.h> // in6_addr, INET6_ADDRSTRLEN
#include <arpa/inet.h> // inet_ntop()

#include <linux/netlink.h> // NETLINK_ROUTE
#include <linux/rtnetlink.h> // RTM_GETADDR, IFA_ADDRESS, /usr/include/linux/if_addr.h

#ifdef MAIN
#define debugf(...) do { printf(__VA_ARGS__); putchar('\n'); } while (0)
#else
#include "wsdd.h"
#define debugf(...) LOG(LOG_DEBUG, "nl_debug: " __VA_ARGS__)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static char outbuf[4096];
static int outlen = 0;

static void outf(const char *fmt, ... ) __attribute__((format(printf, 1, 2)));

void outf(const char *fmt, ...)
{
    char mbuf[1024], *lf;
    int mbuflen;
    va_list list;

    va_start(list, fmt);
    mbuflen = vsnprintf(mbuf, sizeof(mbuf), fmt, list);
    va_end(list);

    strncat(outbuf + outlen, mbuf, mbuflen);
    lf = strchr(outbuf + outlen, '\n');
    outlen += mbuflen;

    while (lf != NULL) {
        *lf = '\0';
        debugf("%s", outbuf);
        strcpy(outbuf, lf + 1);
        outlen -= lf - outbuf + 1;
        lf = strchr(outbuf, '\n');
    }
}

static void dump(void *p, size_t len, unsigned long start, const char *prefix)
{
    unsigned char *s = p;
    for (size_t i = 0; i < len; i += 16) {
        size_t j, blen = len - i > 16 ? 16 : len - i;
        outf("%s[%08lx]", prefix, start + i);
        for (j = 0; j < blen; j++) outf(" %02x", s[i+j]);
        for (; j < 16; j++) outf("   ");
        outf(" |");
        for (j = 0; j < blen; j++) outf("%c", isprint(s[i+j]) ? s[i+j] : '.');
        for (; j < 16; j++) outf(" ");
        outf("|\n");
    }
}

static const char nlmsg_type_str[][16] = {
    [NLMSG_NOOP]              = "NOOP",   /* Nothing       */
    [NLMSG_ERROR]             = "ERROR",  /* Error         */
    [NLMSG_DONE]              = "DONE",   /* End of a dump */
    [NLMSG_OVERRUN]           = "OVERRUN",/* Data lost     */
    [RTM_NEWLINK]             = "NEWLINK",
    [RTM_DELLINK]             = "DELLINK",
    [RTM_GETLINK]             = "GETLINK",
    [RTM_SETLINK]             = "SETLINK",
    [RTM_NEWADDR]             = "NEWADDR",
    [RTM_DELADDR]             = "DELADDR",
    [RTM_GETADDR]             = "GETADDR",
    [RTM_NEWROUTE]            = "NEWROUTE",
    [RTM_DELROUTE]            = "DELROUTE",
    [RTM_GETROUTE]            = "GETROUTE",
    [RTM_NEWNEIGH]            = "NEWNEIGH",
    [RTM_DELNEIGH]            = "DELNEIGH",
    [RTM_GETNEIGH]            = "GETNEIGH",
    [RTM_NEWRULE]             = "NEWRULE",
    [RTM_DELRULE]             = "DELRULE",
    [RTM_GETRULE]             = "GETRULE",
    [RTM_NEWQDISC]            = "NEWQDISC",
    [RTM_DELQDISC]            = "DELQDISC",
    [RTM_GETQDISC]            = "GETQDISC",
    [RTM_NEWTCLASS]           = "NEWTCLASS",
    [RTM_DELTCLASS]           = "DELTCLASS",
    [RTM_GETTCLASS]           = "GETTCLASS",
    [RTM_NEWTFILTER]          = "NEWTFILTER",
    [RTM_DELTFILTER]          = "DELTFILTER",
    [RTM_GETTFILTER]          = "GETTFILTER",
    [RTM_NEWACTION]           = "NEWACTION",
    [RTM_DELACTION]           = "DELACTION",
    [RTM_GETACTION]           = "GETACTION",
    [RTM_NEWPREFIX]           = "NEWPREFIX",
    [RTM_GETMULTICAST]        = "GETMULTICAST",
    [RTM_GETANYCAST]          = "GETANYCAST",
    [RTM_NEWNEIGHTBL]         = "NEWNEIGHTBL",
    [RTM_GETNEIGHTBL]         = "GETNEIGHTBL",
    [RTM_SETNEIGHTBL]         = "SETNEIGHTBL",
    [RTM_NEWNDUSEROPT]        = "NEWNDUSEROPT",
    [RTM_NEWADDRLABEL]        = "NEWADDRLABEL",
    [RTM_DELADDRLABEL]        = "DELADDRLABEL",
    [RTM_GETADDRLABEL]        = "GETADDRLABEL",
    [RTM_GETDCB]              = "GETDCB",
    [RTM_SETDCB]              = "SETDCB",
    [RTM_NEWNETCONF]          = "NEWNETCONF",
    [RTM_DELNETCONF]          = "DELNETCONF",
    [RTM_GETNETCONF]          = "GETNETCONF",
    [RTM_NEWMDB]              = "NEWMDB",
    [RTM_DELMDB]              = "DELMDB",
    [RTM_GETMDB]              = "GETMDB",
    [RTM_NEWNSID]             = "NEWNSID",
    [RTM_DELNSID]             = "DELNSID",
    [RTM_GETNSID]             = "GETNSID",
    [RTM_NEWSTATS]            = "NEWSTATS",
    [RTM_GETSTATS]            = "GETSTATS",
    [RTM_NEWCACHEREPORT]      = "NEWCACHEREPORT",
    [RTM_NEWCHAIN]            = "NEWCHAIN",
    [RTM_DELCHAIN]            = "DELCHAIN",
    [RTM_GETCHAIN]            = "GETCHAIN",
    [RTM_NEWNEXTHOP]          = "NEWNEXTHOP",
    [RTM_DELNEXTHOP]          = "DELNEXTHOP",
    [RTM_GETNEXTHOP]          = "GETNEXTHOP",
    [RTM_NEWLINKPROP]         = "NEWLINKPROP",
    [RTM_DELLINKPROP]         = "DELLINKPROP",
    [RTM_GETLINKPROP]         = "GETLINKPROP",
    [RTM_NEWNVLAN]            = "NEWVLAN",
    [RTM_DELVLAN]             = "DELVLAN",
    [RTM_GETVLAN]             = "GETVLAN",
};

static const char ifla_rta_type_str[][32] = {
    [IFLA_UNSPEC]            = "UNSPEC",
    [IFLA_ADDRESS]           = "ADDRESS",
    [IFLA_BROADCAST]         = "BROADCAST",
    [IFLA_IFNAME]            = "IFNAME",
    [IFLA_MTU]               = "MTU",
    [IFLA_LINK]              = "LINK",
    [IFLA_QDISC]             = "QDISC",
    [IFLA_STATS]             = "STATS",
    [IFLA_COST]              = "COST",
    [IFLA_PRIORITY]          = "PRIORITY",
    [IFLA_MASTER]            = "MASTER",
    [IFLA_WIRELESS]          = "WIRELESS",              /* Wireless Extension event - see wireless.h */
    [IFLA_PROTINFO]          = "PROTINFO",              /* Protocol specific information for a link */
    [IFLA_TXQLEN]            = "TXQLEN",
    [IFLA_MAP]               = "MAP",
    [IFLA_WEIGHT]            = "WEIGHT",
    [IFLA_OPERSTATE]         = "OPERSTATE",
    [IFLA_LINKMODE]          = "LINKMODE",
    [IFLA_LINKINFO]          = "LINKINFO",
    [IFLA_NET_NS_PID]        = "NET_NS_PID",
    [IFLA_IFALIAS]           = "IFALIAS",
    [IFLA_NUM_VF]            = "NUM_VF",                /* Number of VFs if device is SR-IOV PF */
    [IFLA_VFINFO_LIST]       = "VFINFO_LIST",
    [IFLA_STATS64]           = "STATS64",
    [IFLA_VF_PORTS]          = "VF_PORTS",
    [IFLA_PORT_SELF]         = "PORT_SELF",
    [IFLA_AF_SPEC]           = "AF_SPEC",
    [IFLA_GROUP]             = "GROUP",         /* Group the device belongs to */
    [IFLA_NET_NS_FD]         = "NET_NS_FD",
    [IFLA_EXT_MASK]          = "EXT_MASK",              /* Extended info mask, VFs, etc */
    [IFLA_PROMISCUITY]       = "PROMISCUITY",   /* Promiscuity count: > 0 means acts PROMISC */
    [IFLA_NUM_TX_QUEUES]     = "NUM_TX_QUEUES",
    [IFLA_NUM_RX_QUEUES]     = "NUM_RX_QUEUES",
    [IFLA_CARRIER]           = "CARRIER",
    [IFLA_PHYS_PORT_ID]      = "PHYS_PORT_ID",
    [IFLA_CARRIER_CHANGES]   = "CARRIER_CHANGES",
    [IFLA_PHYS_SWITCH_ID]    = "PHYS_SWITCH_ID",
    [IFLA_LINK_NETNSID]      = "LINK_NETNSID",
    [IFLA_PHYS_PORT_NAME]    = "PHYS_PORT_NAME",
    [IFLA_PROTO_DOWN]        = "PROTO_DOWN",
    [IFLA_GSO_MAX_SEGS]      = "GSO_MAX_SEGS",
    [IFLA_GSO_MAX_SIZE]      = "GSO_MAX_SIZE",
    [IFLA_PAD]               = "PAD",
    [IFLA_XDP]               = "XDP",
    [IFLA_EVENT]             = "EVENT",
    [IFLA_NEW_NETNSID]       = "NEW_NETNSID",
    [IFLA_TARGET_NETNSID]    = "TARGET_NETNSID",
    [IFLA_CARRIER_UP_COUNT]  = "CARRIER_UP_COUNT",
    [IFLA_CARRIER_DOWN_COUNT]= "CARRIER_DOWN_COUNT",
    [IFLA_NEW_IFINDEX]       = "NEW_IFINDEX",
    [IFLA_MIN_MTU]           = "MIN_MTU",
    [IFLA_MAX_MTU]           = "MAX_MTU",
    [IFLA_PROP_LIST]         = "PROP_LIST",
    [IFLA_ALT_IFNAME]        = "ALT_IFNAME", /* Alternative ifname */
    [IFLA_PERM_ADDRESS]      = "PERM_ADDRESS",
    [IFLA_PROTO_DOWN_REASON] = "PROTO_DOWN_REASON",
};

static const char ifa_rta_type_str[][16] = {
    [IFA_UNSPEC]             = "UNSPEC",
    [IFA_ADDRESS]            = "ADDRESS",
    [IFA_LOCAL]              = "LOCAL",
    [IFA_LABEL]              = "LABEL",
    [IFA_BROADCAST]          = "BROADCAST",
    [IFA_ANYCAST]            = "ANYCAST",
    [IFA_CACHEINFO]          = "CACHEINFO",
    [IFA_MULTICAST]          = "MULTICAST",
    [IFA_FLAGS]              = "FLAGS",
    [IFA_RT_PRIORITY]        = "RT_PRIORITY",  /* u32, priority/metric for prefix route */
    [IFA_TARGET_NETNSID]     = "TARGET_NETNSID",
};

static const char rtmsg_type_str[][16] = {
    [RTN_UNSPEC]             = "UNSPEC",
    [RTN_UNICAST]            = "UNICAST",       /* Gateway or direct route      */
    [RTN_LOCAL]              = "LOCAL",         /* Accept locally               */
    [RTN_BROADCAST]          = "BROADCAST",     /* Accept locally as broadcast, send as broadcast */
    [RTN_ANYCAST]            = "ANYCAST",       /* Accept locally as broadcast, but send as unicast */
    [RTN_MULTICAST]          = "MULTICAST",     /* Multicast route              */
    [RTN_BLACKHOLE]          = "BLACKHOLE",     /* Drop                         */
    [RTN_UNREACHABLE]        = "UNREACHABLE",   /* Destination is unreachable   */
    [RTN_PROHIBIT]           = "PROHIBIT",      /* Administratively prohibited  */
    [RTN_THROW]              = "THROW",         /* Not in this table            */
    [RTN_NAT]                = "NAT",           /* Translate this address       */
    [RTN_XRESOLVE]           = "XRESOLVE",      /* Use external resolver        */
};

static const char rtattr_type_str[][16] = {
    [RTA_UNSPEC]             = "UNSPEC",
    [RTA_DST]                = "DST",
    [RTA_SRC]                = "SRC",
    [RTA_IIF]                = "IIF",
    [RTA_OIF]                = "OIF",
    [RTA_GATEWAY]            = "GATEWAY",
    [RTA_PRIORITY]           = "PRIORITY",
    [RTA_PREFSRC]            = "PREFSRC",
    [RTA_METRICS]            = "METRICS",
    [RTA_MULTIPATH]          = "MULTIPATH",
    [RTA_PROTOINFO]          = "PROTOINFO", /* no longer used */
    [RTA_FLOW]               = "FLOW",
    [RTA_CACHEINFO]          = "CACHEINFO",
    [RTA_SESSION]            = "SESSION", /* no longer used */
    [RTA_MP_ALGO]            = "MP_ALGO", /* no longer used */
    [RTA_TABLE]              = "TABLE",
    [RTA_MARK]               = "MARK",
    [RTA_MFC_STATS]          = "MFC_STATS",
    [RTA_VIA]                = "VIA",
    [RTA_NEWDST]             = "NEWDST",
    [RTA_PREF]               = "PREF",
    [RTA_ENCAP_TYPE]         = "ENCAP_TYPE",
    [RTA_ENCAP]              = "ENCAP",
    [RTA_EXPIRES]            = "EXPIRES",
    [RTA_PAD]                = "PAD",
    [RTA_UID]                = "UID",
    [RTA_TTL_PROPAGATE]      = "TTL_PROPAGATE",
    [RTA_IP_PROTO]           = "IP_PROTO",
    [RTA_SPORT]              = "SPORT",
    [RTA_DPORT]              = "DPORT",
    [RTA_NH_ID]              = "NH_ID",
};

static struct {
    int flag;
    const char *name;
} ifa_flags_descr[] = {
    { IFA_F_SECONDARY,       "SECONDARY" },
    { IFA_F_NODAD,           "NODAD" },
    { IFA_F_OPTIMISTIC,      "OPTIMISTIC" },
    { IFA_F_DADFAILED,       "DADFAILED" },
    { IFA_F_HOMEADDRESS,     "HOMEADDRESS" },
    { IFA_F_DEPRECATED,      "DEPRECATED" },
    { IFA_F_TENTATIVE,       "TENTATIVE" },
    { IFA_F_PERMANENT,       "PERMANENT" },
    { IFA_F_MANAGETEMPADDR,  "MANAGETEMPADDR" },
    { IFA_F_NOPREFIXROUTE,   "NOPREFIXROUTE" },
    { IFA_F_MCAUTOJOIN,      "MCAUTOJOIN" },
    { IFA_F_STABLE_PRIVACY,  "STABLE_PRIVACY" },
    { 0, "" },
};

static void print_rta_addr(int family, const struct rtattr *rta)
{
    if (!family && RTA_PAYLOAD(rta) == 6)
        family = AF_PACKET;

    switch (family) {
    case AF_PACKET: {
        unsigned char *x = RTA_DATA(rta);
        outf(" %02x:%02x:%02x:%02x:%02x:%02x", x[0], x[1], x[2], x[3], x[4], x[5]);
        break;
    }
    case AF_INET:
    case AF_INET6: {
        char host[INET6_ADDRSTRLEN];
        outf(" %s", inet_ntop(family, RTA_DATA(rta), host, sizeof(host)));
        break;
    }
    default:
        outf(" AF_unexpected_family_%d\n", family);
        dump(RTA_DATA(rta), RTA_PAYLOAD(rta), 0, "\t");
        break;
    }
}

static void print_iff(int flags)
{
    outf(" ");
    if (!flags) {
        outf("-");
        return;
    }
    int first = 1;
    for (int i = 0; ifa_flags_descr[i].flag; i++) {
        if (flags & ifa_flags_descr[i].flag) {
            outf("%s%s", first ? "" : "|", ifa_flags_descr[i].name);
            first = 0;
        }
        flags &= ~ifa_flags_descr[i].flag;
    }
    if (flags) outf("|%#x", flags);
}

int nl_debug(void *buf, int len)
{
    if (len < 0) {
        outf("netlink_read: len=%d - %s\n", len, strerror(errno));
        return len;
    }
    if (len == 0) {
        outf("netlink_read: EOF\n");
        return -1;
    }
    if (len < NLMSG_HDRLEN) {
        outf("netlink_read: short read (%d)\n", len);
        return 0;
    }

    //dump(&buf, len, 0, "\t");

    for (struct nlmsghdr *nh = buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
        if (0) {
            outf("--- Netlink message %d bytes, flags %#x %s\n", nh->nlmsg_len, nh->nlmsg_flags & ~NLM_F_MULTI,
                (nh->nlmsg_flags & NLM_F_MULTI) ? "[multi]" : "");
        }

        if (nh->nlmsg_type == NLMSG_DONE) {
            //done = 1;
            break;

        } else if (nh->nlmsg_type == NLMSG_ERROR) {
            // struct nlmsgerr {
            //     int error;        /* Negative errno or 0 for acknowledgements */
            //     struct nlmsghdr msg;  /* Message header that caused the error */
            // };
            struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(nh);
            if (err->error == 0) {
                outf("(ACK)\n");
            } else {
                errno = -err->error;
                outf("netlink_read: %s, caused by nlmsghdr { type %s, len %u, flags %#x, seq %u, pid %u }\n",
                    strerror(errno),
                    nlmsg_type_str[err->msg.nlmsg_type], /* Type of message content */
                    err->msg.nlmsg_len, /* Length of message including header */
                    err->msg.nlmsg_flags, /* Additional flags */
                    err->msg.nlmsg_seq, /* Sequence number */
                    err->msg.nlmsg_pid /* Sender port ID */
                );
            }

        } else if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
            // struct ifinfomsg {
            //     unsigned char  ifi_family; /* AF_UNSPEC */
            //     unsigned short ifi_type;   /* Device type */
            //     int            ifi_index;  /* Interface index */
            //     unsigned int   ifi_flags;  /* Device flags  */
            //     unsigned int   ifi_change; /* change mask */
            // };
            struct ifinfomsg *ifm = (struct ifinfomsg *) NLMSG_DATA(nh);
            size_t rta_len = IFLA_PAYLOAD(nh); //NLMSG_PAYLOAD(nh, sizeof(*ifm));

            outf("%s interface ifindex %u, type %hu, family %d, flags %#x, change %#x,",
                nh->nlmsg_type == RTM_NEWLINK ? "+" : "-", ifm->ifi_index, ifm->ifi_type,
                ifm->ifi_family, ifm->ifi_flags, ifm->ifi_change);

            for (struct rtattr *rta = IFLA_RTA(ifm); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                outf(" %s", ifla_rta_type_str[rta->rta_type]);
                switch (rta->rta_type) {
                // not implemented
                case IFLA_UNSPEC:
                case IFLA_AF_SPEC:
                case IFLA_STATS64:
                case IFLA_STATS:
                case IFLA_MAP:
                case IFLA_XDP:
                case IFLA_LINKINFO:
                    outf(" -");
                    break;
                // mac
                case IFLA_ADDRESS:
                case IFLA_BROADCAST:
                case IFLA_PERM_ADDRESS:
                    print_rta_addr(ifm->ifi_family, rta);
                    break;
                // asciiz
                case IFLA_IFNAME:
                case IFLA_QDISC: {
                    const char *val = RTA_DATA(rta);
                    outf(" %s", val);
                    break;
                }
                // unsigned char
                case IFLA_OPERSTATE:
                case IFLA_LINKMODE:
                case IFLA_CARRIER:
                case IFLA_PROTO_DOWN: {
                    const unsigned char *val = RTA_DATA(rta);
                    outf(" %u", *val);
                    break;
                }
                // unsigned int
                case IFLA_TXQLEN:
                case IFLA_MTU:
                case IFLA_MIN_MTU:
                case IFLA_MAX_MTU:
                case IFLA_GROUP:
                case IFLA_PROMISCUITY:
                case IFLA_NUM_TX_QUEUES:
                case IFLA_GSO_MAX_SEGS:
                case IFLA_GSO_MAX_SIZE:
                case IFLA_NUM_RX_QUEUES:
                case IFLA_CARRIER_CHANGES:
                case IFLA_CARRIER_UP_COUNT:
                case IFLA_CARRIER_DOWN_COUNT: {
                    const unsigned *val = RTA_DATA(rta);
                    outf(" %u", *val);
                    break;
                }
                // int
                case IFLA_LINK: {
                    const int *val = RTA_DATA(rta);
                    outf(" %d", *val);
                    break;
                }
                default:
                    outf("\n");
                    dump(RTA_DATA(rta), RTA_PAYLOAD(rta), 0, "\t");
                    break;
                }
            }
            outf("\n");

        } else if (nh->nlmsg_type == RTM_NEWADDR || nh->nlmsg_type == RTM_DELADDR) {
            // struct ifaddrmsg {
            //     unsigned char ifa_family;    /* Address type */
            //     unsigned char ifa_prefixlen; /* Prefixlength of address */
            //     unsigned char ifa_flags;     /* Address flags */
            //     unsigned char ifa_scope;     /* Address scope */
            //     unsigned int  ifa_index;     /* Interface index */
            // };
            struct ifaddrmsg *ifm = (struct ifaddrmsg *) NLMSG_DATA(nh);
            size_t rta_len = IFA_PAYLOAD(nh); //NLMSG_PAYLOAD(nh, sizeof(*ifm));

            outf("%s address ifindex %d, family %d, prefix /%d, flags %x, scope %#x,",
                nh->nlmsg_type == RTM_NEWADDR ? "+" : "-", ifm->ifa_index, ifm->ifa_family,
                ifm->ifa_prefixlen, ifm->ifa_flags, ifm->ifa_scope);

            for (struct rtattr *rta = IFA_RTA(ifm); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                outf(" %s", ifa_rta_type_str[rta->rta_type]);
                switch (rta->rta_type) {
                // address
                case IFA_ADDRESS:
                case IFA_LOCAL:
                case IFA_BROADCAST:
                case IFA_ANYCAST:
                case IFA_MULTICAST:
                    print_rta_addr(ifm->ifa_family, rta);
                    break;
                // asciiz
                case IFA_LABEL: {
                    const char *ifname = RTA_DATA(rta);
                    outf(" %s", ifname);
                    break;
                }
                // ifa_cacheinfo
                case IFA_CACHEINFO: {
                    // struct ifa_cacheinfo {
                    //     __u32 ifa_prefered;
                    //     __u32 ifa_valid;
                    //     __u32 cstamp; // created timestamp, hundredths of seconds
                    //     __u32 tstamp; // updated timestamp, hundredths of seconds
                    // };
                    struct ifa_cacheinfo *ifci = RTA_DATA(rta);
                    outf(" prefered=%d,valid=%d,ct=%.2f,ut=%.2f",
                        ifci->ifa_prefered, ifci->ifa_valid,
                        ifci->cstamp/100.0, ifci->tstamp/100.0);
                    break;
                }
                // flags
                case IFA_FLAGS: {
                    int *pflags = RTA_DATA(rta), flags_len = RTA_PAYLOAD(rta);
                    if (flags_len == sizeof(int)) print_iff(*pflags);
                    break;
                }
                default:
                    //outf("IFA_0x%04x\n", rta->rta_type);
                    dump(RTA_DATA(rta), RTA_PAYLOAD(rta), 0, "\t");
                    break;
                }
            }
            outf("\n");

        } else if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
            // struct rtmsg {
            //     unsigned char rtm_family;
            //     unsigned char rtm_dst_len;
            //     unsigned char rtm_src_len;
            //     unsigned char rtm_tos;
            //     unsigned char rtm_table;     /* Routing table id */
            //     unsigned char rtm_protocol;  /* Routing protocol; see below  */
            //     unsigned char rtm_scope;     /* See below */
            //     unsigned char rtm_type;      /* See below    */
            //     unsigned      rtm_flags;
            // };
            struct rtmsg *ifm = (struct rtmsg *) NLMSG_DATA(nh);
            size_t rta_len = RTM_PAYLOAD(nh); //NLMSG_PAYLOAD(nh, sizeof(*ifm));

            outf("%s route %s, family %d, flags %#x, dst_len %u, src_len %u, tos %u, table %u, protocol %u, scope %u,",
                nh->nlmsg_type == RTM_NEWROUTE ? "+" : "-", rtmsg_type_str[ifm->rtm_type], ifm->rtm_family,
                ifm->rtm_flags, ifm->rtm_dst_len, ifm->rtm_src_len, ifm->rtm_tos,
                ifm->rtm_table, ifm->rtm_protocol, ifm->rtm_scope);

            for (struct rtattr *rta = RTM_RTA(ifm); RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                outf(" %s", rtattr_type_str[rta->rta_type]);
                switch (rta->rta_type) {
                // not implemented
                case RTA_UNSPEC:
                case RTA_CACHEINFO:
                    outf(" -");
                    break;
                // address
                case RTA_DST:
                case RTA_SRC:
                case RTA_GATEWAY:
                case RTA_PREFSRC:
                case RTA_NEWDST:
                    print_rta_addr(ifm->rtm_family, rta);
                    break;
                // unsigned char
                case RTA_PREF: {
                    const unsigned char *val = RTA_DATA(rta);
                    outf(" %u", *val);
                    break;
                }
                // unsigned short
                case RTA_ENCAP_TYPE: {
                    const unsigned short *val = RTA_DATA(rta);
                    outf(" %hu", *val);
                    break;
                }
                // unsigned int
                case RTA_TABLE:
                case RTA_PRIORITY:
                case RTA_IIF:
                case RTA_OIF:
                case RTA_METRICS:
                case RTA_FLOW:
                case RTA_MARK:
                case RTA_EXPIRES: {
                    const unsigned *val = RTA_DATA(rta);
                    outf(" %u", *val);
                    break;
                }
                default:
                    outf("\n");
                    dump(RTA_DATA(rta), RTA_PAYLOAD(rta), 0, "\t");
                    break;
                }
            }
            outf("\n");

        } else {
                outf("unimplemented nlmsg_type %d (%s)\n", nh->nlmsg_type,
                    nlmsg_type_str[nh->nlmsg_type]);
                dump(NLMSG_DATA(nh), NLMSG_PAYLOAD(nh, 0), NLMSG_DATA(nh) - (void*) &buf, "\t");
        }
    }

    return len;
}

#ifdef MAIN

static int send_req(int nls, unsigned seqno)
{
    int rc;
    struct sockaddr_nl nladdr = { AF_NETLINK, 0, 0, 0 };
    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    } req = {
        { sizeof(req), NLMSG_NOOP, NLM_F_REQUEST | NLM_F_ROOT | NLM_F_ACK, seqno, getpid() },
        { AF_UNSPEC },
    };

    switch (seqno) {
    case 0:
        req.hdr.nlmsg_type = RTM_GETLINK;
        rc = sendto(nls, &req, sizeof(req), 0, (struct sockaddr *) &nladdr, sizeof(nladdr));
        break;
    case 1:
        req.hdr.nlmsg_type = RTM_GETADDR;
        rc = sendto(nls, &req, sizeof(req), 0, (struct sockaddr *) &nladdr, sizeof(nladdr));
        break;
    case 2:
        req.hdr.nlmsg_type = RTM_GETROUTE;
        rc = sendto(nls, &req, sizeof(req), 0, (struct sockaddr *) &nladdr, sizeof(nladdr));
        break;
    }

    return rc == (int) sizeof(req);
}

int main(int argc, char *argv[])
{
    int rc;
    (void)argc;
    (void)argv;

    int nls = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nls < 0) goto fail;

    int bufsize = 65536;
    rc = setsockopt(nls, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    if (rc < 0) goto fail;
    rc = setsockopt(nls, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    if (rc < 0) goto fail;

    const int enable = 1;
    rc = setsockopt(nls, SOL_NETLINK, NETLINK_NO_ENOBUFS, &enable, sizeof(enable));
    if (rc < 0) goto fail;

    struct sockaddr_nl nlsaddr = { AF_NETLINK, 0, getpid(),
        RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
        RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE };

    rc = bind(nls, (struct sockaddr *) &nlsaddr, sizeof(nlsaddr));
    if (rc < 0) goto fail;

    size_t nlslen = sizeof(nlsaddr);
    rc = getsockname(nls, (struct sockaddr *) &nlsaddr, &nlslen);
    if (rc < 0) goto fail;

    //rc = fcntl(nls, F_GETFL, 0);
    //if (rc < 0) goto fail;
    //rc = fcntl(nls, F_SETFL, rc | O_NONBLOCK);
    //if (rc < 0) goto fail;

    // struct iovec {                    /* Scatter/gather array items */
    //     void  *iov_base;              /* Starting address */
    //     size_t iov_len;               /* Number of bytes to transfer */
    // };

    // struct msghdr {
    //     void         *msg_name;       /* Optional address */
    //     socklen_t     msg_namelen;    /* Size of address */
    //     struct iovec *msg_iov;        /* Scatter/gather array */
    //     size_t        msg_iovlen;     /* # elements in msg_iov */
    //     void         *msg_control;    /* Ancillary data, see below */
    //     size_t        msg_controllen; /* Ancillary data buffer len */
    //     int           msg_flags;      /* Flags on received message */
    // };

    // struct nlmsghdr {
    //     __u32 nlmsg_len;    /* Length of message including header */
    //     __u16 nlmsg_type;   /* Type of message content */
    //     __u16 nlmsg_flags;  /* Additional flags */
    //     __u32 nlmsg_seq;    /* Sequence number */
    //     __u32 nlmsg_pid;    /* Sender port ID */
    // };

    // struct rtgenmsg {
    //     unsigned char rtgen_family;
    // };

    // struct sockaddr_nl {
    //     unsigned short  nl_family;      /* AF_NETLINK   */
    //     unsigned short  nl_pad;         /* zero         */
    //     __u32           nl_pid;         /* port ID      */
    //     __u32           nl_groups;      /* multicast groups mask */
    // };

    union {
        struct nlmsghdr nh;
        char buf[8192];
    } buf;

    int done = 0;
    unsigned seqno = 0;
    struct iovec iov = { &buf, sizeof(buf) };
    struct sockaddr_nl nladdr = { AF_NETLINK, 0, 0, 0 };
    struct msghdr msg = { &nladdr, sizeof(nladdr), &iov, 1, NULL, 0, MSG_WAITALL };

    send_req(nls, seqno++);

    do {
        int len = recvmsg(nls, &msg, 0);

        if (len < 0) {
            goto fail;
        } else if (len == 0) {
            outf("netlink_read: EOF\n");
            goto fail;
        } else if (msg.msg_flags & MSG_TRUNC) {
            outf("netlink_read: message truncated (%d)\n", len);
            continue;
        } else if (len < NLMSG_HDRLEN) {
            outf("netlink_read: short read (%d)\n", len);
            continue;
        } else if (msg.msg_namelen != nlslen) {
            outf("netlink_read: unexpected sender address length (%d)\n", msg.msg_namelen);
            goto fail;
        } else if (nladdr.nl_pid != 0) {
            outf("netlink_read: message from pid=%d\n", nladdr.nl_pid);
            continue;
        }

        if (1) {
            struct nlmsghdr *nh = (void *) &buf;
            outf("\n-------------------- Netlink message %s seq %d pid %d, %d bytes %s ----------------------------\n",
                len >= NLMSG_HDRLEN ? nlmsg_type_str[nh->nlmsg_type] : "?",
                len >= NLMSG_HDRLEN ? nh->nlmsg_seq : 0xffffffff,
                len >= NLMSG_HDRLEN ? nh->nlmsg_pid : 0xffffffff,
                len, nh->nlmsg_flags & NLM_F_MULTI ? "[multi]" : ""
            );
            if (nh->nlmsg_type == NLMSG_DONE || (nh->nlmsg_flags & NLM_F_MULTI) == 0)
                send_req(nls, seqno++);
        }

        if (nl_debug(&buf, len) < 0)
            goto fail;
    } while (!done);

    return 0;

  fail:
    fflush(stdout);
    perror("netlink");
    if (nls > 0) close(nls);
    return 1;
}
#endif
