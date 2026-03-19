#ifndef PAMKIT_NET_H
#define PAMKIT_NET_H

extern int prevent_pam_mod_mapping;

int add_netfilter_hook(void);
void remove_netfilter_hook(void);

#endif /* PAMKIT_NET_H */
