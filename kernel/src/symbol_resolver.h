#ifndef _PAMKIT_SYMBOL_RESOLVER_H
#define _PAMKIT_SYMBOL_RESOLVER_H

/* Must be invoked before trying to resolve a symbol's address */
int init_symbol_resolver(void);

void * pamkit_lookup_symbol_addr(const char *symbol_name);

#endif /* _PAMKIT_SYMBOL_RESOLVER_H */
