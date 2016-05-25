#ifndef _IPSET_H
#define	_IPSET_H

int ipset_init(void);

int add_to_ipset(const char *setname, const char *ipaddr, int remove);

int flush_ipset(const char *setname);

#endif
