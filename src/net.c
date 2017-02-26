/**
 * @file src/net.c Networking code
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */
#include <assert.h>
#include <re.h>
#include <baresip.h>
#include "core.h"


struct network {
	struct config_net cfg;
	struct sa laddr;
	char ifname[16];
#ifdef HAVE_INET6
	struct sa laddr6;
	char ifname6[16];
#endif
	struct tmr tmr;
	struct dnsc *dnsc;
	struct sa nsv[NET_MAX_NS];/**< Configured name servers      */
	uint32_t nsn;        /**< Number of configured name servers */
	uint32_t interval;
	int af;              /**< Preferred address family          */
	char domain[64];     /**< DNS domain from network           */
	net_change_h *ch;
	void *arg;
};


/*
      Prefix        Precedence Label
      ::1/128               50     0
      ::/0                  40     1
      ::ffff:0:0/96         35     4
      2002::/16             30     2
      2001::/32              5     5
      fc00::/7               3    13
      ::/96                  1     3
      fec0::/10              1    11
      3ffe::/16              1    12

 * NOTE: The table is sorted by prefix_length in order to have fast lookup
 */
static const struct policy {
	uint32_t addr[4];     /* host-order */
	unsigned prefix_len;
	unsigned precedence;
	unsigned label;
} policy_table[] = {

{ {0x00000000, 0x00000000, 0x00000000, 0x00000001}, 128,  50,  0 },
{ {0x00000000, 0x00000000, 0x0000ffff, 0x00000000},  96,  35,  4 },
{ {0x00000000, 0x00000000, 0x00000000, 0x00000000},  96,   1,  3 },
{ {0x20010000, 0x00000000, 0x00000000, 0x00000000},  32,   5,  5 },
{ {0x20020000, 0x00000000, 0x00000000, 0x00000000},  16,  30,  2 },
{ {0x3ffe0000, 0x00000000, 0x00000000, 0x00000000},  16,   1, 12 },
{ {0xfec00000, 0x00000000, 0x00000000, 0x00000000},  10,   1, 11 },
{ {0xfc000000, 0x00000000, 0x00000000, 0x00000000},   7,   3, 13 },
{ {0x00000000, 0x00000000, 0x00000000, 0x00000000},   0,  40,  1 },

};


static bool sa_cmp_prefix(const uint32_t *la, const struct sa *r,
			  unsigned prefix)
{
	uint32_t *ra;
	int i, j;

	if (!la || !r)
		return false;

	if (r->u.sa.sa_family != AF_INET6)
		return false;

	if (prefix > 128)
		prefix = 128;

	ra = (uint32_t *)&r->u.in6.sin6_addr;

	for (i = prefix, j = 0; j < 4; i -= 32, ++j) {
		uint32_t mask;
		bool match;

		if (i >= 32)
			mask = 0xffffffff;
		else if (i <= 0)
			mask = 0x00000000;
		else
			mask = 0xffffffffu << ( 32 - i );

		match = (la[j] & mask) == (ntohl(ra[j]) & mask);

		if (!match)
			return false;
	}

	return true;
}


static const struct policy *policy_table_lookup(const struct sa *sa)
{
	size_t i;

	for (i=0; i<ARRAY_SIZE(policy_table); i++) {

		const struct policy *policy = &policy_table[i];
		bool match;

		match = sa_cmp_prefix(policy->addr, sa, policy->prefix_len);
		if (match)
			return policy;
	}

	return NULL;
}


/*
 * The policy table is a longest-matching-prefix lookup table
 */
static unsigned ipv6_calc_precedence(const struct sa *sa)
{
	const struct policy *policy;

	if (AF_INET6 != sa_af(sa)) {
		re_printf("not an ipv6 address\n");
		return 0;
	}

	policy = policy_table_lookup(sa);
	if (!policy) {
		warning("net: no matches in policy table for addr (%j)\n", sa);
		return 0;
	}

	return policy->precedence;
}


#if 1
/* only for testing */
static void pretest(void)
{
	struct sa sa;
	int pre;

	sa_set_str(&sa, "2001:67c:2b8c:3:b065:e5e2:c73:962a", 0);

	pre = ipv6_calc_precedence(&sa);
	re_printf("pre: %d\n", pre);
	assert(pre == 40);

	sa_set_str(&sa, "2002:5345:ca62:1:b065:e5e2:c73:962a", 0);

	pre = ipv6_calc_precedence(&sa);
	re_printf("pre: %d\n", pre);
	assert(pre == 30);
}
#endif


struct preaddr {
	struct sa *addr;
	unsigned precedence;
};

static bool ipv6_handler(const char *ifname, const struct sa *sa,
			 void *arg)
{
	struct preaddr *preaddr = arg;
	unsigned precedence;

	if (AF_INET6 != sa_af(sa))
		return false;

	precedence = ipv6_calc_precedence(sa);

	info("net: ifaddr:   %10s   %32j   precedence=%u\n",
		  ifname, sa, precedence);

	if (precedence > preaddr->precedence) {
		info("net: precedence %u > %u\n",
		     precedence, preaddr->precedence);

		*preaddr->addr = *sa;
		preaddr->precedence = precedence;
	}

	return false;
}


static int default_source_addr_get(int af, struct sa *addr)
{
	struct preaddr preaddr;

	if (af != AF_INET6)
		return EAFNOSUPPORT;

	preaddr.addr = addr;
	preaddr.precedence = 0;

	return net_getifaddrs(ipv6_handler, &preaddr);
}


static int net_dnssrv_add(struct network *net, const struct sa *sa)
{
	if (!net)
		return EINVAL;

	if (net->nsn >= ARRAY_SIZE(net->nsv))
		return E2BIG;

	sa_cpy(&net->nsv[net->nsn++], sa);

	return 0;
}


static int net_dns_srv_get(const struct network *net,
			   struct sa *srvv, uint32_t *n, bool *from_sys)
{
	struct sa nsv[NET_MAX_NS];
	uint32_t i, nsn = ARRAY_SIZE(nsv);
	int err;

	err = dns_srv_get(NULL, 0, nsv, &nsn);
	if (err) {
		nsn = 0;
	}

	if (net->nsn) {

		if (net->nsn > *n)
			return E2BIG;

		/* Use any configured nameservers */
		for (i=0; i<net->nsn; i++) {
			srvv[i] = net->nsv[i];
		}

		*n = net->nsn;

		if (from_sys)
			*from_sys = false;
	}
	else {
		if (nsn > *n)
			return E2BIG;

		for (i=0; i<nsn; i++)
			srvv[i] = nsv[i];

		*n = nsn;

		if (from_sys)
			*from_sys = true;
	}

	return 0;
}


/**
 * Check for DNS Server updates
 */
static void dns_refresh(struct network *net)
{
	struct sa nsv[NET_MAX_NS];
	uint32_t nsn;
	int err;

	nsn = ARRAY_SIZE(nsv);

	err = net_dns_srv_get(net, nsv, &nsn, NULL);
	if (err)
		return;

	(void)dnsc_srv_set(net->dnsc, nsv, nsn);
}


/**
 * Detect changes in IP address(es)
 */
static void ipchange_handler(void *arg)
{
	struct network *net = arg;
	bool change;

	tmr_start(&net->tmr, net->interval * 1000, ipchange_handler, net);

	dns_refresh(net);

	change = net_check(net);
	if (change && net->ch) {
		net->ch(net->arg);
	}
}


/**
 * Check if local IP address(es) changed
 *
 * @param net Network instance
 *
 * @return True if changed, otherwise false
 */
bool net_check(struct network *net)
{
	struct sa laddr = net->laddr;
#ifdef HAVE_INET6
	struct sa laddr6 = net->laddr6;
#endif
	bool change = false;

	if (!net)
		return false;

	if (str_isset(net->cfg.ifname)) {

		(void)net_if_getaddr(net->cfg.ifname, AF_INET, &net->laddr);

#ifdef HAVE_INET6
		(void)net_if_getaddr(net->cfg.ifname, AF_INET6, &net->laddr6);
#endif
	}
	else {
		(void)net_default_source_addr_get(AF_INET, &net->laddr);
		(void)net_rt_default_get(AF_INET, net->ifname,
					 sizeof(net->ifname));

#ifdef HAVE_INET6
		(void)default_source_addr_get(AF_INET6, &net->laddr6);
		(void)net_rt_default_get(AF_INET6, net->ifname6,
					 sizeof(net->ifname6));
#endif
	}

	if (sa_isset(&net->laddr, SA_ADDR) &&
	    !sa_cmp(&laddr, &net->laddr, SA_ADDR)) {
		change = true;
		info("net: local IPv4 address changed: %j -> %j\n",
		     &laddr, &net->laddr);
	}

#ifdef HAVE_INET6
	if (sa_isset(&net->laddr6, SA_ADDR) &&
	    !sa_cmp(&laddr6, &net->laddr6, SA_ADDR)) {
		change = true;
		info("net: local IPv6 address changed: %j -> %j\n",
		     &laddr6, &net->laddr6);
	}
#endif

	return change;
}


static int dns_init(struct network *net)
{
	struct sa nsv[NET_MAX_NS];
	uint32_t nsn = ARRAY_SIZE(nsv);
	int err;

	err = net_dns_srv_get(net, nsv, &nsn, NULL);
	if (err)
		return err;

	return dnsc_alloc(&net->dnsc, NULL, nsv, nsn);
}


/**
 * Return TRUE if libre supports IPv6
 */
static bool check_ipv6(void)
{
	struct sa sa;

	return 0 == sa_set_str(&sa, "::1", 2000);
}


static void net_destructor(void *data)
{
	struct network *net = data;

	tmr_cancel(&net->tmr);
	mem_deref(net->dnsc);
}


/**
 * Initialise networking
 *
 * @param netp Pointer to allocated network instance
 * @param cfg  Network configuration
 * @param af   Preferred address family
 *
 * @return 0 if success, otherwise errorcode
 */
int net_alloc(struct network **netp, const struct config_net *cfg, int af)
{
	struct network *net;
	struct sa nsv[NET_MAX_NS];
	uint32_t nsn = ARRAY_SIZE(nsv);
	char buf4[128] = "", buf6[128] = "";
	int err;

	if (!netp || !cfg)
		return EINVAL;

	/*
	 * baresip/libre must be built with matching HAVE_INET6 value.
	 * if different the size of `struct sa' will not match and the
	 * application is very likely to crash.
	 */
#ifdef HAVE_INET6
	if (!check_ipv6()) {
		error("libre was compiled without IPv6-support"
		      ", but baresip was compiled with\n");
		return EAFNOSUPPORT;
	}
#else
	if (check_ipv6()) {
		error("libre was compiled with IPv6-support"
		      ", but baresip was compiled without\n");
		return EAFNOSUPPORT;
	}
#endif

	net = mem_zalloc(sizeof(*net), net_destructor);
	if (!net)
		return ENOMEM;

	net->cfg = *cfg;
	net->af  = af;

	tmr_init(&net->tmr);

	if (cfg->nsc) {
		size_t i;

		for (i=0; i<cfg->nsc; i++) {

			const char *ns = cfg->nsv[i].addr;
			struct sa sa;

			err = sa_decode(&sa, ns, str_len(ns));
			if (err) {
				warning("net: dns_server:"
					" could not decode `%s' (%m)\n",
					ns, err);
				goto out;
			}

			err = net_dnssrv_add(net, &sa);
			if (err) {
				warning("net: failed to add nameserver: %m\n",
					err);
				goto out;
			}
		}
	}

	/* Initialise DNS resolver */
	err = dns_init(net);
	if (err) {
		warning("net: dns_init: %m\n", err);
		goto out;
	}

	sa_init(&net->laddr, AF_INET);
	(void)sa_set_str(&net->laddr, "127.0.0.1", 0);

	if (str_isset(cfg->ifname)) {

		bool got_it = false;

		info("Binding to interface '%s'\n", cfg->ifname);

		str_ncpy(net->ifname, cfg->ifname, sizeof(net->ifname));

		err = net_if_getaddr(cfg->ifname,
				     AF_INET, &net->laddr);
		if (err) {
			info("net: %s: could not get IPv4 address (%m)\n",
			     cfg->ifname, err);
		}
		else
			got_it = true;

#ifdef HAVE_INET6
		str_ncpy(net->ifname6, cfg->ifname,
			 sizeof(net->ifname6));

		err = net_if_getaddr(cfg->ifname,
				     AF_INET6, &net->laddr6);
		if (err) {
			info("net: %s: could not get IPv6 address (%m)\n",
			     cfg->ifname, err);
		}
		else
			got_it = true;
#endif
		if (got_it)
			err = 0;
		else {
			warning("net: %s: could not get network address\n",
				cfg->ifname);
			err = EADDRNOTAVAIL;
			goto out;
		}
	}
	else {
		(void)net_default_source_addr_get(AF_INET, &net->laddr);
		(void)net_rt_default_get(AF_INET, net->ifname,
					 sizeof(net->ifname));

#ifdef HAVE_INET6
		sa_init(&net->laddr6, AF_INET6);

		(void)default_source_addr_get(AF_INET6, &net->laddr6);
		(void)net_rt_default_get(AF_INET6, net->ifname6,
					 sizeof(net->ifname6));
#endif
	}

	if (sa_isset(&net->laddr, SA_ADDR)) {
		re_snprintf(buf4, sizeof(buf4), " IPv4=%s:%j",
			    net->ifname, &net->laddr);
	}
#ifdef HAVE_INET6
	if (sa_isset(&net->laddr6, SA_ADDR)) {
		re_snprintf(buf6, sizeof(buf6), " IPv6=%s:%j",
			    net->ifname6, &net->laddr6);
	}
#endif

	(void)dns_srv_get(net->domain, sizeof(net->domain), nsv, &nsn);

	pretest();

	info("Local network address: %s %s\n",
	     buf4, buf6);

 out:
	if (err)
		mem_deref(net);
	else
		*netp = net;

	return err;
}


/**
 * Use a specific DNS server
 *
 * @param net Network instance
 * @param ns  DNS Server IP address and port
 *
 * @return 0 if success, otherwise errorcode
 */
int net_use_nameserver(struct network *net, const struct sa *ns)
{
	struct dnsc *dnsc;
	int err;

	if (!net || !ns)
		return EINVAL;

	err = dnsc_alloc(&dnsc, NULL, ns, 1);
	if (err)
		return err;

	mem_deref(net->dnsc);
	net->dnsc = dnsc;

	return 0;
}


/**
 * Check for networking changes with a regular interval
 *
 * @param net       Network instance
 * @param interval  Interval in seconds
 * @param ch        Handler called when a change was detected
 * @param arg       Handler argument
 */
void net_change(struct network *net, uint32_t interval,
		net_change_h *ch, void *arg)
{
	if (!net)
		return;

	net->interval = interval;
	net->ch = ch;
	net->arg = arg;

	if (interval)
		tmr_start(&net->tmr, interval * 1000, ipchange_handler, net);
	else
		tmr_cancel(&net->tmr);
}


void net_force_change(struct network *net)
{
	if (net && net->ch) {
		net->ch(net->arg);
	}
}


static int dns_debug(struct re_printf *pf, const struct network *net)
{
	struct sa nsv[NET_MAX_NS];
	uint32_t i, nsn = ARRAY_SIZE(nsv);
	bool from_sys = false;
	int err;

	if (!net)
		return 0;

	err = net_dns_srv_get(net, nsv, &nsn, &from_sys);
	if (err)
		nsn = 0;

	err = re_hprintf(pf, " DNS Servers from %s: (%u)\n",
			 from_sys ? "System" : "Config", nsn);
	for (i=0; i<nsn; i++)
		err |= re_hprintf(pf, "   %u: %J\n", i, &nsv[i]);

	return err;
}


int net_af(const struct network *net)
{
	if (!net)
		return AF_UNSPEC;

	return net->af;
}


/**
 * Print networking debug information
 *
 * @param pf     Print handler for debug output
 * @param net    Network instance
 *
 * @return 0 if success, otherwise errorcode
 */
int net_debug(struct re_printf *pf, const struct network *net)
{
	int err;

	if (!net)
		return 0;

	err  = re_hprintf(pf, "--- Network debug ---\n");
	err |= re_hprintf(pf, " Preferred AF:  %s\n", net_af2name(net->af));
	err |= re_hprintf(pf, " Local IPv4: %9s - %j\n",
			  net->ifname, &net->laddr);
#ifdef HAVE_INET6
	err |= re_hprintf(pf, " Local IPv6: %9s - %j\n",
			  net->ifname6, &net->laddr6);
#endif
	err |= re_hprintf(pf, " Domain: %s\n", net->domain);

	err |= net_if_debug(pf, NULL);

	err |= net_rt_debug(pf, NULL);

	err |= dns_debug(pf, net);

	return err;
}


/**
 * Get the local IP Address for a specific Address Family (AF)
 *
 * @param net Network instance
 * @param af  Address Family
 *
 * @return Local IP Address
 */
const struct sa *net_laddr_af(const struct network *net, int af)
{
	if (!net)
		return NULL;

	switch (af) {

	case AF_INET:  return &net->laddr;
#ifdef HAVE_INET6
	case AF_INET6: return &net->laddr6;
#endif
	default:       return NULL;
	}
}


/**
 * Get the DNS Client
 *
 * @param net Network instance
 *
 * @return DNS Client
 */
struct dnsc *net_dnsc(const struct network *net)
{
	if (!net)
		return NULL;

	return net->dnsc;
}


/**
 * Get the network domain name
 *
 * @param net Network instance
 *
 * @return Network domain
 */
const char *net_domain(const struct network *net)
{
	if (!net)
		return NULL;

	return net->domain[0] ? net->domain : NULL;
}
