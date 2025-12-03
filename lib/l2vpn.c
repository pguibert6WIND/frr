// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LDP L2VPNnorthbound CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 */

#include <zebra.h>

#include "lib/memory.h"
#include "lib/command.h"
#include "lib/northbound_cli.h"

#include "lib/l2vpn.h"

struct l2vpn_lib_register l2vpn_lib_master = { NULL, NULL, NULL, NULL };
struct l2vpn_head l2vpn_tree_config;

static __inline int l2vpn_compare(const struct l2vpn *, const struct l2vpn *);
static __inline int l2vpn_if_compare(const struct l2vpn_if *, const struct l2vpn_if *);
static __inline int l2vpn_pw_compare(const struct l2vpn_pw *, const struct l2vpn_pw *);

DEFINE_QOBJ_TYPE(l2vpn_if);
DEFINE_QOBJ_TYPE(l2vpn_pw);
DEFINE_QOBJ_TYPE(l2vpn);

DEFINE_MTYPE_STATIC(LIB, L2VPN, "L2VPN entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_PWE, "L2VPN PWE entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_IF, "L2VPN IF entry");

RB_GENERATE(l2vpn_head, l2vpn, entry, l2vpn_compare)
RB_GENERATE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare)
RB_GENERATE(l2vpn_pw_head, l2vpn_pw, entry, l2vpn_pw_compare)

static inline int l2vpn_compare(const struct l2vpn *a, const struct l2vpn *b)
{
	if (a->type != b->type)
		return a->type - b->type;
	return (strcmp(a->name, b->name));
}

static inline int l2vpn_pw_compare(const struct l2vpn_pw *a, const struct l2vpn_pw *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

static inline int l2vpn_if_compare(const struct l2vpn_if *a, const struct l2vpn_if *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

struct l2vpn *l2vpn_new(const char *name)
{
	struct l2vpn *l2vpn;

	l2vpn = XCALLOC(MTYPE_L2VPN, sizeof(*l2vpn));

	strlcpy(l2vpn->name, name, sizeof(l2vpn->name));

	/* set default values */
	l2vpn->mtu = DEFAULT_L2VPN_MTU;
	l2vpn->pw_type = DEFAULT_PW_TYPE;

	RB_INIT(l2vpn_if_head, &l2vpn->if_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_tree);
	RB_INIT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

	return (l2vpn);
}


struct l2vpn *l2vpn_find(struct l2vpn_head *conf, const char *name, int type)
{
	struct l2vpn l2vpn;

	strlcpy(l2vpn.name, name, sizeof(l2vpn.name));
	l2vpn.type = type;
	return (RB_FIND(l2vpn_head, conf, &l2vpn));
}

void l2vpn_del(struct l2vpn *l2vpn)
{
	struct l2vpn_if *lif;
	struct l2vpn_pw *pw;

	while (!RB_EMPTY(l2vpn_if_head, &l2vpn->if_tree)) {
		lif = RB_ROOT(l2vpn_if_head, &l2vpn->if_tree);

		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		XFREE(MTYPE_L2VPN_IF, lif);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		XFREE(MTYPE_L2VPN_PWE, pw);
	}
	while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_inactive_tree)) {
		pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		XFREE(MTYPE_L2VPN_PWE, pw);
	}

	free(l2vpn);
}


struct l2vpn_pw *l2vpn_pw_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw *pw;

	pw = XCALLOC(MTYPE_L2VPN_PWE, sizeof(*pw));

	pw->l2vpn = l2vpn;
	strlcpy(pw->ifname, ifname, sizeof(pw->ifname));

	return (pw);
}

struct l2vpn_if *l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if *lif;

	lif = XCALLOC(MTYPE_L2VPN_IF, sizeof(*lif));

	lif->l2vpn = l2vpn;
	strlcpy(lif->ifname, ifname, sizeof(lif->ifname));

	return lif;
}

struct l2vpn_pw *l2vpn_pw_find_active(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return (RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s));
}

struct l2vpn_pw *l2vpn_pw_find_inactive(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return (RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s));
}

struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if lif;
	strlcpy(lif.ifname, ifname, sizeof(lif.ifname));
	return RB_FIND(l2vpn_if_head, &l2vpn->if_tree, &lif);
}

struct l2vpn_pw *l2vpn_pw_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_pw *pw;
	struct l2vpn_pw s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	pw = RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s);
	if (pw)
		return (pw);
	return RB_FIND(l2vpn_pw_head, &l2vpn->pw_inactive_tree, &s);
}

int l2vpn_iface_is_configured(const char *ifname)
{
	struct l2vpn *l2vpn;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn_if_find(l2vpn, ifname))
			return 1;
		if (l2vpn_pw_find(l2vpn, ifname))
			return 1;
	}

	return (0);
}

void l2vpn_register_hook(void (*func_add)(const char *),
			 void (*func_del)(struct l2vpn *l2vpn),
			 void (*func_event)(struct l2vpn_pw *),
			 bool (*func_iface_ok_for_l2vpn)(const char *))
{
	l2vpn_lib_master.add_hook = func_add;
	l2vpn_lib_master.del_hook = func_del;
	l2vpn_lib_master.event_hook = func_event;
	l2vpn_lib_master.iface_ok_for_l2vpn = func_iface_ok_for_l2vpn;
}

void l2vpn_init_new(bool in_backend)
{
	RB_INIT(l2vpn_head, &l2vpn_tree_config);

	if (!in_backend) {
		/* we do not want to handle config commands in the backend */
		l2vpn_cli_init();
	}
}

void l2vpn_init()
{
	RB_INIT(l2vpn_head, &l2vpn_tree_config);
	l2vpn_cli_init();
}
