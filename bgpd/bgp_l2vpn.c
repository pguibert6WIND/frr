// SPDX-License-Identifier: GPL-2.0-or-later
/* L2-VPN File
 * Copyright (C) 2025 6WIND
 *
 * This file is part of FRRouting
 */
#include "lib/zebra.h"
#include "lib/l2vpn.h"

#include "bgpd/bgp_l2vpn.h"

static void bgp_l2vpn_entry_added(const char *l2vpn_name)
{
	/* XXX handle l2vpn entry add */
}

static void bgp_l2vpn_entry_deleted(const char *l2vpn_name)
{
	/* XXX handle l2vpn entry deletion */
}

static void bgp_l2vpn_entry_event(const char *l2vpn_name)
{
	/* XXX handle l2vpn changes */
}

static bool bgp_l2vpn_iface_ok_for_l2vpn(const char *ifname)
{
	/* XXX Check if a given interface is eligible for l2vpn */
	return true;
}

void bgp_l2vpn_init(void)
{
	l2vpn_init();
	l2vpn_register_hook(bgp_l2vpn_entry_added, bgp_l2vpn_entry_deleted, bgp_l2vpn_entry_event,
			    bgp_l2vpn_iface_ok_for_l2vpn);
}
