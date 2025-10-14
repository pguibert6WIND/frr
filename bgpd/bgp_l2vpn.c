// SPDX-License-Identifier: GPL-2.0-or-later
/* L2-VPN File
 * Copyright (C) 2025 6WIND
 *
 * This file is part of FRRouting
 */
#include "lib/zebra.h"
#include "lib/l2vpn.h"

#include "bgpd/bgp_l2vpn.h"

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance
 */
static void bgp_l2vpn_entry_added(const char *l2vpn_name)
{
	/* XXX handle l2vpn entry add */
	/* bridge-interface and member-interface must form an EVPN VNI notified by ZEBRA_VNI_ADD message */
}

static void bgp_l2vpn_entry_deleted(const char *l2vpn_name)
{
	/* XXX handle l2vpn entry deletion */
}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/mtu
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/pw-type
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-interface
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/bridge-interface
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn/local-ac-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn/remote-ac-id
 */

static void bgp_l2vpn_entry_event(struct l2vpn_pw *l2vpn_pw)
{
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
