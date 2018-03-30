/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include "if.h"
#include "prefix.h"
#include "vrf.h"
#include "log.h"
#include "zclient.h"

#include <linux/fib_rules.h>
#include <linux/libipset/linux_ip_set.h>
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/zebra_pbr.h"

/* definitions */
#define IPSET_DEFAULT_HASHSIZE 64
#define IPSET_PRE_HASH "hash:"

static const struct message netlink_ipset_type_msg[] = {
	{IPSET_NET_PORT_NET, "net,port,net"},
	{IPSET_NET_PORT, "net,port"},
	{IPSET_NET_NET, "net,net"},
	{IPSET_NET, "net"},
	{0}};

/* static function declarations */

/* Private functions */

const char *netlink_ipset_type2str(uint32_t type)
{
	return lookup_msg(netlink_ipset_type_msg, type,
			  "Unrecognized IPset Type");
}

/* Install or uninstall specified rule for a specific interface.
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int netlink_rule_update(int cmd, struct zapi_pbr_rule *rule)
{
	int family;
	int bytelen;
	struct {
		struct nlmsghdr n;
		struct fib_rule_hdr frh;
		char buf[NL_PKT_BUF_SIZE];
	} req;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct sockaddr_nl snl;
	char buf1[PREFIX_STRLEN];
	char buf2[PREFIX_STRLEN];

	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);
	family = PREFIX_FAMILY(&rule->filter.src_ip);
	bytelen = (family == AF_INET ? 4 : 16);

	req.n.nlmsg_type = cmd;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.frh.family = family;
	req.frh.action = FR_ACT_TO_TBL;

	/* rule's pref # */
	if (rule->priority)
		addattr32(&req.n, sizeof(req), FRA_PRIORITY, rule->priority);

	/* interface on which applied */
	if (rule->ifp)
		addattr_l(&req.n, sizeof(req), FRA_IFNAME, rule->ifp->name,
			  strlen(rule->ifp->name) + 1);

	/* source IP, if specified */
	if (IS_RULE_FILTERING_ON_SRC_IP(rule)) {
		req.frh.src_len = rule->filter.src_ip.prefixlen;
		addattr_l(&req.n, sizeof(req), FRA_SRC,
			  &rule->filter.src_ip.u.prefix, bytelen);
	}
	/* destination IP, if specified */
	if (IS_RULE_FILTERING_ON_DST_IP(rule)) {
		req.frh.dst_len = rule->filter.dst_ip.prefixlen;
		addattr_l(&req.n, sizeof(req), FRA_DST,
			  &rule->filter.dst_ip.u.prefix, bytelen);
	}
	/* fwmark, if specified */
	if (IS_RULE_FILTERING_ON_FWMARK(rule)) {
		addattr32(&req.n, sizeof(req), FRA_FWMARK,
			  rule->filter.fwmark);
	}
	/* Route table to use to forward, if filter criteria matches. */
	if (rule->action.table < 256)
		req.frh.table = rule->action.table;
	else {
		req.frh.table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), FRA_TABLE,
			  rule->action.table);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Tx %s family %s IF %s(%u) Pref %u Src %s Dst %s"
			" Fwmark %u Table %u",
			nl_msg_type_to_str(cmd), nl_family_to_str(family),
			rule->ifp ? rule->ifp->name : "Unknown",
			rule->ifp ? rule->ifp->ifindex : 0, rule->priority,
			prefix2str(&rule->filter.src_ip, buf1, sizeof(buf1)),
			prefix2str(&rule->filter.dst_ip, buf2, sizeof(buf2)),
			rule->filter.fwmark, rule->action.table);
	/* Ship off the message.
	 * Note: Currently, netlink_talk() is a blocking call which returns
	 * back the status.
	 */
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	if (rule->action.table && IS_RULE_FILTERING_ON_FWMARK(rule)) {
		char buf[255];
		snprintf(buf, 255, "ip rule %s fwmark %d table %d",
			 cmd == RTM_NEWRULE ? "add" : "del",
			 rule->filter.fwmark, rule->action.table);
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("PBR: %s", buf);
		system(buf);
		return 0;
	} else {
		return netlink_talk(netlink_talk_filter, &req.n,
				    &zns->netlink_cmd, zns, 0);
	}
}


/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int netlink_ipset_update(int cmd,
				struct zebra_pbr_ipset *ipset,
				struct zebra_ns *zns)
{
	char buf[256];

	if (cmd == IPSET_CMD_CREATE) {
		sprintf(buf, "ipset create %s %s%s hashsize %u counters",
			ipset->ipset_name, IPSET_PRE_HASH,
			netlink_ipset_type2str(ipset->type),
			IPSET_DEFAULT_HASHSIZE);
	} else
		sprintf(buf, "ipset destroy %s",
			ipset->ipset_name);
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	system(buf);
	return 0;
}

static int netlink_ipset_entry_update_unit(int cmd,
					   struct zebra_pbr_ipset_entry *ipset,
					   char *buf)
{
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	system(buf);
	return 0;
}

static void netlink_ipset_entry_port(char *strtofill, int lenstr,
				     uint32_t filter_bm,
				     uint16_t port_min, uint16_t port_max)
{
	if (port_max)
		sprintf(strtofill, "%d-%d",
			port_min, port_max);
	else
		sprintf(strtofill, "%d",
			port_min);
}

/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int netlink_ipset_entry_update(int cmd,
			struct zebra_pbr_ipset_entry *ipset,
			struct zebra_ns *zns)
{
	char buf[256];
	char buf_src[PREFIX2STR_BUFFER];
	char buf_dst[PREFIX2STR_BUFFER];
	char *psrc = NULL, *pdst = NULL;
	struct zebra_pbr_ipset *bp;
	uint16_t port = 0;
	uint16_t port_max = 0;

	if (ipset->filter_bm & PBR_FILTER_SRC_PORT)
		port = ipset->src_port_min;
	else if (ipset->filter_bm & PBR_FILTER_DST_PORT)
		port = ipset->dst_port_min;
	if (ipset->filter_bm & PBR_FILTER_SRC_PORT_RANGE)
		port_max = ipset->src_port_max;
	else if (ipset->filter_bm & PBR_FILTER_DST_PORT_RANGE)
		port_max = ipset->dst_port_max;
	if (ipset->filter_bm & PBR_FILTER_SRC_IP) {
		psrc = (char *)prefix2str(&ipset->src, buf_src, PREFIX2STR_BUFFER);
		if (psrc == NULL)
			return -1;
	}
	if (ipset->filter_bm & PBR_FILTER_DST_IP) {
		pdst = (char *)prefix2str(&ipset->dst, buf_dst, PREFIX2STR_BUFFER);
		if (pdst == NULL)
			return -1;
	}
	bp = ipset->backpointer;
	if (!bp)
		return -1;
	if (bp->type == IPSET_NET_NET) {
		sprintf(buf, "ipset %s %s %s,%s",
			cmd == IPSET_CMD_ADD ? "add" : "del",
			bp->ipset_name,
			psrc, pdst);
		return netlink_ipset_entry_update_unit(cmd, ipset, buf);
	} else if (bp->type == IPSET_NET) {
		sprintf(buf, "ipset %s %s %s",
			cmd == IPSET_CMD_ADD ? "add" : "del",
			bp->ipset_name,
			pdst == NULL ? psrc : pdst);
		return netlink_ipset_entry_update_unit(cmd, ipset, buf);
	} else if (bp->type == IPSET_NET_PORT) {
		char strtofill[32];

		netlink_ipset_entry_port(strtofill, sizeof(strtofill),
					 ipset->filter_bm,
					 port, port_max);
		/* apply it to udp and tcp */
		if (!(ipset->filter_bm & PBR_FILTER_PROTO)) {
			sprintf(buf, "ipset %s %s %s,udp:%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				pdst == NULL ? psrc : pdst, strtofill);
			netlink_ipset_entry_update_unit(cmd, ipset, buf);
			sprintf(buf, "ipset %s %s %s,tcp:%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				pdst == NULL ? psrc : pdst, strtofill);
			return netlink_ipset_entry_update_unit(cmd, ipset, buf);
		} else {
			sprintf(buf, "ipset %s %s %s,%d:%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				pdst == NULL ? psrc : pdst, ipset->proto,
				strtofill);
			return netlink_ipset_entry_update_unit(cmd, ipset, buf);
		}
	} else if (bp->type == IPSET_NET_PORT_NET) {
		char strtofill[32];

		netlink_ipset_entry_port(strtofill, sizeof(strtofill),
					 ipset->filter_bm,
					 port, port_max);
		/* apply it to udp and tcp */
		if (!(ipset->filter_bm & PBR_FILTER_PROTO)) {
			sprintf(buf, "ipset %s %s %s,tcp:%s,%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				psrc, strtofill, pdst);
			netlink_ipset_entry_update_unit(cmd, ipset, buf);
			sprintf(buf, "ipset %s %s %s,udp:%s,%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				psrc, strtofill, pdst);
			return netlink_ipset_entry_update_unit(cmd, ipset, buf);
		} else {
			sprintf(buf, "ipset %s %s %s,%d:%s,%s",
				cmd == IPSET_CMD_ADD ? "add" : "del",
				bp->ipset_name,
				psrc, ipset->proto, strtofill, pdst);
			return netlink_ipset_entry_update_unit(cmd, ipset, buf);
		}
	}
	return -1;
}


static int netlink_iptable_update_unit(int cmd,
				  struct zebra_pbr_iptable *iptable,
				  char *combi)
{
	char buf[256];
	char *ptr = buf;

	ptr+=sprintf(ptr, "iptables -t mangle -%s PREROUTING -m set",
		     cmd ? "I":"D");
	ptr+=sprintf(ptr, " --match-set %s %s",
		     iptable->ipset_name, combi);
	if (iptable->action == ZEBRA_IPTABLES_DROP)
		ptr+=sprintf(ptr, " -j DROP");
	else
		ptr+=sprintf(ptr, " -j MARK --set-mark %d",
			     iptable->fwmark);
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("PBR: %s", buf);
	system(buf);
	return 0;
}

/*
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int netlink_iptable_update(int cmd,
		      struct zebra_pbr_iptable *iptable,
		      struct zebra_ns *zns)
{
	char buf2[32];

	if (iptable->type == IPSET_NET_NET) {
		sprintf(buf2, "src,dst");
		return netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET) {
		if (iptable->filter_bm & PBR_FILTER_DST_IP)
			sprintf(buf2, "dst");
		else
			sprintf(buf2, "src");
		return netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET_PORT) {
		char *ptr = buf2;

		if (iptable->filter_bm & PBR_FILTER_DST_IP)
			ptr += sprintf(ptr, "dst");
		else
			ptr += sprintf(ptr, "src");

		if ((iptable->filter_bm & PBR_FILTER_DST_PORT) &&
		    (iptable->filter_bm & PBR_FILTER_SRC_PORT)) {
			/* iptable rule will be called twice.
			 * one for each side
			 */
			sprintf(ptr, ",dst");
			netlink_iptable_update_unit(cmd, iptable, buf2);
			sprintf(ptr, ",src");
		} else if (iptable->filter_bm & PBR_FILTER_DST_PORT)
			sprintf(ptr, ",dst");
		else if (iptable->filter_bm & PBR_FILTER_SRC_PORT)
			sprintf(ptr, ",src");
		return netlink_iptable_update_unit(cmd, iptable, buf2);
	} else if (iptable->type == IPSET_NET_PORT_NET) {
		char *ptr = buf2;

		ptr += sprintf(ptr, "src");

		if ((iptable->filter_bm & PBR_FILTER_DST_PORT) &&
		    (iptable->filter_bm & PBR_FILTER_SRC_PORT)) {
			sprintf(ptr, ",dst,dst");
			netlink_iptable_update_unit(cmd, iptable, buf2);
			ptr += sprintf(ptr, ",src");
		} else if (iptable->filter_bm & PBR_FILTER_DST_PORT)
			ptr += sprintf(ptr, ",dst");
		else if (iptable->filter_bm & PBR_FILTER_SRC_PORT)
			ptr += sprintf(ptr, ",src");
		ptr += sprintf(ptr, ",dst");

		netlink_iptable_update_unit(cmd, iptable, buf2);
	}
	return 0;
}

/* Public functions */
/*
 * Install specified rule for a specific interface. The preference is what
 * goes in the rule to denote relative ordering; it may or may not be the
 * same as the rule's user-defined sequence number.
 */
void kernel_add_pbr_rule(struct zapi_pbr_rule *rule)
{
	int ret = 0;

	ret = netlink_rule_update(RTM_NEWRULE, rule);
	kernel_pbr_rule_add_del_status(rule,
				       (!ret) ? SOUTHBOUND_INSTALL_SUCCESS
					      : SOUTHBOUND_INSTALL_FAILURE);
}

/*
 * Uninstall specified rule for a specific interface.
 */
void kernel_del_pbr_rule(struct zapi_pbr_rule *rule)
{
	int ret = 0;

	ret = netlink_rule_update(RTM_DELRULE, rule);
	kernel_pbr_rule_add_del_status(rule,
				       (!ret) ? SOUTHBOUND_DELETE_SUCCESS
					      : SOUTHBOUND_DELETE_FAILURE);
}

void kernel_create_pbr_ipset(struct zebra_ns *zns,
			     struct zebra_pbr_ipset *ipset)
{
	int ret = 0;

	ret = netlink_ipset_update(IPSET_CMD_CREATE, ipset, zns);
	kernel_pbr_ipset_add_del_status(ipset,
				       (!ret) ? SOUTHBOUND_INSTALL_SUCCESS
					      : SOUTHBOUND_INSTALL_FAILURE);
}

/*
 * Uninstall specified ipset for a specific interface.
 */
void kernel_destroy_pbr_ipset(struct zebra_ns *zns,
			      struct zebra_pbr_ipset *ipset)
{
	int ret = 0;

	ret = netlink_ipset_update(IPSET_CMD_DESTROY, ipset, zns);
	kernel_pbr_ipset_add_del_status(ipset,
				       (!ret) ? SOUTHBOUND_DELETE_SUCCESS
					      : SOUTHBOUND_DELETE_FAILURE);
}

void kernel_add_pbr_ipset_entry(struct zebra_ns *zns,
				struct zebra_pbr_ipset_entry *ipset)
{
	int ret = 0;

	ret = netlink_ipset_entry_update(IPSET_CMD_ADD, ipset, zns);
	kernel_pbr_ipset_entry_add_del_status(ipset,
				       (!ret) ? SOUTHBOUND_INSTALL_SUCCESS
					      : SOUTHBOUND_INSTALL_FAILURE);
}

/*
 * Uninstall specified ipset for a specific interface.
 */
void kernel_del_pbr_ipset_entry(struct zebra_ns *zns,
				struct zebra_pbr_ipset_entry *ipset)
{
	int ret = 0;

	ret = netlink_ipset_entry_update(IPSET_CMD_DESTROY, ipset, zns);
	kernel_pbr_ipset_entry_add_del_status(ipset,
				       (!ret) ? SOUTHBOUND_DELETE_SUCCESS
					      : SOUTHBOUND_DELETE_FAILURE);
}


void kernel_add_pbr_iptable(struct zebra_ns *zns,
			    struct zebra_pbr_iptable *iptable)
{
	int ret = 0;

	ret = netlink_iptable_update(1, iptable, zns);
	kernel_pbr_iptable_add_del_status(iptable,
				       (!ret) ? SOUTHBOUND_INSTALL_SUCCESS
					      : SOUTHBOUND_INSTALL_FAILURE);
}

void kernel_del_pbr_iptable(struct zebra_ns *zns,
			    struct zebra_pbr_iptable *iptable)
{
	int ret = 0;

	ret = netlink_iptable_update(0, iptable, zns);
	kernel_pbr_iptable_add_del_status(iptable,
				       (!ret) ? SOUTHBOUND_DELETE_SUCCESS
					      : SOUTHBOUND_DELETE_FAILURE);
}

/*
 * Handle netlink notification informing a rule add or delete.
 * Handling of an ADD is TBD.
 * DELs are notified up, if other attributes indicate it may be a
 * notification of interest. The expectation is that if this corresponds
 * to a PBR rule added by FRR, it will be readded.
 */
int netlink_rule_change(struct sockaddr_nl *snl, struct nlmsghdr *h,
			ns_id_t ns_id, int startup)
{
	struct zebra_ns *zns;
	struct fib_rule_hdr *frh;
	struct rtattr *tb[FRA_MAX + 1];
	int len;
	char *ifname;
	struct zapi_pbr_rule rule;
	char buf1[PREFIX_STRLEN];
	char buf2[PREFIX_STRLEN];

	/* Basic validation followed by extracting attributes. */
	if (h->nlmsg_type != RTM_NEWRULE && h->nlmsg_type != RTM_DELRULE)
		return 0;

	/* TBD */
	if (h->nlmsg_type == RTM_NEWRULE)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	if (len < 0)
		return -1;

	frh = NLMSG_DATA(h);
	if (frh->family != AF_INET && frh->family != AF_INET6)
		return 0;
	if (frh->action != FR_ACT_TO_TBL)
		return 0;

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, FRA_MAX, RTM_RTA(frh), len);

	/* TBD: We don't care about rules not specifying an IIF. */
	if (tb[FRA_IFNAME] == NULL)
		return 0;

	/* If we don't know the interface, we don't care. */
	ifname = (char *)RTA_DATA(tb[FRA_IFNAME]);
	zns = zebra_ns_lookup(ns_id);
	rule.ifp = if_lookup_by_name_per_ns(zns, ifname);
	if (!rule.ifp)
		return 0;

	memset(&rule, 0, sizeof(rule));
	if (tb[FRA_PRIORITY])
		rule.priority = *(uint32_t *)RTA_DATA(tb[FRA_PRIORITY]);

	if (tb[FRA_SRC]) {
		if (frh->family == AF_INET)
			memcpy(&rule.filter.src_ip.u.prefix4,
			       RTA_DATA(tb[FRA_SRC]), 4);
		else
			memcpy(&rule.filter.src_ip.u.prefix6,
			       RTA_DATA(tb[FRA_SRC]), 16);
		rule.filter.src_ip.prefixlen = frh->src_len;
		rule.filter.filter_bm |= PBR_FILTER_SRC_IP;
	}

	if (tb[FRA_DST]) {
		if (frh->family == AF_INET)
			memcpy(&rule.filter.dst_ip.u.prefix4,
			       RTA_DATA(tb[FRA_DST]), 4);
		else
			memcpy(&rule.filter.dst_ip.u.prefix6,
			       RTA_DATA(tb[FRA_DST]), 16);
		rule.filter.dst_ip.prefixlen = frh->dst_len;
		rule.filter.filter_bm |= PBR_FILTER_DST_IP;
	}

	if (tb[FRA_TABLE])
		rule.action.table = *(uint32_t *)RTA_DATA(tb[FRA_TABLE]);
	else
		rule.action.table = frh->table;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Rx %s family %s IF %s(%u) Pref %u Src %s Dst %s Table %u",
			nl_msg_type_to_str(h->nlmsg_type),
			nl_family_to_str(frh->family), rule.ifp->name,
			rule.ifp->ifindex, rule.priority,
			prefix2str(&rule.filter.src_ip, buf1, sizeof(buf1)),
			prefix2str(&rule.filter.dst_ip, buf2, sizeof(buf2)),
			rule.action.table);

	return kernel_pbr_rule_del(&rule);
}

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 * TBD.
 */
int netlink_rules_read(struct zebra_ns *zns)
{
	return 0;
}

#endif /* HAVE_NETLINK */
