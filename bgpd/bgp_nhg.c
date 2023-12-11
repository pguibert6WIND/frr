// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#include <zebra.h>
#include "memory.h"

#include <bgpd/bgpd.h>
#include <bgpd/bgp_debug.h>
#include <bgpd/bgp_nhg.h>
#include <bgpd/bgp_nexthop.h>
#include <bgpd/bgp_zebra.h>

extern struct zclient *zclient;

/* Tree for nhg lookup cache. */
struct bgp_nhg_cache_head nhg_cache_table;

static void bgp_nhg_group_init(void);

/****************************************************************************
 * L3 NHGs are used for fast failover of nexthops in the dplane. These are
 * the APIs for allocating L3 NHG ids. Management of the L3 NHG itself is
 * left to the application using it.
 * PS: Currently EVPN host routes is the only app using L3 NHG for fast
 * failover of remote ES links.
 ***************************************************************************/
static bitfield_t bgp_nh_id_bitmap;
static uint32_t bgp_nhg_start;

/* XXX - currently we do nothing on the callbacks */
static void bgp_nhg_add_cb(const char *name)
{
}

static void bgp_nhg_modify_cb(const struct nexthop_group_cmd *nhgc, bool reset)
{
}

static void bgp_nhg_add_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_nexthop_cb(const struct nexthop_group_cmd *nhgc,
				   const struct nexthop *nhop)
{
}

static void bgp_nhg_del_cb(const char *name)
{
}

static void bgp_nhg_zebra_init(void)
{
	static bool bgp_nhg_zebra_inited;

	if (bgp_nhg_zebra_inited)
		return;

	bgp_nhg_zebra_inited = true;
	bgp_nhg_start = zclient_get_nhg_start(ZEBRA_ROUTE_BGP);
	nexthop_group_init(bgp_nhg_add_cb, bgp_nhg_modify_cb,
			   bgp_nhg_add_nexthop_cb, bgp_nhg_del_nexthop_cb,
			   bgp_nhg_del_cb, NULL);
}

static struct bgp_nhg_cache *bgp_nhg_find_per_id(uint32_t id)
{
	struct bgp_nhg_cache *nhg;

	frr_each (bgp_nhg_cache, &nhg_cache_table, nhg) {
		if (nhg->id == id)
			return nhg;
	}
	return NULL;
}

void bgp_nhg_init(void)
{
	uint32_t id_max;

	id_max = MIN(ZEBRA_NHG_PROTO_SPACING - 1, 16 * 1024);
	bf_init(bgp_nh_id_bitmap, id_max);
	bf_assign_zero_index(bgp_nh_id_bitmap);

	if (BGP_DEBUG(nht, NHT) || BGP_DEBUG(evpn_mh, EVPN_MH_ES))
		zlog_debug("bgp nhg range %u - %u", bgp_nhg_start + 1,
			   bgp_nhg_start + id_max);
	bgp_nhg_group_init();
}

void bgp_nhg_finish(void)
{
	bf_free(bgp_nh_id_bitmap);
}

uint32_t bgp_nhg_id_alloc(void)
{
	uint32_t nhg_id = 0;

	bgp_nhg_zebra_init();
	bf_assign_index(bgp_nh_id_bitmap, nhg_id);
	if (nhg_id)
		nhg_id += bgp_nhg_start;

	return nhg_id;
}

void bgp_nhg_id_free(uint32_t nhg_id)
{
	if (!nhg_id || (nhg_id <= bgp_nhg_start))
		return;

	nhg_id -= bgp_nhg_start;

	bf_release_index(bgp_nh_id_bitmap, nhg_id);
}

int bgp_nhg_cache_compare(const struct bgp_nhg_cache *a,
			  const struct bgp_nhg_cache *b)
{
	int i, ret = 0;

	if (a->flags != b->flags)
		return a->flags - b->flags;

	if (a->nexthop_num != b->nexthop_num)
		return a->nexthop_num - b->nexthop_num;

	for (i = 0; i < a->nexthop_num; i++) {
		ret = zapi_nexthop_cmp(&a->nexthops[i], &b->nexthops[i]);
		if (ret != 0)
			return ret;
	}
	return ret;
}

static void bgp_nhg_add_or_update_nhg(struct bgp_nhg_cache *bgp_nhg)
{
	struct zapi_nhg api_nhg = {};
	int i;
	bool is_valid = true;

	api_nhg.id = bgp_nhg->id;
	if (CHECK_FLAG(bgp_nhg->flags, ZEBRA_FLAG_ALLOW_RECURSION))
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_ALLOW_RECURSION);

	for (i = 0; i < bgp_nhg->nexthop_num; i++) {
		if (api_nhg.nhg_nexthop.nexthop_num >= MULTIPATH_NUM) {
			zlog_warn("%s: number of nexthops greater than max multipath size, truncating",
				  __func__);
			break;
		}
		memcpy(&api_nhg.nhg_nexthop.nexthops[api_nhg.nhg_nexthop.nexthop_num],
		       &bgp_nhg->nexthops[i], sizeof(struct zapi_nexthop));
		api_nhg.nhg_nexthop.nexthop_num++;
	}
	if (api_nhg.nhg_nexthop.nexthop_num == 0) {
		/* assumption that dependent nhg are removed before when id is installed */
		zlog_debug("%s: nhg %u not sent: no valid nexthops", __func__,
			   api_nhg.id);
		is_valid = false;
	}
	if (is_valid)
		zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

struct bgp_nhg_cache *bgp_nhg_new(uint32_t flags, uint16_t nexthop_num,
				  struct zapi_nexthop api_nh[])
{
	struct bgp_nhg_cache *nhg;
	int i;

	nhg = XCALLOC(MTYPE_BGP_NHG_CACHE, sizeof(struct bgp_nhg_cache));
	for (i = 0; i < nexthop_num; i++)
		memcpy(&nhg->nexthops[i], &api_nh[i],
		       sizeof(struct zapi_nexthop));

	nhg->nexthop_num = nexthop_num;
	nhg->flags = flags;

	nhg->id = bgp_nhg_id_alloc();

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP)) {
		zlog_debug("NHG %u: creation", nhg->id);
		bgp_debug_zebra_nh(nhg->nexthops, nexthop_num);
	}

	/* prepare the nexthop */
	bgp_nhg_add_or_update_nhg(nhg);

	LIST_INIT(&(nhg->paths));
	bgp_nhg_cache_add(&nhg_cache_table, nhg);

	return nhg;
}

static void bgp_nhg_free(struct bgp_nhg_cache *nhg)
{
	struct zapi_nhg api_nhg = {};

	api_nhg.id = nhg->id;

	if (api_nhg.id)
		zclient_nhg_send(zclient, ZEBRA_NHG_DEL, &api_nhg);

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP)) {
		zlog_debug("NHG %u: removal", nhg->id);
		bgp_debug_zebra_nh(nhg->nexthops, nhg->nexthop_num);
	}

	bgp_nhg_cache_del(&nhg_cache_table, nhg);
	XFREE(MTYPE_BGP_NHG_CACHE, nhg);
}

void bgp_nhg_path_unlink(struct bgp_path_info *pi)
{
	struct bgp_nhg_cache *nhg;

	if (!pi)
		return;

	nhg = pi->bgp_nhg;

	if (!nhg)
		return;

	LIST_REMOVE(pi, nhg_cache_thread);
	pi->bgp_nhg->path_count--;
	pi->bgp_nhg = NULL;

	if (LIST_EMPTY(&(nhg->paths)))
		bgp_nhg_free(nhg);
}

static void bgp_nhg_group_init(void)
{
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("bgp nexthop group init");

	bgp_nhg_cache_init(&nhg_cache_table);
}

void bgp_nhg_id_set_installed(uint32_t id, bool install)
{
	static struct bgp_nhg_cache *nhg;
	struct bgp_path_info *path;
	struct bgp_table *table;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	if (install == false) {
		if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
			zlog_debug("NHG %u, : ID is uninstalled", nhg->id);
		UNSET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
		return;
	}
	SET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u, : ID is installed, update dependent routes",
			   nhg->id);
	LIST_FOREACH (path, &(nhg->paths), nhg_cache_thread) {
		table = bgp_dest_table(path->net);
		if (table)
			bgp_zebra_announce(path->net,
					   bgp_dest_get_prefix(path->net), path,
					   table->bgp, table->afi, table->safi);
	}
}

void bgp_nhg_id_set_removed(uint32_t id)
{
	static struct bgp_nhg_cache *nhg;

	nhg = bgp_nhg_find_per_id(id);
	if (nhg == NULL)
		return;
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("NHG %u, : ID is uninstalled", nhg->id);
	UNSET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	SET_FLAG(nhg->state, BGP_NHG_STATE_REMOVED);
}

void bgp_nhg_refresh_by_nexthop(struct prefix *p, uint32_t srte_color,
				vrf_id_t vrf_id)
{
	struct bgp_nhg_cache *nhg;
	int i;
	struct zapi_nexthop *zapi_nh;
	bool found;

	frr_each (bgp_nhg_cache, &nhg_cache_table, nhg) {
		found = false;
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED))
			continue;
		if (!CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION))
			continue;
		if ((srte_color &&
		     !CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)) ||
		    (!srte_color &&
		     CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)))
			continue;
		for (i = 0; i < nhg->nexthop_num; i++) {
			zapi_nh = &nhg->nexthops[i];
			if (zapi_nh->type == NEXTHOP_TYPE_IFINDEX ||
			    zapi_nh->type == NEXTHOP_TYPE_BLACKHOLE)
				continue;
			if (srte_color && zapi_nh->srte_color != srte_color)
				continue;
			if (p->family == AF_INET &&
			    (zapi_nh->type == NEXTHOP_TYPE_IPV4 ||
			     zapi_nh->type == NEXTHOP_TYPE_IPV4_IFINDEX) &&
			    IPV4_ADDR_SAME(&zapi_nh->gate.ipv4, &p->u.prefix4))
				found = true;
			else if (p->family == AF_INET6 &&
				 (zapi_nh->type == NEXTHOP_TYPE_IPV6 ||
				  zapi_nh->type == NEXTHOP_TYPE_IPV6_IFINDEX) &&
				 IPV6_ADDR_SAME(&zapi_nh->gate.ipv6,
						&p->u.prefix6))
				found = true;
			if (found) {
				if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
					zlog_debug("NHG %u, VRF %u : IGP change detected with NH %pFX SRTE %u",
						   nhg->id, vrf_id, p,
						   srte_color);
				bgp_nhg_add_or_update_nhg(nhg);
			}
		}
	}

	return;
}
