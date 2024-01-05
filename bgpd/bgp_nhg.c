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
#include <bgpd/bgp_vty.h>

#include "bgpd/bgp_nhg_clippy.c"

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

static void bgp_nhg_debug_group(uint32_t api_groups[], int count)
{
	int i;

	for (i = 0; i < count; i++)
		zlog_debug("  group [%d]: ID %u", i + 1, api_groups[i]);
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

	if (CHECK_FLAG(a->flags, BGP_NHG_FLAG_TYPE_GROUP)) {
		if (a->groups.group_num != b->groups.group_num)
			return a->groups.group_num - b->groups.group_num;
		for (i = 0; i < a->groups.group_num; i++) {
			if (a->groups.groups[i] != b->groups.groups[i])
				return a->groups.groups[i] - b->groups.groups[i];
		}
		return ret;
	}
	if (a->nexthops.nexthop_num != b->nexthops.nexthop_num)
		return a->nexthops.nexthop_num - b->nexthops.nexthop_num;
	for (i = 0; i < a->nexthops.nexthop_num; i++) {
		ret = zapi_nexthop_cmp(&a->nexthops.nexthops[i],
				       &b->nexthops.nexthops[i]);
		if (ret != 0)
			return ret;
	}
	return ret;
}

static void bgp_nhg_add_or_update_nhg(struct bgp_nhg_cache *bgp_nhg)
{
	struct zapi_nhg api_nhg = {};
	struct bgp_nhg_cache *depend_nhg;
	int i;
	bool is_valid = true;

	api_nhg.id = bgp_nhg->id;
	if (CHECK_FLAG(bgp_nhg->flags, ZEBRA_FLAG_ALLOW_RECURSION))
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_ALLOW_RECURSION);

	if (CHECK_FLAG(bgp_nhg->flags, BGP_NHG_FLAG_TYPE_GROUP)) {
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_TYPE_GROUP);
		SET_FLAG(api_nhg.flags, NEXTHOP_GROUP_PROTOCOL_CONTROLLED);
		for (i = 0; i < bgp_nhg->groups.group_num; i++) {
			if (api_nhg.nhg_grp.nh_grp_count >= MULTIPATH_NUM) {
				zlog_warn("%s: number of nexthops greater than max multipath size, truncating",
					  __func__);
				break;
			}
			depend_nhg =
				bgp_nhg_find_per_id(bgp_nhg->groups.groups[i]);
			if (!depend_nhg ||
			    !CHECK_FLAG(depend_nhg->state,
					BGP_NHG_STATE_INSTALLED)) {
				zlog_warn("%s: nhg %u not sent, dependent NHG ID %u not present or not installed.",
					  __func__, bgp_nhg->id,
					  bgp_nhg->groups.groups[i]);
				continue;
			}
			api_nhg.nhg_grp.id_grp[i] = bgp_nhg->groups.groups[i];
			api_nhg.nhg_grp.nh_grp_count++;
		}
		if (api_nhg.nhg_grp.nh_grp_count == 0) {
			/* assumption that dependent nhg are removed before when id is installed */
			zlog_debug("%s: nhg %u not sent: no valid groups",
				   __func__, api_nhg.id);
			is_valid = false;
		}
	} else {
		for (i = 0; i < bgp_nhg->nexthops.nexthop_num; i++) {
			if (api_nhg.nhg_nexthop.nexthop_num >= MULTIPATH_NUM) {
				zlog_warn("%s: number of nexthops greater than max multipath size, truncating",
					  __func__);
				break;
			}
			memcpy(&api_nhg.nhg_nexthop
					.nexthops[api_nhg.nhg_nexthop.nexthop_num],
			       &bgp_nhg->nexthops.nexthops[i],
			       sizeof(struct zapi_nexthop));
			api_nhg.nhg_nexthop.nexthop_num++;
		}
		if (api_nhg.nhg_nexthop.nexthop_num == 0) {
			/* assumption that dependent nhg are removed before when id is installed */
			zlog_debug("%s: nhg %u not sent: no valid nexthops",
				   __func__, api_nhg.id);
			is_valid = false;
		}
	}
	if (is_valid)
		zclient_nhg_send(zclient, ZEBRA_NHG_ADD, &api_nhg);
}

static void bgp_nhg_add_or_update_dependent_nhg(uint32_t id)
{
	struct bgp_nhg_cache *nhg;
	int i;
	frr_each (bgp_nhg_cache, &nhg_cache_table, nhg) {
		if (!CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP))
			continue;
		for (i = 0; i < nhg->groups.group_num; i++) {
			if (nhg->groups.groups[i] == id)
				bgp_nhg_add_or_update_nhg(nhg);
		}
	}
}

struct bgp_nhg_cache *bgp_nhg_new(uint32_t flags, uint16_t num,
				  struct zapi_nexthop api_nh[],
				  uint32_t api_group[])
{
	struct bgp_nhg_cache *nhg;
	int i;

	nhg = XCALLOC(MTYPE_BGP_NHG_CACHE, sizeof(struct bgp_nhg_cache));
	if (CHECK_FLAG(flags, BGP_NHG_FLAG_TYPE_GROUP)) {
		for (i = 0; i < num; i++)
			nhg->groups.groups[i] = api_group[i];
		nhg->groups.group_num = num;
	} else {
		for (i = 0; i < num; i++)
			memcpy(&nhg->nexthops.nexthops[i], &api_nh[i],
			       sizeof(struct zapi_nexthop));
		nhg->nexthops.nexthop_num = num;
	}
	nhg->flags = flags;

	nhg->id = bgp_nhg_id_alloc();

	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP)) {
		zlog_debug("NHG %u: creation", nhg->id);
		if (CHECK_FLAG(flags, BGP_NHG_FLAG_TYPE_GROUP))
			bgp_nhg_debug_group(nhg->groups.groups, num);
		else
			bgp_debug_zebra_nh(nhg->nexthops.nexthops, num);
	}

	/* prepare the nexthop */
	bgp_nhg_add_or_update_nhg(nhg);

	LIST_INIT(&(nhg->paths));
	LIST_INIT(&(nhg->depends));
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
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP))
			bgp_nhg_debug_group(nhg->groups.groups,
					    nhg->groups.group_num);
		else
			bgp_debug_zebra_nh(nhg->nexthops.nexthops,
					   nhg->nexthops.nexthop_num);
	}

	bgp_nhg_cache_del(&nhg_cache_table, nhg);
	XFREE(MTYPE_BGP_NHG_CACHE, nhg);
}

void bgp_nhg_path_unlink(struct bgp_path_info *pi)
{
	struct bgp_nhg_cache *nhg, *nhg_depend;

	if (!pi)
		return;

	nhg = pi->bgp_nhg;

	if (!nhg)
		return;

	LIST_REMOVE(pi, nhg_cache_thread);
	pi->bgp_nhg->path_count--;
	pi->bgp_nhg = NULL;

	if (LIST_EMPTY(&(nhg->paths))) {
		/* detach nhg_depends */
		LIST_FOREACH (nhg_depend, &(nhg->depends), dependents_thread) {
			LIST_REMOVE(nhg_depend, dependents_thread);
			nhg_depend->parent_nhg->depends_count--;
			nhg_depend->parent_nhg = NULL;
		}
		bgp_nhg_free(nhg);
	}
}

void bgp_nhg_group_link(struct bgp_nhg_cache *nhg[], int nexthop_num,
			struct bgp_nhg_cache *nhg_parent)
{
	int i;

	/* updates NHG dependencies */
	for (i = 0; i < nexthop_num; i++) {
		if (nhg[i]->parent_nhg != nhg_parent) {
			if (nhg[i]->parent_nhg) {
				LIST_REMOVE(nhg[i], dependents_thread);
				nhg[i]->parent_nhg->depends_count--;
				nhg[i]->parent_nhg = NULL;
			}
			nhg[i]->parent_nhg = nhg_parent;
			LIST_INSERT_HEAD(&(nhg_parent->depends), nhg[i],
					 dependents_thread);
			nhg[i]->parent_nhg->depends_count++;
		}
	}
}

static void bgp_nhg_group_init(void)
{
	if (BGP_DEBUG(nexthop_group, NEXTHOP_GROUP))
		zlog_debug("bgp nexthop group init");

	bgp_nhg_cache_init(&nhg_cache_table);
}

/* return the first nexthop-vrf available, VRF_DEFAULT otherwise */
static vrf_id_t bgp_nhg_get_vrfid(struct bgp_nhg_cache *nhg)
{
	vrf_id_t vrf_id = VRF_DEFAULT;
	int i = 0;
	struct bgp_nhg_cache *depend_nhg;

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP)) {
		for (i = 0; i < nhg->groups.group_num; i++) {
			depend_nhg = bgp_nhg_find_per_id(nhg->groups.groups[0]);
			if (depend_nhg)
				return bgp_nhg_get_vrfid(depend_nhg);
		}
		return vrf_id;
	}

	for (i = 0; i < nhg->nexthops.nexthop_num; i++)
		return nhg->nexthops.nexthops[i].vrf_id;

	return vrf_id;
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
		zlog_debug("NHG %u, : ID is installed, update dependent NHGs",
			   nhg->id);
	bgp_nhg_add_or_update_dependent_nhg(id);

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
		zlog_debug("NHG %u, : ID is uninstalled, update dependent NHGs",
			   nhg->id);
	UNSET_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED);
	SET_FLAG(nhg->state, BGP_NHG_STATE_REMOVED);
	bgp_nhg_add_or_update_dependent_nhg(id);
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
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP))
			continue;
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED))
			continue;
		if (!CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION))
			continue;
		if ((srte_color &&
		     !CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)) ||
		    (!srte_color &&
		     CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)))
			continue;
		for (i = 0; i < nhg->nexthops.nexthop_num; i++) {
			zapi_nh = &nhg->nexthops.nexthops[i];
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

static void show_bgp_nhg_id_helper_detail(struct vty *vty,
					  struct bgp_nhg_cache *nhg,
					  json_object *json)
{
	struct bgp_path_info *path;
	json_object *paths = NULL;
	json_object *json_path = NULL;

	if (json)
		paths = json_object_new_array();
	else
		vty_out(vty, "  Paths:\n");
	LIST_FOREACH (path, &(nhg->paths), nhg_cache_thread) {
		if (json)
			json_path = json_object_new_object();
		bgp_path_info_display(path, vty, json_path);
		if (json)
			json_object_array_add(paths, json_path);
	}
	if (json)
		json_object_object_add(json, "paths", paths);
}

static void show_bgp_nhg_id_helper(struct vty *vty, struct bgp_nhg_cache *nhg,
				   json_object *json, bool detail)
{
	struct nexthop *nexthop;
	json_object *json_entry;
	json_object *json_array = NULL;
	int i;
	bool first;

	if (!nhg) {
		if (json)
			json_object_string_add(json, "error", "notFound");
		return;
	}

	if (json) {
		json_object_int_add(json, "nhgId", nhg->id);
		json_object_int_add(json, "flagAllowRecursion",
				    CHECK_FLAG(nhg->flags,
					       BGP_NHG_FLAG_ALLOW_RECURSION));
		json_object_boolean_add(json, "flagAllowRecursion",
					CHECK_FLAG(nhg->flags,
						   BGP_NHG_FLAG_ALLOW_RECURSION));
		json_object_boolean_add(json, "flagInternalBgp",
					CHECK_FLAG(nhg->flags,
						   BGP_NHG_FLAG_IBGP));
		json_object_boolean_add(json, "flagSrtePresence",
					CHECK_FLAG(nhg->flags,
						   BGP_NHG_FLAG_SRTE_PRESENCE));
		json_object_boolean_add(json, "flagTypeGroup",
					CHECK_FLAG(nhg->flags,
						   BGP_NHG_FLAG_TYPE_GROUP));
		json_object_boolean_add(json, "stateInstalled",
					CHECK_FLAG(nhg->state,
						   BGP_NHG_STATE_INSTALLED));
		json_object_boolean_add(json, "stateRemoved",
					CHECK_FLAG(nhg->state,
						   BGP_NHG_STATE_REMOVED));
	} else {
		vty_out(vty, "ID: %u\n", nhg->id);
		vty_out(vty, "  Flags: 0x%04x", nhg->flags);
		first = true;
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_ALLOW_RECURSION)) {
			vty_out(vty, " (allowRecursion");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_IBGP)) {
			vty_out(vty, "%sinternalBgp", first ? " (" : ", ");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_SRTE_PRESENCE)) {
			vty_out(vty, "%sSrtePresence", first ? " (" : ", ");
			first = false;
		}
		if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP))
			vty_out(vty, "%sTypeGroup", first ? " (" : ", ");
		if (nhg->flags)
			vty_out(vty, ")");
		vty_out(vty, "\n");

		vty_out(vty, "  State: 0x%04x", nhg->state);
		first = true;
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_INSTALLED)) {
			vty_out(vty, " (Installed");
			first = false;
		}
		if (CHECK_FLAG(nhg->state, BGP_NHG_STATE_REMOVED)) {
			vty_out(vty, "%sRemoved", first ? " (" : ", ");
			first = false;
		}
		if (nhg->state)
			vty_out(vty, ")");
		vty_out(vty, "\n");
	}

	if (CHECK_FLAG(nhg->flags, BGP_NHG_FLAG_TYPE_GROUP)) {
		if (nhg->groups.group_num && json)
			json_array = json_object_new_array();
		for (i = 0; i < nhg->groups.group_num; i++) {
			if (json) {
				json_entry = json_object_new_object();
				json_object_int_add(json_entry, "Id",
						    nhg->groups.groups[i]);
				json_object_array_add(json_array, json_entry);
			} else
				vty_out(vty, "       ID %u\n",
					nhg->groups.groups[i]);
		}
		if (json_array)
			json_object_object_add(json, "groups", json_array);
		if (nhg->depends_count) {
			if (json) {
				json_object_int_add(json, "dependsCount",
						    nhg->depends_count);
			} else {
				vty_out(vty, "          depends count %u\n",
					nhg->depends_count);
			}
		}
		if (detail)
			show_bgp_nhg_id_helper_detail(vty, nhg, json);
		return;
	}

	if (nhg->nexthops.nexthop_num && json)
		json_array = json_object_new_array();

	for (i = 0; i < nhg->nexthops.nexthop_num; i++) {
		nexthop = nexthop_from_zapi_nexthop(&nhg->nexthops.nexthops[i]);
		if (json) {
			json_entry = json_object_new_object();
			nexthop_json_helper(json_entry, nexthop, true);
			json_object_string_add(json_entry, "vrf",
					       vrf_id_to_name(nexthop->vrf_id));
			json_object_array_add(json_array, json_entry);
		} else {
			if (!CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				vty_out(vty, "          ");
			else
				/* Make recursive nexthops a bit more clear */
				vty_out(vty, "       ");
			nexthop_vty_helper(vty, nexthop, true);
			vty_out(vty, "\n");
		}
		nexthops_free(nexthop);
	}
	if (json_array)
		json_object_object_add(json, "nexthops", json_array);

	if (nhg->parent_nhg) {
		if (json) {
			json_object_int_add(json, "parentId",
					    nhg->parent_nhg->id);
		} else {
			vty_out(vty, "          parent ID %u\n",
				nhg->parent_nhg->id);
		}
	}

	if (detail)
		show_bgp_nhg_id_helper_detail(vty, nhg, json);
}

DEFPY (show_ip_bgp_nhg,
       show_ip_bgp_nhg_cmd,
       "show [ip] bgp [vrf <NAME$vrf_name|all$vrf_all>] nexthop-group [<(0-4294967295)>$id] [detail$detail] [json$uj]",
       SHOW_STR
       IP_STR
       BGP_STR
       VRF_FULL_CMD_HELP_STR
       "BGP nexthop-group table\n"
       "Nexthop Group ID\n"
       "Show detailed information\n"
       JSON_STR)
{
	json_object *json = NULL;
	json_object *json_list = NULL;
	struct vrf *vrf = NULL;
	static struct bgp_nhg_cache *nhg;

	if (id) {
		nhg = bgp_nhg_find_per_id(id);
		if (uj)
			json = json_object_new_object();
		show_bgp_nhg_id_helper(vty, nhg, json, !!detail);
		if (json)
			vty_json(vty, json);
		return CMD_SUCCESS;
	}

	if (vrf_is_backend_netns() && (vrf_name || vrf_all)) {
		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty,
				"VRF subcommand does not make any sense in netns based vrf's\n");
		return CMD_WARNING;
	}
	if (vrf_name)
		vrf = vrf_lookup_by_name(vrf_name);

	if (uj)
		json_list = json_object_new_array();

	frr_each (bgp_nhg_cache, &nhg_cache_table, nhg) {
		if (json_list)
			json = json_object_new_object();
		if (vrf && vrf->vrf_id != bgp_nhg_get_vrfid(nhg))
			continue;
		show_bgp_nhg_id_helper(vty, nhg, json, !!detail);
		if (json_list)
			json_object_array_add(json_list, json);
	}
	if (json_list)
		vty_json(vty, json_list);
	return CMD_SUCCESS;
}


void bgp_nhg_vty_init(void)
{
	install_element(VIEW_NODE, &show_ip_bgp_nhg_cmd);
}
