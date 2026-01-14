// SPDX-License-Identifier: GPL-2.0-or-later
/* L2-VPN File
 * Copyright (C) 2025 6WIND
 *
 * This file is part of FRRouting
 */
#include "lib/zebra.h"
#include "lib/l2vpn.h"

#include "zebra/zebra_pw.h"

#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_l2vpn.h"
#include "bgp_evpn.h"
#include "bgpd/bgpd.h"

static void bgp_l2vpn_vpws_run(struct l2vpn_pw *pw);
void bgp_l2vpn_vpws_local_withdraw(struct bgp *bgp, struct l2vpn_pw *l2vpn_pw,
				   struct bgpevpn *vpn);
static bool is_l2vpn_vpws_ready(struct bgp *bgp, struct l2vpn *l2vpn,
				struct l2vpn_pw *l2vpn_pw, const char **pmsg);
void bgp_pw2zpw(struct l2vpn_pw *pw, struct zapi_pw *zpw);
static bool bgp_l2vpn_vpws_zebra_add(struct l2vpn_pw *l2vpn_pw, bool add);

extern struct zclient *bgp_zclient;

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance
 */
static void bgp_l2vpn_entry_added(const char *l2vpn_name)
{
	/* XXX handle l2vpn entry add */
	/* bridge-interface and member-interface must form an EVPN VNI notified by ZEBRA_VNI_ADD message */
	struct l2vpn *l2vpn;

	l2vpn = l2vpn_find(&l2vpn_tree_config, l2vpn_name, L2VPN_TYPE_VPWS);
	if (!l2vpn)
		return;

	l2vpn->pw_type = PW_TYPE_ETHERNET_TAGGED;
}

static void bgp_l2vpn_entry_deleted(struct l2vpn *l2vpn)
{
	struct bgpevpn *vpn;
	struct l2vpn_pw *l2vpn_pw, *l2vpn_pw_iter;
	struct bgp *bgp = bgp_get_evpn();

	if (l2vpn->type != L2VPN_TYPE_VPWS)
		return;

	if (!bgp)
		return;


	RB_FOREACH_SAFE (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw_iter) {
		vpn = bgp_evpn_lookup_vni(bgp, l2vpn_pw->vni);
		if (!vpn)
			continue;
		bgp_l2vpn_vpws_zebra_add(l2vpn_pw, false);
		bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_pw, vpn);
		l2vpn_pw->enabled = false;

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw);
		RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw);
		UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);
	}

}

/*
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/mtu
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/pw-type
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/pw-status
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/control-word
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn/evi
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn/local-ac-id
 * XPath: /frr-l2vpn:l2vpn/l2vpn-instance/member-pseudowire/neighbor-evpn/remote-ac-id
 */
static void bgp_l2vpn_entry_event(struct l2vpn_pw *l2vpn_pw)
{
	const char *pmsg;
	bool running_change;
	struct bgpevpn *vpn;
	struct bgp *bgp = bgp_get_evpn();
	struct l2vpn *l2vpn = l2vpn_pw->l2vpn;

	if (l2vpn->type != L2VPN_TYPE_VPWS)
		return;

	if (!bgp)
		return;

	running_change = RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw) ? true : false;

	/* Try move inactive pw to active */
	if (!running_change) {
		if (!is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_pw, &pmsg)) {
			if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
				zlog_debug("%s: VPWS local-ac %u remote-ac %u no ready, reason: %s",
					   __func__, l2vpn_pw->local_ac_id, l2vpn_pw->remote_ac_id,
					   pmsg);
			return;
		}

		RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw);
		RB_INSERT(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw);
		bgp_l2vpn_vpws_zebra_add(l2vpn_pw, true);
		l2vpn_pw->local_status = PW_LOCAL_TX_FAULT;
		l2vpn_pw->remote_status = PW_NOT_FORWARDING;

		return;
	}

	/* Update running pw */
	if (l2vpn_pw->enabled && is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_pw, &pmsg))
		return;

	RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw);
	RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw);

	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_pw->vni);
	bgp_l2vpn_vpws_zebra_add(l2vpn_pw, false);
	bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_pw, vpn);
}

void bgp_l2vpn_vpws_zebra_set(struct bgp *bgp, struct l2vpn_pw *l2vpn_pw, bool on)
{
	struct zapi_pw zpw;
	struct interface *ifp;

	bgp_pw2zpw(l2vpn_pw, &zpw);

	if (!on) {
		zebra_send_pw(bgp_zclient, ZEBRA_PW_UNSET, &zpw);
		l2vpn_pw->remote_status = PW_NOT_FORWARDING;
		l2vpn_pw->reason = F_PW_REMOTE_NOT_FWD;

		return;
	}

	ifp = if_lookup_by_index(l2vpn_pw->ifindex, bgp->vrf_id);
	if (l2vpn_pw->remote_mtu != ifp->mtu && !l2vpn_pw->ignore_mtu_mismatch) {
		l2vpn_pw->remote_status = PW_NOT_FORWARDING;
		l2vpn_pw->reason = F_PW_MTU_MISMATCH;

		return;
	}

	if (zebra_send_pw(bgp_zclient, ZEBRA_PW_SET, &zpw) == ZCLIENT_SEND_FAILURE) {
		l2vpn_pw->remote_status = PW_NOT_FORWARDING;
		l2vpn_pw->reason = F_PW_LOCAL_NOT_FWD;
	} else {
		l2vpn_pw->remote_status = PW_FORWARDING;
		l2vpn_pw->reason = F_PW_NO_ERR;
	}
}

static bool bgp_l2vpn_vpws_zebra_add(struct l2vpn_pw *l2vpn_pw, bool add)
{
	struct zapi_pw zpw;
	zebra_message_types_t m_type;

	m_type = add ? ZEBRA_PW_ADD : ZEBRA_PW_DELETE;

	bgp_pw2zpw(l2vpn_pw, &zpw);

	return zebra_send_pw(bgp_zclient, m_type, &zpw) == ZCLIENT_SEND_FAILURE;
}

void bgp_pw2zpw(struct l2vpn_pw *pw, struct zapi_pw *zpw)
{
	memset(zpw, 0, sizeof(*zpw));
	strlcpy(zpw->ifname, pw->ifname, sizeof(zpw->ifname));
	zpw->ifindex = pw->ifindex;
	zpw->type = pw->l2vpn->pw_type;
	zpw->af = AF_INET;
	zpw->local_label = MPLS_INVALID_LABEL;
	zpw->remote_label = MPLS_INVALID_LABEL;
	zpw->nexthop.ipv4 = pw->addr.ipv4;
	if (CHECK_FLAG(pw->flags, F_PW_CWORD))
		zpw->flags = F_PSEUDOWIRE_CWORD;
	zpw->data.bgp.vni = pw->vni;
	strlcpy(zpw->data.bgp.local_ac, pw->local_ac, IFNAMSIZ);
	strlcpy(zpw->data.bgp.vpn_name, pw->l2vpn->name,
	    sizeof(zpw->data.bgp.vpn_name));
}

void bgp_l2vpn_init(void)
{
	l2vpn_init();
	l2vpn_register_hook(bgp_l2vpn_entry_added, bgp_l2vpn_entry_deleted, bgp_l2vpn_entry_event,
			    NULL);
}

static bool is_l2vpn_vpws_ready(struct bgp *bgp, struct l2vpn *l2vpn,
				struct l2vpn_pw *l2vpn_pw, const char **pmsg)
{
	struct bgpevpn *vpn;
	struct interface *ifp;

	if (!l2vpn_pw->enabled) {
		*pmsg = "status disabled";
		return false;
	}

	if (!l2vpn_pw->evi) {
		*pmsg = "Missing EVPN instance identifier";
		return false;
	}

	if (!l2vpn_pw->local_ac_id || !l2vpn_pw->remote_ac_id) {
		*pmsg = "Missing local/remote ac id";
		return false;
	}

	if (!l2vpn_pw->vni) {
		*pmsg = "Missing BGP EVPN VNI config";
		return false;
	}

	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_pw->vni);
	if (!vpn) {
		*pmsg = "Can not find VPN for vni";
		return false;
	}
	l2vpn->br_ifindex = vpn->svi_ifindex;


	ifp = if_lookup_by_name(l2vpn_pw->ifname, bgp->vrf_id);
	if (!ifp) {
		*pmsg = "Pseudowire interface not found";
		return false;
	}
	l2vpn_pw->ifindex = ifp->ifindex;

	return true;
}

static void bgp_l2vpn_vpws_run(struct l2vpn_pw *l2vpn_pw)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp_evpn_es *es;
	struct ecommunity_val eval;
	struct bgp_interface *binfo;
	struct interface *ifp, *local_ifp;
	struct bgp_evpn_es_evi *evi_match;
	struct bgp_evpn_es_evi_vtep *es_evi_vtep;

	bgp = bgp_get_evpn();
	vpn = bgp_evpn_lookup_vni(bgp, l2vpn_pw->vni);
	ifp = if_lookup_by_name(l2vpn_pw->ifname, bgp->vrf_id);

	if (!CHECK_FLAG(vpn->flags, VNI_FLAG_VPWS)) {
		delete_routes_for_vni(bgp, vpn);
		SET_FLAG(vpn->flags, VNI_FLAG_VPWS);
	}

	encode_l2attr_extcomm(&eval, ifp->mtu, 0);
	if (!memcmp(&l2vpn_pw->esi, zero_esi, sizeof(esi_t))) {
		es = bgp_evpn_es_find(&l2vpn_pw->esi);
		if (!es) {
			es = bgp_evpn_es_new(bgp, zero_esi);
			bgp_evpn_es_local_info_set(bgp, es);
		}
		SET_FLAG(es->flags, BGP_EVPNES_ADV_EVI);
		local_ifp = if_lookup_by_name(l2vpn_pw->local_ac, bgp->vrf_id);
		if (!local_ifp) {
			if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
				zlog_debug("VPWS: can not find single homed interface %s",
					   local_ifp->name);

			return;
		}
		binfo = local_ifp->info;
		SET_FLAG(binfo->flags, BGP_INTERFACE_EVPN_SINGLE_HOMED);
		if (!if_is_operative(local_ifp)) {
			if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
				zlog_debug("VPWS: single homed interface %s is not active",
					   local_ifp->name);

			return;
		}

		bgp_evpn_local_es_evi_add(bgp, &l2vpn_pw->esi, vpn->vni, l2vpn_pw->evi,
					  &eval);
	} else {
		es = bgp_evpn_es_find(&l2vpn_pw->esi);
		if (!es || bgp_evpn_local_es_is_active(es)) {
			if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
				zlog_debug("VPWS: multihoming interface %s is not active",
					   ifp->name);

			return;
		}
		/* TODO */
	}
	SET_FLAG(l2vpn_pw->flags, F_PW_SEND_REMOTE);

	evi_match = bgp_evpn_es_evi_find(es, vpn, l2vpn_pw->evi);
	if (!evi_match || !CHECK_FLAG(evi_match->flags, BGP_EVPNES_EVI_LOCAL)) {
		UNSET_FLAG(l2vpn_pw->flags, F_PW_SEND_REMOTE);
		return;
	}

	if (!CHECK_FLAG(evi_match->flags, BGP_EVPNES_EVI_REMOTE)) {
		l2vpn_pw->reason = F_PW_NO_REMOTE_AD;
		return;
	}

	if (listcount(evi_match->es_evi_vtep_list) > 1) {
		l2vpn_pw->reason = F_PW_AD_MISMATCH;
		return;
	}

	es_evi_vtep = listgetdata(listhead(evi_match->es_evi_vtep_list));
	IPV4_ADDR_COPY(&l2vpn_pw->addr.ipv4, &es_evi_vtep->vtep_ip);
	IPV4_ADDR_COPY(&l2vpn_pw->lsr_id, &es_evi_vtep->vtep_ip);
	build_evpn_type1_prefix(&p, evi_match->eth_tag, &evi_match->es->esi,
				es_evi_vtep->vtep_ip);

	bgp_l2vpn_vpws_zebra_set(bgp, l2vpn_pw, true);
}

void bgp_l2vpn_vpws_local_withdraw(struct bgp *bgp, struct l2vpn_pw *l2vpn_pw,
				   struct bgpevpn *vpn)
{
	struct bgp_evpn_es *es;
	struct bgp_evpn_es_evi *es_evi;

	UNSET_FLAG(l2vpn_pw->flags, F_PW_SEND_REMOTE);
	es = bgp_evpn_es_find(&l2vpn_pw->esi);
	if (!es)
		return;
	es_evi = bgp_evpn_es_evi_find(es, vpn, l2vpn_pw->evi);
	if (!es_evi)
		return;

	bgp_evpn_local_es_evi_do_del(es_evi);
}

struct l2vpn_pw *bgp_l2vpn_vpws_evi_match(uint32_t ethtag)
{
	struct l2vpn *l2vpn;
	struct l2vpn_pw *l2vpn_pw;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree) {
			if (l2vpn_pw->evi == ethtag)
				return l2vpn_pw;
		}
	}

	return NULL;
}

uint32_t bgp_l2vpn_vpws_es_add(esi_t esi)
{
	uint32_t count = 0;
	struct l2vpn *l2vpn;
	struct l2vpn_pw *l2vpn_pw;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree) {
			if (!memcmp(&l2vpn_pw->esi, &esi, sizeof(esi_t))) {
				bgp_l2vpn_vpws_run(l2vpn_pw);
				count++;
			}
		}
	}

	return count;
}

uint32_t bgp_evpn_vpws_vni_add(struct bgp *bgp, struct bgpevpn *vpn,
			       vrf_id_t tenant_vrf_id)
{
	const char *pmsg;
	uint32_t count = 0;
	struct l2vpn *l2vpn;
	struct l2vpn_pw *l2vpn_pw, *l2vpn_pw_nxt;

	if (tenant_vrf_id != bgp->vrf_id)
		return 0;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH_SAFE (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw_nxt) {
			if (vpn->vni != l2vpn_pw->vni)
				continue;

			if (vpn->number_ac != 1) {
				if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
					zlog_debug("%s: VPWS local-ac %u, remote-ac %u no ready, reason: invalid AC count %u",
						   __func__, l2vpn_pw->local_ac_id,
						   l2vpn_pw->remote_ac_id, vpn->number_ac);
				if (CHECK_FLAG(vpn->flags, VNI_FLAG_VPWS))
					count++;
				UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);
				/* VNI changed, PW local status forced to FAULT */
				l2vpn_pw->local_status = PW_LOCAL_TX_FAULT;
				continue;
			}
			if (!CHECK_FLAG(vpn->flags, VNI_FLAG_VPWS)) {
				count++;
				SET_FLAG(vpn->flags, VNI_FLAG_VPWS);
				/* check if PW local_status can be refreshed */
				bgp_l2vpn_vpws_run(l2vpn_pw);
			}
		}

		RB_FOREACH_SAFE (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw_nxt) {
			if (vpn->vni != l2vpn_pw->vni)
				continue;

			if (!l2vpn_pw->enabled)
				continue;

			if (vpn->number_ac != 1) {
				if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
					zlog_debug("%s: VPWS local-ac %u, remote-ac %u no ready, reason: invalid AC count %u",
						   __func__, l2vpn_pw->local_ac_id,
						   l2vpn_pw->remote_ac_id, vpn->number_ac);
				/* VNI changed, PW local status forced to FAULT */
				l2vpn_pw->local_status = PW_LOCAL_TX_FAULT;
				continue;
			}

			SET_FLAG(vpn->flags, VNI_FLAG_VPWS);

			if (!is_l2vpn_vpws_ready(bgp, l2vpn, l2vpn_pw, &pmsg)) {
				if (BGP_DEBUG(l2vpn, PSEUDOWIRE))
					zlog_debug("%s: VPWS local-ac %u, remote-ac %u no ready, reason: %s",
						   __func__, l2vpn_pw->local_ac_id,
						   l2vpn_pw->remote_ac_id, pmsg);
				continue;
			}

			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw);
			l2vpn_pw->local_status = PW_LOCAL_TX_FAULT;
			l2vpn_pw->remote_status = PW_NOT_FORWARDING;
			bgp_l2vpn_vpws_zebra_add(l2vpn_pw, true);
			count++;
		}
	}
	
	return count;
}

uint32_t bgp_evpn_vpws_vni_del(struct bgp *bgp, struct bgpevpn *vpn)
{
	uint32_t count = 0;
	struct l2vpn *l2vpn;
	struct l2vpn_pw *l2vpn_pw, *l2vpn_pw_nxt;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		UNSET_FLAG(vpn->flags, VNI_FLAG_VPWS);
		RB_FOREACH_SAFE (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw_nxt) {
			if (vpn->vni != l2vpn_pw->vni)
				continue;

			if (!l2vpn_pw->enabled)
				continue;

			bgp_l2vpn_vpws_zebra_add(l2vpn_pw, false);
			bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_pw, vpn);
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, l2vpn_pw);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, l2vpn_pw);
			count++;
		}
	}

	return count;
}

static void bgp_l2vpn_vpws_status_change(struct l2vpn_pw *l2vpn_pw, int status)
{
	char buf[ESI_STR_LEN];

	if (BGP_DEBUG(l2vpn, PSEUDOWIRE)) {
		esi_to_str(&l2vpn_pw->esi, buf, ESI_STR_LEN);
		zlog_debug("BGP VPWS: EVI %u esi %s switch status from %d to %d",
			   l2vpn_pw->evi, buf, l2vpn_pw->local_status, status);
	}

	if (l2vpn_pw->local_status == PW_LOCAL_TX_FAULT)
		bgp_l2vpn_vpws_run(l2vpn_pw);
}

void bgp_l2vpn_pw_update_status(struct zapi_pw_status *zpw) {
	struct l2vpn *l2vpn;
	struct l2vpn_pw *l2vpn_pw, s;

	strlcpy(s.ifname, zpw->ifname, IFNAMSIZ);
	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		l2vpn_pw = RB_FIND(l2vpn_pw_head, &l2vpn->pw_tree, &s);
		if (l2vpn_pw) {
			memcpy(&l2vpn_pw->esi, &zpw->esi, sizeof(esi_t));
			strlcpy(l2vpn_pw->local_ac, zpw->local_ac, IFNAMSIZ);
			if (l2vpn_pw->local_status != zpw->status)
				bgp_l2vpn_vpws_status_change(l2vpn_pw, zpw->status);

			l2vpn_pw->local_status = zpw->status;
		}
	}
}

void bgp_l2vpn_ifp_up(struct interface *ifp, bool up)
{
	struct l2vpn *l2vpn;
	struct bgpevpn *vpn;
	struct l2vpn_pw *l2vpn_pw;
	struct bgp *bgp = bgp_get_evpn();

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn->type != L2VPN_TYPE_VPWS)
			continue;

		RB_FOREACH (l2vpn_pw, l2vpn_pw_head, &l2vpn->pw_tree) {
			vpn = bgp_evpn_lookup_vni(bgp, l2vpn_pw->vni);
			if (!vpn)
				continue;
			if (!strcmp(l2vpn_pw->local_ac, ifp->name)) {
				if (up) {
					bgp_l2vpn_vpws_run(l2vpn_pw);
				} else {
					bgp_l2vpn_vpws_zebra_set(bgp, l2vpn_pw, up);
					l2vpn_pw->local_status = PW_LOCAL_TX_FAULT;
					bgp_l2vpn_vpws_local_withdraw(bgp, l2vpn_pw, vpn);
				}

				return;
			}
		}
	}
}
