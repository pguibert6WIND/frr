// SPDX-License-Identifier: GPL-2.0-or-later
/* L2VPN header
 * Copyright (C) 2025 6WIND
 */
#ifndef _FRR_BGP_L2VPN_H
#define _FRR_BGP_L2VPN_H

extern void bgp_l2vpn_init(void);
extern struct l2vpn_pw *bgp_l2vpn_vpws_evi_match(uint32_t ethtag);
extern uint32_t bgp_evpn_vpws_vni_add(struct bgp *bgp, struct bgpevpn *vpn,
				      vrf_id_t tenant_vrf_id);
uint32_t bgp_evpn_vpws_vni_del(struct bgp *bgp, struct bgpevpn *vpn);
extern uint32_t bgp_l2vpn_vpws_es_add(esi_t esi);
extern void bgp_l2vpn_pw_update_status(struct zapi_pw_status *zpw);
struct zebra_pw;
extern void bgp_l2vpn_vpws_zebra_set(struct bgp *bgp, struct l2vpn_pw *l2vpn_pw, bool on);
extern void bgp_l2vpn_ifp_up(struct interface *ifp, bool up);

#endif /* _FRR_BGP_L2VPN_H */
