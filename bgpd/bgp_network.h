// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP network related header
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_NETWORK_H
#define _QUAGGA_BGP_NETWORK_H

#include "lib/sockopt.h"

#define BGP_SOCKET_SNDBUF_SIZE 65536

struct bgp_listener {
	int fd;
	union sockunion su;
	struct event *event;
	struct bgp *bgp;
	char *name;
};

extern void bgp_dump_listener_info(struct vty *vty);
extern int bgp_socket(struct bgp *bgp, unsigned short port,
		      const char *address);
extern void bgp_close_vrf_socket(struct bgp *bgp);
extern void bgp_close(void);
extern enum connect_result bgp_connect(struct peer_connection *connection);
extern int bgp_getsockname(struct peer_connection *connection);

extern int bgp_md5_set_prefix(struct bgp *bgp, struct prefix *p,
			      const char *password);
extern int bgp_md5_unset_prefix(struct bgp *bgp, struct prefix *p);
extern int bgp_md5_set(struct peer_connection *connection);
extern int bgp_md5_unset(struct peer_connection *connection);
extern int bgp_tcp_ao_set_listener(struct peer_connection *connection);
extern int bgp_tcp_ao_unset(struct peer_connection *connection);
extern int bgp_tcp_ao_key_del(struct peer_connection *connection,
			      const struct bgp_tcp_ao_key *key);
extern int bgp_tcp_ao_key_add(struct peer_connection *connection,
			      const struct bgp_tcp_ao_key *key);
extern int bgp_tcp_ao_set_current_rnext(struct peer_connection *connection,
					struct bgp_tcp_ao_key_list_head *keys);
extern int bgp_tcp_ao_get_kernel_keys(struct peer_connection *connection,
				      struct tcp_ao_key_info **out,
				      uint32_t *nkeys);
extern int bgp_tcp_ao_apply_keys_connection(struct peer_connection *connection,
					    struct bgp_tcp_ao_key_list_head *keys,
					    int set_current_rnext);
extern int bgp_set_socket_ttl(struct peer_connection *connection);
extern int bgp_tcp_mss_set(struct peer *peer);
extern int bgp_update_address(struct interface *ifp, const union sockunion *dst,
			      union sockunion *addr);

#endif /* _QUAGGA_BGP_NETWORK_H */
