/* Zebra Policy Based Routing (PBR) main handling.
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

#include <jhash.h>
#include <hash.h>
#include <json.h>

#include "zebra/zebra_pbr.h"
#include "zebra/rt.h"
#include "zebra/zebra_wrap_script.h"

/* definitions */

/* static function declarations */

/* Private functions */

/* Public functions */
void zebra_pbr_rules_free(void *arg)
{
	struct zebra_pbr_rule *rule;

	rule = (struct zebra_pbr_rule *)arg;

	kernel_del_pbr_rule(rule);
	XFREE(MTYPE_TMP, rule);
}

uint32_t zebra_pbr_rules_hash_key(void *arg)
{
	struct zebra_pbr_rule *rule;
	uint32_t key;

	rule = (struct zebra_pbr_rule *)arg;
	key = jhash_3words(rule->rule.seq, rule->rule.priority,
			   rule->rule.action.table,
			   prefix_hash_key(&rule->rule.filter.src_ip));
	if (rule->ifp)
		key = jhash_1word(rule->ifp->ifindex, key);
	else
		key = jhash_1word(0, key);

	if (rule->rule.filter.fwmark)
		key = jhash_1word(rule->rule.filter.fwmark, key);
	else
		key = jhash_1word(0, key);
	return jhash_3words(rule->rule.filter.src_port,
			    rule->rule.filter.dst_port,
			    prefix_hash_key(&rule->rule.filter.dst_ip),
			    jhash_1word(rule->rule.unique, key));
}

int zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_rule *r1, *r2;

	r1 = (const struct zebra_pbr_rule *)arg1;
	r2 = (const struct zebra_pbr_rule *)arg2;

	if (r1->rule.seq != r2->rule.seq)
		return 0;

	if (r1->rule.priority != r2->rule.priority)
		return 0;

	if (r1->rule.unique != r2->rule.unique)
		return 0;

	if (r1->rule.action.table != r2->rule.action.table)
		return 0;

	if (r1->rule.filter.src_port != r2->rule.filter.src_port)
		return 0;

	if (r1->rule.filter.dst_port != r2->rule.filter.dst_port)
		return 0;

	if (r1->rule.filter.fwmark != r2->rule.filter.fwmark)
		return 0;

	if (!prefix_same(&r1->rule.filter.src_ip, &r2->rule.filter.src_ip))
		return 0;

	if (!prefix_same(&r1->rule.filter.dst_ip, &r2->rule.filter.dst_ip))
		return 0;

	if (r1->ifp != r2->ifp)
		return 0;

	return 1;
}

struct pbr_rule_unique_lookup {
	struct zebra_pbr_rule *rule;
	uint32_t unique;
};

static int pbr_rule_lookup_unique_walker(struct hash_backet *b, void *data)
{
	struct pbr_rule_unique_lookup *pul = data;
	struct zebra_pbr_rule *rule = b->data;

	if (pul->unique == rule->rule.unique) {
		pul->rule = rule;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

static struct zebra_pbr_rule *pbr_rule_lookup_unique(struct zebra_ns *zns,
						     uint32_t unique)
{
	struct pbr_rule_unique_lookup pul;

	pul.unique = unique;
	pul.rule = NULL;
	hash_walk(zns->rules_hash, &pbr_rule_lookup_unique_walker, &pul);

	return pul.rule;
}

void zebra_pbr_ipset_free(void *arg)
{
	struct zebra_pbr_ipset *ipset;
	struct zebra_ns *zns;

	ipset = (struct zebra_pbr_ipset *)arg;
	if (vrf_is_backend_netns())
		zns = zebra_ns_lookup(ipset->vrf_id);
	else
		zns = zebra_ns_lookup(NS_DEFAULT);
	kernel_destroy_pbr_ipset(zns, ipset);
	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_hash_key(void *arg)
{
	struct zebra_pbr_ipset *ipset = (struct zebra_pbr_ipset *)arg;
	uint32_t *pnt = (uint32_t *)&ipset->ipset_name;

	return jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE, 0x63ab42de);
}

int zebra_pbr_ipset_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset *r1, *r2;

	r1 = (const struct zebra_pbr_ipset *)arg1;
	r2 = (const struct zebra_pbr_ipset *)arg2;

	if (r1->type != r2->type)
		return 0;
	if (r1->unique != r2->unique)
		return 0;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return 0;
	return 1;
}

void zebra_pbr_ipset_entry_free(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;
	struct zebra_ns *zns;

	ipset = (struct zebra_pbr_ipset_entry *)arg;
	if (ipset->backpointer && vrf_is_backend_netns()) {
		struct zebra_pbr_ipset *ips = ipset->backpointer;

		zns = zebra_ns_lookup((ns_id_t)ips->vrf_id);
	} else
		zns = zebra_ns_lookup(NS_DEFAULT);
	kernel_del_pbr_ipset_entry(zns, ipset);

	XFREE(MTYPE_TMP, ipset);
}

uint32_t zebra_pbr_ipset_entry_hash_key(void *arg)
{
	struct zebra_pbr_ipset_entry *ipset;
	uint32_t key;

	ipset = (struct zebra_pbr_ipset_entry *)arg;
	key = prefix_hash_key(&ipset->src);
	key = jhash_1word(ipset->unique, key);
	key = jhash_1word(prefix_hash_key(&ipset->dst), key);
	key = jhash(&ipset->dst_port_min, 2, key);
	key = jhash(&ipset->dst_port_max, 2, key);
	key = jhash(&ipset->src_port_min, 2, key);
	key = jhash(&ipset->src_port_max, 2, key);
	key = jhash(&ipset->proto, 1, key);

	return key;
}

int zebra_pbr_ipset_entry_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_ipset_entry *r1, *r2;

	r1 = (const struct zebra_pbr_ipset_entry *)arg1;
	r2 = (const struct zebra_pbr_ipset_entry *)arg2;

	if (r1->unique != r2->unique)
		return 0;

	if (!prefix_same(&r1->src, &r2->src))
		return 0;

	if (!prefix_same(&r1->dst, &r2->dst))
		return 0;

	if (r1->src_port_min != r2->src_port_min)
		return 0;

	if (r1->src_port_max != r2->src_port_max)
		return 0;

	if (r1->dst_port_min != r2->dst_port_min)
		return 0;

	if (r1->dst_port_max != r2->dst_port_max)
		return 0;

	if (r1->proto != r2->proto)
		return 0;
	return 1;
}

void zebra_pbr_iptable_free(void *arg)
{
	struct zebra_pbr_iptable *iptable;
	struct zebra_ns *zns;

	iptable = (struct zebra_pbr_iptable *)arg;
	if (vrf_is_backend_netns())
		zns = zebra_ns_lookup((ns_id_t)iptable->vrf_id);
	else
		zns =  zebra_ns_lookup(NS_DEFAULT);
	kernel_del_pbr_iptable(zns, iptable);

	XFREE(MTYPE_TMP, iptable);
}

uint32_t zebra_pbr_iptable_hash_key(void *arg)
{
	struct zebra_pbr_iptable *iptable = (struct zebra_pbr_iptable *)arg;
	uint32_t *pnt = (uint32_t *)&(iptable->ipset_name);
	uint32_t key;

	key = jhash2(pnt, ZEBRA_IPSET_NAME_HASH_SIZE,
		     0x63ab42de);
	key = jhash_1word(iptable->fwmark, key);
	return jhash_3words(iptable->filter_bm, iptable->type,
			    iptable->unique, key);
}

int zebra_pbr_iptable_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_iptable *r1, *r2;

	r1 = (const struct zebra_pbr_iptable *)arg1;
	r2 = (const struct zebra_pbr_iptable *)arg2;

	if (r1->type != r2->type)
		return 0;
	if (r1->unique != r2->unique)
		return 0;
	if (r1->filter_bm != r2->filter_bm)
		return 0;
	if (r1->fwmark != r2->fwmark)
		return 0;
	if (r1->action != r2->action)
		return 0;
	if (strncmp(r1->ipset_name, r2->ipset_name,
		    ZEBRA_IPSET_NAME_SIZE))
		return 0;
	return 1;
}

static void *pbr_rule_alloc_intern(void *arg)
{
	struct zebra_pbr_rule *zpr;
	struct zebra_pbr_rule *new;

	zpr = (struct zebra_pbr_rule *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(*new));

	memcpy(new, zpr, sizeof(*zpr));

	return new;
}

void zebra_pbr_add_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *unique =
		pbr_rule_lookup_unique(zns, rule->rule.unique);

	(void)hash_get(zns->rules_hash, rule, pbr_rule_alloc_intern);
	kernel_add_pbr_rule(rule);

	/*
	 * Rule Replace semantics, if we have an old, install the
	 * new rule, look above, and then delete the old
	 */
	if (unique)
		zebra_pbr_del_rule(zns, unique);
}

void zebra_pbr_del_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *lookup;

	lookup = hash_lookup(zns->rules_hash, rule);
	kernel_del_pbr_rule(rule);

	if (lookup) {
		hash_release(zns->rules_hash, lookup);
		XFREE(MTYPE_TMP, lookup);
	} else
		zlog_warn("%s: Rule being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

static void zebra_pbr_cleanup_rules(struct hash_backet *b, void *data)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_rule *rule = b->data;
	int *sock = data;

	if (rule->sock == *sock) {
		kernel_del_pbr_rule(rule);
		hash_release(zns->rules_hash, rule);
		XFREE(MTYPE_TMP, rule);
	}
}

static void zebra_pbr_cleanup_ipset(struct hash_backet *b, void *data)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_ipset *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		kernel_destroy_pbr_ipset(zns, ipset);
		hash_release(zns->ipset_hash, ipset);
	}
}

static void zebra_pbr_cleanup_ipset_entry(struct hash_backet *b, void *data)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_ipset_entry *ipset = b->data;
	int *sock = data;

	if (ipset->sock == *sock) {
		kernel_del_pbr_ipset_entry(zns, ipset);
		hash_release(zns->ipset_entry_hash, ipset);
	}
}

static void zebra_pbr_cleanup_iptable(struct hash_backet *b, void *data)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_iptable *iptable = b->data;
	int *sock = data;

	if (iptable->sock == *sock) {
		kernel_del_pbr_iptable(zns, iptable);
		hash_release(zns->iptable_hash, iptable);
	}
}

void zebra_pbr_client_close_cleanup(int sock)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	hash_iterate(zns->rules_hash, zebra_pbr_cleanup_rules, &sock);
	hash_iterate(zns->iptable_hash, zebra_pbr_cleanup_iptable, &sock);
	hash_iterate(zns->ipset_entry_hash, zebra_pbr_cleanup_ipset_entry, &sock);
	hash_iterate(zns->ipset_hash, zebra_pbr_cleanup_ipset, &sock);
}

static void *pbr_ipset_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_pbr_ipset *new;

	zpi = (struct zebra_pbr_ipset *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_ipset));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_create_ipset(struct zebra_ns *zns,
			    struct zebra_pbr_ipset *ipset)
{
	(void)hash_get(zns->ipset_hash, ipset, pbr_ipset_alloc_intern);
	kernel_create_pbr_ipset(zns, ipset);
}

void zebra_pbr_destroy_ipset(struct zebra_ns *zns,
			     struct zebra_pbr_ipset *ipset)
{
	struct zebra_pbr_ipset *lookup;

	lookup = hash_lookup(zns->ipset_hash, ipset);
	kernel_destroy_pbr_ipset(zns, ipset);
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPSet Entry being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

struct pbr_ipset_name_lookup {
	struct zebra_pbr_ipset *ipset;
	char ipset_name[ZEBRA_IPSET_NAME_SIZE];
};

static int zebra_pbr_ipset_pername_walkcb(struct hash_backet *backet, void *arg)
{
	struct pbr_ipset_name_lookup *pinl =
		(struct pbr_ipset_name_lookup *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)backet->data;

	if (!strncmp(pinl->ipset_name, zpi->ipset_name,
		     ZEBRA_IPSET_NAME_SIZE)) {
		pinl->ipset = zpi;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

struct zebra_pbr_ipset *zebra_pbr_lookup_ipset_pername(struct zebra_ns *zns,
						       char *ipsetname)
{
	struct pbr_ipset_name_lookup pinl;
	struct pbr_ipset_name_lookup *ptr = &pinl;

	if (!ipsetname)
		return NULL;
	memset(ptr, 0, sizeof(struct pbr_ipset_name_lookup));
	snprintf((char *)ptr->ipset_name, ZEBRA_IPSET_NAME_SIZE, "%s",
		ipsetname);
	ptr->ipset = NULL;
	hash_walk(zns->ipset_hash, zebra_pbr_ipset_pername_walkcb, ptr);
	return ptr->ipset;
}

static void *pbr_ipset_entry_alloc_intern(void *arg)
{
	struct zebra_pbr_ipset_entry *zpi;
	struct zebra_pbr_ipset_entry *new;

	zpi = (struct zebra_pbr_ipset_entry *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_ipset_entry));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_add_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset)
{
	(void)hash_get(zns->ipset_entry_hash, ipset,
		       pbr_ipset_entry_alloc_intern);
	kernel_add_pbr_ipset_entry(zns, ipset);
}

void zebra_pbr_del_ipset_entry(struct zebra_ns *zns,
			       struct zebra_pbr_ipset_entry *ipset)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zns->ipset_entry_hash, ipset);
	kernel_del_pbr_ipset_entry(zns, ipset);
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPSet being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

static void *pbr_iptable_alloc_intern(void *arg)
{
	struct zebra_pbr_iptable *zpi;
	struct zebra_pbr_iptable *new;

	zpi = (struct zebra_pbr_iptable *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(struct zebra_pbr_iptable));

	memcpy(new, zpi, sizeof(*zpi));

	return new;
}

void zebra_pbr_add_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable)
{
	(void)hash_get(zns->iptable_hash, iptable,
		       pbr_iptable_alloc_intern);
	kernel_add_pbr_iptable(zns, iptable);
}

void zebra_pbr_del_iptable(struct zebra_ns *zns,
			   struct zebra_pbr_iptable *iptable)
{
	struct zebra_pbr_ipset_entry *lookup;

	lookup = hash_lookup(zns->iptable_hash, iptable);
	kernel_del_pbr_iptable(zns, iptable);
	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: IPTable being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
				    enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
		break;
	case SOUTHBOUND_DELETE_FAILURE:
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_add_del_status(struct zebra_pbr_ipset *ipset,
				    enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_ipset_notify_owner(ipset, ZAPI_IPSET_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_ipset_entry_add_del_status(
			struct zebra_pbr_ipset_entry *ipset,
			enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_ipset_entry_notify_owner(ipset,
					       ZAPI_IPSET_ENTRY_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
		break;
	}
}

/*
 * Handle success or failure of ipset (un)install in the kernel.
 */
void kernel_pbr_iptable_add_del_status(struct zebra_pbr_iptable *iptable,
				       enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_iptable_notify_owner(iptable, ZAPI_IPTABLE_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
	case SOUTHBOUND_DELETE_FAILURE:
		/* TODO : handling of delete event */
		break;
	}
}

/*
 * Handle rule delete notification from kernel.
 */
int kernel_pbr_rule_del(struct zebra_pbr_rule *rule)
{
	return 0;
}

struct zebra_pbr_ipset_entry_unique_display {
	struct zebra_pbr_ipset *zpi;
	struct vty *vty;
	struct json_object *json;
};

struct zebra_pbr_env_display {
	struct zebra_ns *zns;
	struct vty *vty;
	struct json_object *json;
};

static const char *zebra_pbr_prefix2str(union prefixconstptr pu, char *str, int size)
{
	const struct prefix *p = pu.p;
	char buf[PREFIX2STR_BUFFER];

	if (p->family == AF_INET && p->prefixlen == IPV4_MAX_PREFIXLEN) {
		snprintf(str, size, "%s", inet_ntop(p->family, &p->u.prefix,
						    buf, PREFIX2STR_BUFFER));
		return str;
	}
	return prefix2str(pu, str, size);
}

static int zebra_pbr_sprint_port(char *str,
				 uint16_t port_min,
				 uint16_t port_max,
				 uint8_t proto)
{
	char *ptr = str;

	ptr += sprintf(ptr, ",");
	if(proto)
		ptr += sprintf(ptr, "%d:", proto);
	else
		ptr += sprintf(ptr, "tcp:"); /* arbitrary */
	if (port_max)
		ptr += sprintf(ptr, "%d-%d", port_min, port_max);
	else
		ptr += sprintf(ptr, "%d", port_min);
	return (int)(ptr - str);
}

static void zebra_pbr_display_port(struct vty *vty, uint32_t filter_bm,
			    uint16_t port_min, uint16_t port_max,
			    uint8_t proto)
{
	if (!(filter_bm & PBR_FILTER_PROTO)) {
		if (port_max)
			vty_out(vty, ":udp/tcp:%d-%d",
				port_min, port_max);
		else
			vty_out(vty, ":udp/tcp:%d",
				port_min);
	} else {
		if (port_max)
			vty_out(vty, ":proto %d:%d-%d",
				proto, port_min, port_max);
		else
			vty_out(vty, ":proto %d:%d",
				proto, port_min);
	}
}

static int zebra_pbr_show_ipset_entry_walkcb(struct hash_backet *backet, void *arg)
{
	struct zebra_pbr_ipset_entry_unique_display *unique =
		(struct zebra_pbr_ipset_entry_unique_display *)arg;
	struct zebra_pbr_ipset *zpi = unique->zpi;
	struct vty *vty = unique->vty;
	struct zebra_pbr_ipset_entry *zpie = (struct zebra_pbr_ipset_entry *)backet->data;
	char json_data_str[100];

	if (zpie->backpointer != zpi)
		return HASHWALK_CONTINUE;

	if (unique->json) {
		/* create data string
		 */
		char *ptr = json_data_str;
		int len = sizeof(json_data_str);

		memset(ptr, 0, sizeof(json_data_str));
		if ((zpi->type == IPSET_NET_NET) ||
		    (zpi->type == IPSET_NET_PORT_NET)) {
			char buf[PREFIX_STRLEN];
			int len_temp;

			zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
			len_temp = snprintf(ptr, len, "%s", buf);
			ptr += len_temp;
			len -= len_temp;
			if (zpie->filter_bm & PBR_FILTER_SRC_PORT) {
				len_temp = zebra_pbr_sprint_port(ptr, zpie->src_port_min,
								 zpie->src_port_max,
								 zpie->proto);
				ptr += len_temp;
				len -= len_temp;
			} else if (zpie->filter_bm & PBR_FILTER_DST_PORT) {
				len_temp = zebra_pbr_sprint_port(ptr, zpie->dst_port_min,
								 zpie->dst_port_max,
								 zpie->proto);
				ptr += len_temp;
				len -= len_temp;
			}
			zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
			len_temp = snprintf(ptr, len, ",%s", buf);
			ptr += len_temp;
			len -= len_temp;
		} else if ((zpi->type == IPSET_NET) ||
			   (zpi->type == IPSET_NET_PORT)) {
			char buf[PREFIX_STRLEN];
			int len_temp;

			if (zpie->filter_bm & PBR_FILTER_SRC_IP)
				zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
			else
				zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
			len_temp = snprintf(ptr, len, "%s", buf);
			ptr += len_temp;
			len -= len_temp;
			if (zpie->filter_bm & PBR_FILTER_SRC_PORT) {
				len_temp = zebra_pbr_sprint_port(ptr, zpie->src_port_min,
								 zpie->src_port_max,
								 zpie->proto);
				ptr += len_temp;
				len -= len_temp;
			} else if (zpie->filter_bm & PBR_FILTER_DST_PORT) {
				len_temp = zebra_pbr_sprint_port(ptr, zpie->dst_port_min,
								 zpie->dst_port_max,
								 zpie->proto);
				ptr += len_temp;
				len -= len_temp;
			}
		}
	}
	if ((zpi->type == IPSET_NET_NET) ||
	    (zpi->type == IPSET_NET_PORT_NET)) {
		char buf[PREFIX_STRLEN];

		zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
		vty_out(vty, "\tfrom %s", buf);
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		vty_out(vty, " to ");
		zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
		vty_out(vty, "%s", buf);
		if (zpie->filter_bm & PBR_FILTER_DST_PORT)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
	} else if ((zpi->type == IPSET_NET) ||
		   (zpi->type == IPSET_NET_PORT)) {
		char buf[PREFIX_STRLEN];

		if (zpie->filter_bm & PBR_FILTER_SRC_IP) {
			zebra_pbr_prefix2str(&(zpie->src), buf, sizeof(buf));
			vty_out(vty, "\tfrom %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_SRC_PORT)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->src_port_min,
					       zpie->src_port_max,
					       zpie->proto);
		if (zpie->filter_bm & PBR_FILTER_DST_IP) {
			zebra_pbr_prefix2str(&(zpie->dst), buf, sizeof(buf));
			vty_out(vty, "\tto %s", buf);
		}
		if (zpie->filter_bm & PBR_FILTER_DST_PORT)
			zebra_pbr_display_port(vty, zpie->filter_bm,
					       zpie->dst_port_min,
					       zpie->dst_port_max,
					       zpie->proto);
	}
	vty_out(vty, " (%u)\n", zpie->unique);
	if (unique->json) {
		int i = 1;
		char buff[10];
		bool found = false;
		struct json_object *json;
		struct json_object *json_data;

		/* get pkts and bytes */
		do {
			json = NULL;
			snprintf(buff, sizeof(buff), "%d", i);
			json_object_object_get_ex(unique->json, buff, &json);
			if (!json)
				return HASHWALK_CONTINUE;
			if (json_object_object_get_ex(json, "data", &json_data)) {
				/* get misc string */
				if (json_object_get_string(json_data) &&
				    strstr(json_object_get_string(json_data),
					   json_data_str))
					found = true;
			}
			if (!found)
				i++;
		} while (found == false);
		if (found && json) {
			struct json_object *json_temp;

			if (json_object_object_get_ex(json, "packets", &json_temp))
				vty_out(vty, "\t packets %s",
					json_object_get_string(json_temp));
			if (json_object_object_get_ex(json, "bytes", &json_temp))
				vty_out(vty, "\t bytes %s",
					json_object_get_string(json_temp));
			vty_out(vty,"\n");
		}
	}
	return HASHWALK_CONTINUE;
}

static int zebra_pbr_get_json_from_ipset(char *ipsetname, struct json_object *list)
{
	const char input[120];
	const char *members = "Members:";
	int ret = 0;

	/*
	 * Name: match0x39ea2d0
	 * Type: hash:net,net
	 * Revision: 2
	 * Header: family inet hashsize 64 maxelem 65536 counters
	 * Size in memory: 824
	 * References: 1
	 * Number of entries: 2
	 * Members:
	 * 1.1.1.2,2.2.2.2 packets 0 bytes 0
	 * 172.17.0.0/24,172.17.0.31 packets 0 bytes 0
	 * =>
	 * "0":{"Name":"match0x39ea2d0", "Type":"hash:net,net",
	 * "Revision":"2","Header":"...", ...,"Number of entries":"2"}
	 * "1":{"data":"1.1.1.2,2.2.2.2","packets":"0","bytes":"0"}
	 * "2":{"data":"172.17.0.0/24,172.17.0.31","packets":"0","bytes":"0"}
	 */
	snprintf((char *)input, sizeof(input),
		 "ipset --list %s", ipsetname);
	ret = hook_call(zebra_pbr_wrap_script_column, input, 1,
			list, members);
	return ret;
}

static int zebra_pbr_show_ipset_walkcb(struct hash_backet *backet, void *arg)
{
	struct zebra_pbr_env_display *uniqueipset =
		(struct zebra_pbr_env_display *)arg;
	struct zebra_pbr_ipset *zpi = (struct zebra_pbr_ipset *)backet->data;
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct vty *vty = uniqueipset->vty;
	struct json_object *list;
	struct zebra_ns *zns = uniqueipset->zns;

	vty_out(vty, "IPset %s type %s\n", zpi->ipset_name,
		netlink_ipset_type2str(zpi->type));
	unique.vty = vty;
	unique.zpi = zpi;
	list = json_object_new_object();
	if (zebra_pbr_get_json_from_ipset(zpi->ipset_name, list) < 0)
		unique.json = NULL;
	else
		unique.json = list;
	hash_walk(zns->ipset_entry_hash, zebra_pbr_show_ipset_entry_walkcb,
		  &unique);
	vty_out(vty, "\n");
	return HASHWALK_CONTINUE;
}

/*
 */
void zebra_pbr_show_ipset_list(struct vty *vty, char *ipsetname)
{
	struct zebra_pbr_ipset *zpi;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_ipset_entry_unique_display unique;
	struct zebra_pbr_env_display uniqueipset;
	struct json_object *list;

	if(ipsetname) {
		zpi = zebra_pbr_lookup_ipset_pername(zns, ipsetname);
		if (!zpi) {
			vty_out(vty, "No IPset %s found\n", ipsetname);
		}
		vty_out(vty, "IPset %s type %s\n", ipsetname,
			netlink_ipset_type2str(zpi->type));

		unique.vty = vty;
		unique.zpi = zpi;
		list = json_object_new_object();
		if (zebra_pbr_get_json_from_ipset(ipsetname, list) < 0)
			unique.json = NULL;
		else
			unique.json = list;
		hash_walk(zns->ipset_entry_hash, zebra_pbr_show_ipset_entry_walkcb,
			  &unique);
		json_object_free(list);
		return;
	}
	uniqueipset.zns = zns;
	uniqueipset.vty = vty;
	hash_walk(zns->ipset_hash, zebra_pbr_show_ipset_walkcb,
		  &uniqueipset);
}

struct pbr_rule_fwmark_lookup {
	struct zebra_pbr_rule *ptr;
	uint32_t fwmark;
};

static int zebra_pbr_rule_lookup_fwmark_walkcb(struct hash_backet *backet, void *arg)
{
	struct pbr_rule_fwmark_lookup *iprule = (struct pbr_rule_fwmark_lookup *)arg;
	struct zebra_pbr_rule *zpr = (struct zebra_pbr_rule *)backet->data;

	if (iprule->fwmark == zpr->rule.filter.fwmark) {
		iprule->ptr = zpr;
		return HASHWALK_ABORT;
	}
	return HASHWALK_CONTINUE;
}

static int zebra_pbr_show_iptable_walkcb(struct hash_backet *backet, void *arg)
{
	struct zebra_pbr_iptable *iptable = (struct zebra_pbr_iptable *)backet->data;
	struct zebra_pbr_env_display *env = (struct zebra_pbr_env_display *)arg;
	struct vty *vty = env->vty;
	struct zebra_ns *zns = env->zns;

	vty_out(vty, "IPtable %s action %s (%u)\n", iptable->ipset_name,
		iptable->action == ZEBRA_IPTABLES_DROP ? "drop" : "redirect",
		iptable->unique);
	if (env->json) {
		struct json *json;
		struct json_object *json_misc = NULL;
		int i = 0;
		bool found = false;
		char buff[10];

		do {
			json_bool ret;

			snprintf(buff, sizeof(buff), "%d", i);
			json = json_object_object_get(env->json, buff);
			if (!json)
				break;
			if (json_object_object_get_ex(json, "data", &json_misc)) {
				/* get misc string */
				if (json_object_get_string(json_misc) &&
				    strstr(json_object_get_string(json_misc),
					   iptable->ipset_name))
					found = true;
			}
			if (!found)
				i++;
		} while (found == false);
		if (found && json) {
			struct json_object *json_temp;

			if (json_object_object_get_ex(json, "pkts", &json_temp))
				vty_out(vty, "\t pkts %s",
					json_object_get_string(json_temp));
			if (json_object_object_get_ex(json, "bytes", &json_temp))
				vty_out(vty, "\t bytes %s",
					json_object_get_string(json_temp));
			vty_out(vty,"\n");
		}
	}
	if (iptable->action != ZEBRA_IPTABLES_DROP) {
		struct pbr_rule_fwmark_lookup prfl;

		prfl.fwmark = iptable->fwmark;
		prfl.ptr = NULL;
		hash_walk(zns->rules_hash, &zebra_pbr_rule_lookup_fwmark_walkcb, &prfl);
		if (prfl.ptr) {
			struct zebra_pbr_rule *zpr = prfl.ptr;
			vty_out(vty, "\t table %u, fwmark %u\n", zpr->rule.action.table,
				prfl.fwmark);
		}
	}
	return HASHWALK_CONTINUE;
}

void zebra_pbr_show_iptable(struct vty *vty)
{
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct zebra_pbr_env_display env;
	struct json_object *list;
	char input[120];
	int ret = 0;

	env.vty = vty;
	env.zns = zns;

	list = json_object_new_object();
	snprintf(input, sizeof(input),
		 "iptables -t mangle -L PREROUTING -v");
	/*
	  pkts bytes target     prot opt in     out     source               destination
	  0     0     MARK       all --  any    any     anywhere             anywhere \
	  match-set match0x44af320 dst,dst MARK set 0x100
	  =>
	  "<IDx>":{ "pkts":"<X>","bytes":"<Y>"",...,"misc":".. match0x<ptr1> ..."},
	  "<IDy>":{ "pkts":"<X>","bytes":"<Y>"",...,"misc":".. match0x<ptr2> ..."},
	 */
	ret = zebra_wrap_script_rows(input, 1, list);
	if (ret < 0)
		env.json = NULL;
	else
		env.json = list;

	hash_walk(zns->iptable_hash, zebra_pbr_show_iptable_walkcb,
		  &env);
	json_object_free(list);
}

