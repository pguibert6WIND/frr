/*
 * Zebra GRE
 * Copyright (C) 2020 6WIND
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
#include <if.h>

#include "zebra/debug.h"
#include <zebra/zebra_gre.h>


/* definitions */

/*
 * Handle GRE interface update - change to tunnel IP
 */
int zebra_gre_if_update(struct interface *ifp, uint16_t chgflags)
{
	if (IS_ZEBRA_DEBUG_GRE) {
		zlog_debug("%s: interface %s IP address changed",
			   __PRETTY_FUNCTION__,
			   ifp->name);
	}
	return 0;
}

/*
 * Handle GRE interface add.
 */
int zebra_gre_if_add(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_GRE) {
		zlog_debug("%s: VRF %u, interface %s added",
			   __PRETTY_FUNCTION__,
			   ifp->vrf_id,
			   ifp->name);
	}
	return 0;
}

/*
 * Handle GRE interface delete.
 */
int zebra_gre_if_del(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_GRE) {
		zlog_debug("%s: VRF %u, interface %s removed",
			   __PRETTY_FUNCTION__,
			   ifp->vrf_id,
			   ifp->name);
	}
	return 0;
}

/*
 * Handle GRE interface up - update NHRP if required.
 */
int zebra_gre_if_up(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_GRE) {
		zlog_debug("%s: VRF %u, interface %s up",
			   __PRETTY_FUNCTION__,
			   ifp->vrf_id,
			   ifp->name);
	}
	return 0;
}

/*
 * Handle GRE interface down
 */
int zebra_gre_if_down(struct interface *ifp)
{
	if (IS_ZEBRA_DEBUG_GRE) {
		zlog_debug("%s: VRF %u, interface %s down",
			   __PRETTY_FUNCTION__,
			   ifp->vrf_id,
			   ifp->name);
	}
	return 0;
}
