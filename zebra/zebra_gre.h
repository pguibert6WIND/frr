/*
 * Zebra GRE structures and definitions
 * These are public definitions referenced by other files.
 * Copyright (C) 2020, 6WIND
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

#ifndef _ZEBRA_GRE_H
#define _ZEBRA_GRE_H

#include <if.h>
#include <zebra.h>

/* GRE interface change flags of interest. */
#define ZEBRA_GREIF_LOCAL_IP_CHANGE     0x1

extern int zebra_gre_if_update(struct interface *ifp, uint16_t chgflags);

/*
 * Handle GRE interface add.
 */
extern int zebra_gre_if_add(struct interface *ifp);

/*
 * Handle GRE interface delete.
 */
extern int zebra_gre_if_del(struct interface *ifp);

extern int zebra_gre_if_up(struct interface *ifp);

extern int zebra_gre_if_down(struct interface *ifp);

#endif /* _ZEBRA_GRE_H */
