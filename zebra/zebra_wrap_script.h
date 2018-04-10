/*
 * Zebra Wrap Script Definitions
 * Copyright (C) 2018 6WIND
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

#ifndef _ZEBRA_WRAP_SCRIPT_H
#define _ZEBRA_WRAP_SCRIPT_H

#include <zebra.h>

enum zebra_wrap_type_data {
	ZEBRA_WRAP_ROWS_MODE,
	ZEBRA_WRAP_COLUMN_MODE
};

struct json_object;
extern int zebra_wrap_script_rows(const char *script,
				  int begin_at_line,
				  struct json_object *json);

extern int zebra_wrap_script_column(const char *script,
				    int begin_at_line,
				    struct json_object *json,
				    char *switch_to_mode_row_at);

extern int zebra_wrap_script_call_only(const char *script);

extern void zebra_wrap_init(void);

#endif /* _ZEBRA_WRAP_SCRIPT_H */
