/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_CONF_H
#define _ENBOX_CONF_H

#include "lib.h"
#include <libconfig.h>

#define ENBOX_MAKE_LIBCONFIG_VERS(_maj, _min, _rev) \
	(((_maj) << 16) | ((_min) << 8) | _rev)

#define ENBOX_LIBCONFIG_VERS \
	ENBOX_MAKE_LIBCONFIG_VERS(LIBCONFIG_VER_MAJOR, \
	                          LIBCONFIG_VER_MINOR, \
	                          LIBCONFIG_VER_REVISION)

#if ENBOX_LIBCONFIG_VERS < ENBOX_MAKE_LIBCONFIG_VERS(1, 6, 0)
#error Libconfig library too old (revision 1.6.0 or later required)
#endif

struct enbox_conf {
	struct enbox_fsset * host;
	struct enbox_jail *  jail;
	struct enbox_proc *  proc;
        const char **        cmd;
	config_t             lib;
};

#define enbox_assert_conf(_conf) \
	enbox_assert(_conf); \
	enbox_assert(!(_conf)->jail || (_conf)->proc); \
	enbox_assert(!(_conf)->cmd || (_conf)->proc); \
	enbox_assert(!(_conf)->host || \
	             ({ enbox_assert_fsset((_conf)->host); true; })); \
	enbox_assert(!(_conf)->jail || \
	             ({ enbox_assert_jail((_conf)->jail); true; })); \
	enbox_assert(!(_conf)->proc || \
	             ({ enbox_assert_proc((_conf)->proc); true; })); \
	enbox_assert(!(_conf)->cmd || \
	             ({ enbox_assert_cmd((_conf)->cmd); true; }))

#if defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL)

extern const struct enbox_flag_desc enbox_mount_flag_descs[];
extern const struct enbox_flag_desc enbox_namespace_descs[];

#endif /* defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL) */

#endif /* _ENBOX_CONF_H */
