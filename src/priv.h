/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_PRIV_H
#define _ENBOX_PRIV_H

#include "common.h"

#if defined(CONFIG_ENBOX_TOOL) && defined(CONFIG_ENBOX_ASSERT)

#define __enbox_validate_pwd_export

#else  /* !(defined(CONFIG_ENBOX_TOOL) && defined(CONFIG_ENBOX_ASSERT)) */

#define __enbox_validate_pwd_export __export_intern

#endif /* defined(CONFIG_ENBOX_TOOL) && defined(CONFIG_ENBOX_ASSERT) */

extern int
enbox_validate_pwd(const struct passwd * __restrict pwd, bool allow_root)
	__enbox_nonull(1)
	__enbox_pure
	__enbox_nothrow
	__leaf
	__warn_result
	__enbox_validate_pwd_export;

#if defined(CONFIG_ENBOX_SHOW)

static inline __warn_result
const char *
enbox_get_user_name(uid_t uid)
{
	const struct passwd * pwd;

	pwd = upwd_get_user_byid(uid);

	return pwd ? pwd->pw_name : "??";
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

static inline __warn_result
const char *
enbox_get_group_name(gid_t gid)
{
	const struct group * grp;

	grp = upwd_get_group_byid(gid);

	return grp ? grp->gr_name : "??";
}

#if defined(CONFIG_ENBOX_SHOW)

extern bool
enbox_load_dump(void)
	__enbox_nothrow __leaf __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_SHOW) */

/**
 * @internal
 *
 * Enable process *dumpable* attribute.
 *
 * @see enbox_setup_dump()
 */
#define ENBOX_ENABLE_DUMP  (1)

/**
 * @internal
 *
 * Disable process *dumpable* attribute.
 *
 * @see enbox_setup_dump()
 */
#define ENBOX_DISABLE_DUMP (0)

#if defined(CONFIG_ENBOX_DISABLE_DUMP)

extern void
enbox_setup_dump(bool on)
	__enbox_nothrow __leaf __export_intern;

#else  /* !defined(CONFIG_ENBOX_DISABLE_DUMP) */

static inline
void
enbox_setup_dump(bool on __unused)
{
}

#endif /* defined(CONFIG_ENBOX_DISABLE_DUMP) */

#endif /* _ENBOX_PRIV_H */
