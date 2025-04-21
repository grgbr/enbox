/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_LIB_H
#define _ENBOX_LIB_H

#include "priv.h"
#include "caps.h"
#include <linux/sched.h>
#include <linux/mount.h>

#define ENBOX_VALID_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

/* Mask of inode timestamp related mounting flags. */
#define ENBOX_MOUNT_TIME_FLAGS \
	(MS_LAZYTIME | MS_NOATIME | MS_RELATIME | MS_STRICTATIME | \
	 MS_NODIRATIME)

/* Mask of supported / valid initial mounting flags. */
#define ENBOX_VALID_MOUNT_FLAGS \
	(MS_DIRSYNC | MS_MANDLOCK | MS_NODEV | MS_NOEXEC | MS_NOSUID | \
	 MS_RDONLY | MS_SILENT | MS_SYNCHRONOUS | MS_NOSYMFOLLOW | \
	 ENBOX_MOUNT_TIME_FLAGS)

#define ENBOX_TREE_VALID_FLAGS \
	ENBOX_VALID_MOUNT_FLAGS

#define ENBOX_FILE_VALID_FLAGS \
	(MS_MANDLOCK | MS_NODEV | MS_NOEXEC | MS_NOSUID | \
	 MS_RDONLY | MS_SILENT | MS_SYNCHRONOUS | MS_NOSYMFOLLOW | \
	 MS_LAZYTIME | MS_NOATIME | MS_RELATIME | MS_STRICTATIME)

#define ENBOX_PROC_VALID_FLAGS \
	(MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RDONLY | MS_SILENT | \
	 ENBOX_MOUNT_TIME_FLAGS)

extern int
enbox_validate_mount_time_flags(unsigned long flags)
	__enbox_const __enbox_nothrow __leaf __warn_result __export_intern;

#define ENBOX_ARG_SIZE (1024U)
#define ENBOX_ARGS_MAX (1024U)

extern int
enbox_validate_exec_arg(const char * __restrict arg)
	__enbox_nonull(1) __enbox_pure __enbox_nothrow __leaf __export_intern;

#if defined(CONFIG_ENBOX_ASSERT)

#if defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL)

#define __enbox_validate_export

#else  /* !(defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL)) */

#define __enbox_validate_export __export_intern

#endif /* defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL) */

extern int
enbox_validate_exec(const char * const exec[__restrict_arr])
	__enbox_nonull(1)
	__enbox_pure
	__enbox_nothrow
	__warn_result
	__enbox_validate_export;

extern int
enbox_validate_fds(const int    keep_fds[__restrict_arr], unsigned int nr)
	__enbox_pure
	__enbox_nothrow
	__leaf
	__warn_result
	__enbox_validate_export;

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

static inline __enbox_nonull(1) __const __nothrow
int
enbox_validate_exec(const char * const exec[__restrict_arr] __unused)
{
	return 0;
}

static inline __const __nothrow
int
enbox_validate_fds(const int    keep_fds[__restrict_arr] __unused,
                   unsigned int nr __unused)
{
	return 0;
}

#endif /* defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert_entry(_ent) \
	enbox_assert(upath_validate_path_name((_ent)->path) > 0); \
	enbox_assert((_ent)->type >= 0); \
	enbox_assert((_ent)->type < ENBOX_ENTRY_TYPE_NR)

#define enbox_assert_fsset(_fsset) \
	enbox_assert(_fsset); \
	enbox_assert((_fsset)->nr); \
	enbox_assert((_fsset)->entries)

#define enbox_assert_ids(_ids) \
	enbox_assert(_ids); \
	enbox_assert(!enbox_validate_pwd((_ids)->pwd, true))

#define enbox_assert_jail(_jail) \
	enbox_assert(_jail); \
	enbox_assert(!((_jail)->namespaces & ~ENBOX_VALID_NAMESPACE_FLAGS)); \
	enbox_assert(upath_validate_path_name((_jail)->root_path) > 0); \
	enbox_assert(!(_jail)->fsset.nr || \
	             ({ enbox_assert_fsset(&(_jail)->fsset); true; }))

#define enbox_assert_proc(_proc) \
	enbox_assert(_proc); \
	enbox_assert(!((_proc)->umask & ~((mode_t)ALLPERMS))); \
	enbox_assert(!((_proc)->caps & \
	               ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1))); \
	enbox_assert(!(_proc)->cwd || \
	             (upath_validate_path_name((_proc)->cwd) > 0)); \
	enbox_assert(!enbox_validate_fds((_proc)->fds, (_proc)->fds_nr))

#define enbox_assert_cmd(_cmd) \
	enbox_assert(!enbox_validate_exec(_cmd))

#if defined(CONFIG_ENBOX_PAM)

extern int
_enbox_prep_proc(const struct enbox_proc * __restrict proc,
                 const struct enbox_jail * __restrict jail,
                 gid_t                                gid)
	__enbox_nonull(1) __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_PAM) */

#endif /* _ENBOX_LIB_H */
