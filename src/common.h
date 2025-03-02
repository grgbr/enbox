/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_COMMON_H
#define _ENBOX_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include "enbox/enbox.h"
#include <stroll/cdefs.h>
#include <elog/elog.h>
#include <libconfig.h>
#include <sys/mount.h>
#include <linux/sched.h>

#define ENBOX_MAKE_LIBCONFIG_VERS(_maj, _min, _rev) \
	(((_maj) << 16) | ((_min) << 8) | _rev)

#define ENBOX_LIBCONFIG_VERS \
	ENBOX_MAKE_LIBCONFIG_VERS(LIBCONFIG_VER_MAJOR, \
	                          LIBCONFIG_VER_MINOR, \
	                          LIBCONFIG_VER_REVISION)

#if ENBOX_LIBCONFIG_VERS < ENBOX_MAKE_LIBCONFIG_VERS(1, 6, 0)
#error Libconfig library too old (revision 1.6.0 or later required)
#endif

/*
 * Declare a symbol as unused when Enbox is built with verbose support disabled.
 * This prevents GCC from emitting a warning when a variable is only used for
 * outputting messages which are not compiled-in when CONFIG_ENBOX_VERBOSE is
 * off.
 */
#if defined(CONFIG_ENBOX_VERBOSE)

#define __enbox_terse_unused

#else  /* !defined(CONFIG_ENBOX_VERBOSE) */

#define __enbox_terse_unused \
	__unused

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_assert_entry(_ent) \
	enbox_assert(upath_validate_path_name((_ent)->path) > 0); \
	enbox_assert((_ent)->type >= 0); \
	enbox_assert((_ent)->type < ENBOX_ENTRY_TYPE_NR)

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

struct enbox_flag_desc {
	const char *  kword;
	size_t        len;
	unsigned long value;
};

#define ENBOX_INIT_FLAG_DESC(_kword, _value) \
	{ \
		.kword = _kword, \
		.len =  sizeof(_kword) - 1, \
		.value = _value \
	}

#if defined(CONFIG_ENBOX_TOOL)
extern const struct enbox_flag_desc enbox_mount_flag_descs[];
extern const struct enbox_flag_desc enbox_namespace_descs[];
#endif /* defined(CONFIG_ENBOX_TOOL) */

extern int
enbox_validate_mount_time_flags(unsigned long flags)
	__enbox_const __enbox_nothrow __leaf __warn_result __export_intern;

#define ENBOX_VALID_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

/* Maximum number of supported system capabilities. */
#define ENBOX_CAPS_NR \
	(CAP_LAST_CAP + 1)

/*
 * Mask of capabilities that Enbox refuses to propagate across setresuid(2) and
 * execve(2).
 */
#define ENBOX_CAPS_INVAL \
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SYS_ADMIN))

/*
 * Mask of capabilities that Enbox allows to propagate across setresuid(2) and
 * execve(2).
 */
#define ENBOX_CAPS_VALID \
	(((UINT64_C(1) << ENBOX_CAPS_NR) - 1) & ~(ENBOX_CAPS_INVAL))

#if defined(CONFIG_ENBOX_TOOL)
#define __enbox_export_caps
#else  /* !defined(CONFIG_ENBOX_TOOL) */
#define __enbox_export_caps __export_intern
#endif /* defined(CONFIG_ENBOX_TOOL) */

extern const struct enbox_flag_desc enbox_caps_descs[] __enbox_export_caps;

extern struct elog * enbox_logger;

#define enbox_err(_format, ...) \
	do { \
		if (enbox_logger) \
			elog_err(enbox_logger, _format ".", ## __VA_ARGS__); \
	} while (0)

#if defined(CONFIG_ENBOX_VERBOSE)

#define enbox_info(_format, ...) \
	do { \
		if (enbox_logger) \
			elog_info(enbox_logger, _format ".", ## __VA_ARGS__); \
	} while (0)

#else /* !defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_info(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_assert_fsset(_fsset) \
	enbox_assert(_fsset); \
	enbox_assert((_fsset)->nr); \
	enbox_assert((_fsset)->entries); \

#define enbox_assert_jail(_jail) \
	enbox_assert(_jail); \
	enbox_assert(!((_jail)->namespaces & ~ENBOX_VALID_NAMESPACE_FLAGS)); \
	enbox_assert(upath_validate_path_name((_jail)->root_path) > 0); \
	enbox_assert_fsset(&(_jail)->fsset)

#define enbox_assert_proc(_proc) \
	enbox_assert(_proc); \
	enbox_assert(!((_proc)->umask & ~((mode_t)ALLPERMS))); \
	enbox_assert(!(_proc)->ids || \
	             !enbox_validate_pwd((_proc)->ids->pwd, true)); \
	enbox_assert(!((_proc)->caps & \
	               ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1))); \
	enbox_assert(!(_proc)->cwd || \
	             (upath_validate_path_name((_proc)->cwd) > 0)); \
	enbox_assert(!(_proc)->fds_nr || (_proc)->fds)

#define enbox_assert_cmd(_cmd) \
	enbox_assert(!enbox_validate_exec(_cmd))

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

struct enbox_conf {
	struct enbox_fsset * host;
	struct enbox_jail *  jail;
	struct enbox_proc *  proc;
        const char **        cmd;
	config_t             lib;
};

static inline const char *
enbox_get_user_name(uid_t uid)
{
	const struct passwd * pwd;

	pwd = upwd_get_user_byid(uid);

	return pwd ? pwd->pw_name : "??";
}

static inline const char *
enbox_get_group_name(gid_t gid)
{
	const struct group * grp;

	grp = upwd_get_group_byid(gid);

	return grp ? grp->gr_name : "??";
}

extern void
enbox_enable_nonewprivs(void)
	__enbox_nothrow __export_intern;

extern int
enbox_save_secbits(int secbits)
	__enbox_nothrow __export_intern;

extern int
enbox_validate_pwd(const struct passwd * __restrict pwd, bool allow_root)
#if defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_TOOL)
	__enbox_nonull(1) __enbox_pure __enbox_nothrow __leaf __warn_result;
#else  /* !(defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_TOOL)) */
	__enbox_nonull(1) \
	__enbox_pure \
	__enbox_nothrow \
	__leaf \
	__warn_result \
	__export_intern;
#endif /* defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_TOOL) */

#define ENBOX_EXEC_ARGS_MAX (1024U)

extern int
enbox_validate_exec_arg(const char * __restrict arg)
	__enbox_pure __enbox_nothrow __leaf __export_intern;

#if defined(CONFIG_ENBOX_ASSERT)

extern int
enbox_validate_exec(const char * const exec[__restrict_arr])
#if !defined(CONFIG_ENBOX_TOOL)
	__enbox_nonull(1) __enbox_pure __enbox_nothrow __leaf __export_intern;
#else  /* defined(CONFIG_ENBOX_TOOL) */
	__enbox_nonull(1) __enbox_pure __enbox_nothrow __leaf;
#endif /* !defined(CONFIG_ENBOX_TOOL) */

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

static inline int __enbox_nonull(1) __const __nothrow
enbox_validate_exec(const char * const exec[__restrict_arr] __unused)
{
	return 0;
}

#endif /* defined(CONFIG_ENBOX_ASSERT) */

#endif /* _ENBOX_COMMON_H */
