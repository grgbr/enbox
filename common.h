#ifndef _ENBOX_COMMON_H
#define _ENBOX_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include "enbox/enbox.h"
#include <elog/elog.h>
#include <libconfig.h>
#include <linux/sched.h>

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

#if defined(CONFIG_ENBOX_SKEL)
extern const struct enbox_flag_desc enbox_mount_flag_descs[];
extern const struct enbox_flag_desc enbox_namespace_descs[];
#endif /* defined(CONFIG_ENBOX_SKEL) */

/* Include generated mounting flags definitions. */
#include "mount_flags.h"

extern int
enbox_validate_mount_time_flags(unsigned long flags)
	__const __nothrow __leaf __priv_visi;

#define enbox_assert_jail(_jail) \
	enbox_assert(_jail); \
	enbox_assert((_jail)->namespaces); \
	enbox_assert(!((_jail)->namespaces & ~ENBOX_VALID_NAMESPACE_FLAGS)); \
	enbox_assert(upath_validate_path_name((_jail)->root_path) > 0); \
	enbox_assert((_jail)->fsset.nr); \
	enbox_assert((_jail)->fsset.entries)

/*
 * Enbox is meant to run onto embedded systems, i.e., from within a controlled
 * software runtime. That is the reason why Enbox is a execve() based
 * containment system to keep things simple. As a consequence, this comes with a
 * few limitations with respect to namespace isolation handling:
 * 1. don't support CLONE_NEWPID since we don't want to handle fork / init
 *    process machinery ; instead, we may rely upon secure procfs operations to
 *    provide some sort of PID space isolation (see procfs hidepid / gid /
 *    subset mount options).
 * 2. don't support CLONE_NEWUSER since we don't really need it for now (we have
 *    no use case for emulating a complete virtualized OS while running onto an
 *    embedded system) ;
 *    we may however need to investigate possible implications related to kernel
 *    keyrings isolation...
 */
#define ENBOX_VALID_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

/* Include generated namespaces definitions. */
#include "namespaces.h"

extern struct elog * enbox_logger;

#define enbox_err(_format, ...) \
	elog_err(enbox_logger, _format ".", ## __VA_ARGS__)

#if defined(CONFIG_ENBOX_VERBOSE)

#define enbox_info(_format, ...) \
	elog_info(enbox_logger, _format ".", ## __VA_ARGS__)

#else /* !defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_info(_format, ...)

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

struct enbox_conf {
	struct enbox_fsset * host;
	struct enbox_ids *   ids;
	struct enbox_jail *  jail;
	struct enbox_cmd *   cmd;
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

extern int
enbox_validate_pwd(const struct passwd * __restrict pwd, bool allow_root)
#if defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_SKEL)
	__enbox_nonull(1) __pure __nothrow __leaf;
#else  /* !(defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_SKEL)) */
	__enbox_nonull(1) __pure __nothrow __leaf __priv_visi;
#endif /* defined(CONFIG_ENBOX_ASSERT) && defined(CONFIG_ENBOX_SKEL) */

#define ENBOX_EXEC_ARGS_MAX (1024U)

extern int
enbox_validate_exec_arg(const char * __restrict arg)
	__pure __nothrow __leaf __priv_visi;

#if defined(CONFIG_ENBOX_ASSERT)

extern int
enbox_validate_exec(const char * const exec[__restrict_arr])
#if !defined(CONFIG_ENBOX_SKEL)
	__enbox_nonull(1) __pure __nothrow __leaf __priv_visi;
#else  /* defined(CONFIG_ENBOX_SKEL) */
	__enbox_nonull(1) __pure __nothrow __leaf;
#endif /* !defined(CONFIG_ENBOX_SKEL) */

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

static inline int __enbox_nonull(1) __const __nothrow
enbox_validate_exec(const char * const exec[__restrict_arr] __unused)
{
	return 0;
}

#endif /* defined(CONFIG_ENBOX_ASSERT) */

#endif /* _ENBOX_COMMON_H */
