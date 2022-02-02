#ifndef _ENBOX_H
#define _ENBOX_H

#include <enbox/config.h>
#include <utils/pwd.h>
#include <unistd.h>
#include <sys/prctl.h>

#if defined(CONFIG_ENBOX_ASSERT)

#define enbox_assert(_expr) \
	uassert("enbox", _expr)

#define __enbox_nonull(_arg_index, ...)

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert(_expr)

#define __enbox_nonull(_arg_index, ...) \
	__nonull(_arg_index, ## __VA_ARGS__)

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/*
 * Drop all ambient set capabilities.
 *
 * Requires CAP_SETPCAP capability.
 */
static inline int __nothrow
enbox_drop_ambient_caps(void)
{
	if (!prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0))
		return 0;

	return -errno;
}

extern int
enbox_drop_bounding_caps(void) __nothrow __leaf;

extern int
enbox_lock_caps(void) __nothrow __leaf;

extern void
enbox_drop_caps(void) __nothrow __leaf;

/*
 * Require the CAP_SETUID capability.
 */
static inline int __nothrow __warn_result
enbox_change_uid(uid_t uid)
{
	if (!setresuid(uid, uid, uid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static inline int __nothrow __warn_result
enbox_change_gid(gid_t gid)
{
	if (!setresgid(gid, gid, gid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static inline int __nothrow
enbox_drop_supp_groups(void)
{
	if (!setgroups(0, NULL))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != EINVAL);

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static inline int __enbox_nonull(1)
enbox_raise_supp_groups(const char * user, gid_t gid)
{
	enbox_assert(upwd_validate_user_name(user) > 0);

	if (!initgroups(user, gid))
		return 0;

	return -errno;
}

extern void
enbox_change_ids(const char * __restrict user) __enbox_nonull(1);

struct elog;

extern void __nothrow __leaf
enbox_setup(struct elog * __restrict logger);

#endif /* _ENBOX_H */
