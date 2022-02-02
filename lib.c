#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include "enbox/enbox.h"
#include <elog/elog.h>
#include <stdlib.h>

static struct elog * enbox_logger;

#define enbox_err(_format, ...) \
	({ \
		if (enbox_logger) \
			elog_err(enbox_logger, _format ".", ## __VA_ARGS__); \
	 })


#if defined(CONFIG_ENBOX_VERBOSE)

#define enbox_info(_format, ...) \
	({ \
		if (enbox_logger) \
			elog_info(enbox_logger, _format ".", ## __VA_ARGS__); \
	 })

static const char *
enbox_get_group_name(gid_t gid)
{
	const struct group * grp;

	grp = upwd_get_group_byid(gid);

	return grp ? grp->gr_name : "??";
}

#else /* !defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_info(_format, ...)

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

void
enbox_change_ids(const char * __restrict user)
{
	enbox_assert(upwd_validate_user_name(user) > 0);

	const struct passwd * pwd;
	int                   err;

	pwd = upwd_get_user_byname(user);
	if (!pwd) {
		enbox_info("invalid '%s' user name: %s (%d)",
		           user,
		           strerror(errno),
		           errno);
		goto err;
	}

	err = enbox_change_gid(pwd->pw_gid);
	if (err) {
		enbox_info("cannot switch to GID %hu(%s): %s (%d)",
		           pwd->pw_gid,
		           enbox_get_group_name(pwd->pw_gid),
		           strerror(-err),
		           -err);
		goto err;
	}

	err = enbox_raise_supp_groups(user, pwd->pw_gid);
	if (err) {
		enbox_info("cannot setup %d(%s) users's supplementary groups: "
		           "%s (%d)",
		           pwd->pw_uid,
		           user,
		           strerror(-err),
		           -err);
		goto err;
	}

	err = enbox_change_uid(pwd->pw_uid);
	if (err) {
		enbox_info("cannot switch to UID %d(%s): %s (%d)",
		           pwd->pw_uid,
		           user,
		           strerror(-err),
		           -err);
		goto err;
	}

	return;

err:
	enbox_err("cannot change user / groups IDs");

	exit(EXIT_FAILURE);
}

void
enbox_setup(struct elog * logger)
{
	enbox_logger = logger;
}
