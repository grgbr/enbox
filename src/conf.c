/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "conf.h"
#include <utils/path.h>
#include <stdlib.h>

#if defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL)

#define __enbox_flag_descs_storage

#else /* !(defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL)) */

#define __enbox_flag_descs_storage static

#endif /* defined(CONFIG_ENBOX_SHOW) && defined(CONFIG_ENBOX_TOOL) */

#define enbox_conf_log(_setting, _severity, _format, ...) \
	({ \
		const config_setting_t * __set = _setting; \
		enum elog_severity       __svrt = _severity; \
		const char *             __path; \
		unsigned int             __line; \
		const char *             __name; \
		\
		__path = config_setting_source_file(__set); \
		enbox_assert(__path); \
		__line = config_setting_source_line(__set); \
		enbox_assert(__line); \
		__name = config_setting_name(__set); \
		\
		if (__name) \
			elog_log(enbox_logger, \
			         __svrt, \
			         "%s:%d: '%s': " _format ".", \
			         __path, \
			         __line, \
			         __name, \
			         ## __VA_ARGS__); \
		else \
			elog_log(enbox_logger, \
			         __svrt, \
			         "%s:%d: " _format ".", \
			         __path, \
			         __line, \
			         ## __VA_ARGS__); \
	 })

#define enbox_conf_err(_setting, _format, ...) \
	do { \
		if (enbox_logger) \
			enbox_conf_log(_setting, \
			               ELOG_ERR_SEVERITY, \
			               _format, \
			               ## __VA_ARGS__); \
	} while (0)

#if defined(CONFIG_ENBOX_VERBOSE)

#define enbox_conf_warn(_setting, _format, ...) \
	do { \
		if (enbox_logger) \
			enbox_conf_log(_setting, \
			               ELOG_WARNING_SEVERITY, \
			               _format, \
			               ## __VA_ARGS__); \
	} while (0)

#define enbox_conf_info(_setting, _format, ...) \
	do { \
		if (enbox_logger) \
			enbox_conf_log(_setting, \
			               ELOG_INFO_SEVERITY, \
			               _format, \
			               ## __VA_ARGS__); \
	} while (0)

#else /* !defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_conf_warn(_setting, _format, ...)
#define enbox_conf_info(_setting, _format, ...)

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

typedef int (enbox_load_setting_fn)(const config_setting_t * __restrict setting,
                                    void * __restrict                   data);

struct enbox_loader {
	const char            * name;
	enbox_load_setting_fn * load;
};

#define enbox_assert_loader(_loader) \
	enbox_assert((_loader)->name); \
	enbox_assert((_loader)->name[0]); \
	enbox_assert((_loader)->load)

static int __enbox_nonull(1, 2)
enbox_skip_entry_setting(const config_setting_t * __restrict setting __unused,
                         void * __restrict                   data __unused)
{
	return 0;
}

static int __enbox_nonull(1, 2, 3)
enbox_load_setting(const config_setting_t * __restrict    setting,
                   void * __restrict                      data,
                   const struct enbox_loader * __restrict loaders,
                   unsigned int                           count)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(data);
	enbox_assert(loaders);
	enbox_assert(count);

	int nr;
	int s;

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		if (config_setting_is_root(setting))
			enbox_err("%s: empty configuration not allowed",
			          config_setting_source_file(setting));
		else
			enbox_conf_err(setting,
			               "empty setting not allowed");
		return -ENODATA;
	}

	for (s = 0; s < nr; s++) {
		const config_setting_t * set;
		const char *             name;
		unsigned int             l;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)s);
		enbox_assert(set);

		/* Cannot be empty as parent setting is a group setting. */
		name = config_setting_name(set);
		enbox_assert(name);
		enbox_assert(name[0]);

		for (l = 0; l < count; l++) {
			enbox_assert_loader(&loaders[l]);
			if (!strcmp(name, loaders[l].name))
				break;
		}

		if (l == count) {
			enbox_conf_err(set, "unknown setting");
			return -EINVAL;
		}

		err = loaders[l].load(set, data);
		if (err)
			return err;
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_type_setting(const config_setting_t * __restrict setting,
                        enum enbox_entry_type * __restrict  type)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(type);

	const config_setting_t * set;
	const char *             str;

	set = config_setting_get_member(setting, "type");
	if (!set) {
		enbox_conf_err(setting, "missing 'type' setting");
		return -ENODATA;
	}

	str = config_setting_get_string(set);
	if (!str) {
		enbox_conf_err(set, "string required");
		return -EINVAL;
	}

	if (!strcmp(str, "dir"))
		*type = ENBOX_DIR_ENTRY_TYPE;
	else if (!strcmp(str, "slink"))
		*type = ENBOX_SLINK_ENTRY_TYPE;
	else if (!strcmp(str, "chrdev"))
		*type = ENBOX_CHRDEV_ENTRY_TYPE;
	else if (!strcmp(str, "blkdev"))
		*type = ENBOX_BLKDEV_ENTRY_TYPE;
	else if (!strcmp(str, "fifo"))
		*type = ENBOX_FIFO_ENTRY_TYPE;
	else if (!strcmp(str, "file"))
		*type = ENBOX_FILE_ENTRY_TYPE;
	else if (!strcmp(str, "tree"))
		*type = ENBOX_TREE_ENTRY_TYPE;
	else if (!strcmp(str, "proc"))
		*type = ENBOX_PROC_ENTRY_TYPE;
	else {
		enbox_conf_err(set, "unknown '%s' type", str);
		return -EINVAL;
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_pwd_setting_byid(const config_setting_t * __restrict setting,
                            const struct passwd ** __restrict   pwd)
{
	enbox_assert(setting);
	enbox_assert(config_setting_type(setting) == CONFIG_TYPE_INT);
	enbox_assert(pwd);

	int id;
	int err;

	id = config_setting_get_int(setting);
	if (id >= 0) {
		const struct passwd * pass;

		pass = upwd_get_user_byid((uid_t)id);
		if (pass) {
			*pwd = pass;
			return 0;
		}

		err = errno;
	}
	else
		err = ERANGE;

	enbox_assert(err > 0);
	switch (err) {
	case ERANGE:
		enbox_conf_info(setting, "'%d': positive integer expected", id);
		break;
	case ENOENT:
		enbox_conf_info(setting, "'%d': no such user", id);
		break;
	default:
		enbox_conf_info(setting,
		                "'%d': unexpected user ID: %s (%d)",
		                id,
		                strerror(err),
		                err);
	}

	enbox_conf_err(setting, "invalid user ID");

	return -err;
}

static int __enbox_nonull(1, 2)
enbox_load_pwd_setting_byname(const config_setting_t * __restrict setting,
                              const struct passwd ** __restrict   pwd)
{
	enbox_assert(setting);
	enbox_assert(config_setting_type(setting) == CONFIG_TYPE_STRING);
	enbox_assert(pwd);

	const char * user;
	int          err;

	user = config_setting_get_string(setting);
	enbox_assert(user);

	err = (int)upwd_validate_user_name(user);
	if (err > 0) {
		const struct passwd * pass;

		pass = upwd_get_user_byname(user);
		if (pass) {
			*pwd = pass;
			return 0;
		}

		err = errno;
	}

	enbox_assert(err > 0);
	switch (err) {
	case ENODATA:
		enbox_conf_info(setting, "'%s': empty user name", user);
		break;
	case ENAMETOOLONG:
		enbox_conf_info(setting, "'%s': user name too long", user);
		break;
	case ENOENT:
		enbox_conf_info(setting, "'%s': no such user", user);
		break;
	default:
		enbox_conf_info(setting,
		                "'%s': unexpected user name: %s (%d)",
		                user,
		                strerror(err),
		                err);
	}

	enbox_conf_err(setting, "invalid user name");

	return -err;
}

static int __enbox_nonull(1, 2)
enbox_load_pwd_setting(const config_setting_t * __restrict setting,
                       const struct passwd ** __restrict   pwd)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(pwd);

	int err;

	switch (config_setting_type(setting)) {
	case CONFIG_TYPE_INT:
		err = enbox_load_pwd_setting_byid(setting, pwd);
		break;
	case CONFIG_TYPE_STRING:
		err = enbox_load_pwd_setting_byname(setting, pwd);
		break;
	default:
		enbox_conf_err(setting,
		               "positive integer or string required");
		err = -EINVAL;
	}

	if (err)
		return err;

	err = enbox_validate_pwd(*pwd, true);
	if (err) {
		enbox_conf_err(setting,
		               "invalid user entry: %s (%d)",
		               strerror(-err),
		               -err);
		return err;
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_group_gid_setting(const config_setting_t * __restrict setting,
                             gid_t * __restrict                  gid)
{
	enbox_assert(setting);
	enbox_assert(config_setting_type(setting) == CONFIG_TYPE_INT);
	enbox_assert(gid);

	int id;
	int err;

	id = config_setting_get_int(setting);
	if (id >= 0) {
		const struct group * grp;

		grp = upwd_get_group_byid((gid_t)id);
		if (grp) {
			*gid = (gid_t)id;
			return 0;
		}

		err = errno;
	}
	else
		err = ERANGE;

	enbox_assert(err > 0);
	switch (err) {
	case ERANGE:
		enbox_conf_info(setting, "'%d': positive integer expected", id);
		break;
	case ENOENT:
		enbox_conf_info(setting, "'%d': no such group", id);
		break;
	default:
		enbox_conf_info(setting,
		                "'%d': unexpected group ID: %s (%d)",
		                id,
		                strerror(err),
		                err);
	}

	enbox_conf_err(setting, "invalid group ID");

	return -err;
}

static int __enbox_nonull(1, 2)
enbox_load_group_name_setting(const config_setting_t * __restrict setting,
                              gid_t * __restrict                  gid)
{
	enbox_assert(setting);
	enbox_assert(config_setting_type(setting) == CONFIG_TYPE_STRING);
	enbox_assert(gid);

	const char * group;
	int          err;

	group = config_setting_get_string(setting);
	enbox_assert(group);

	err = (int)upwd_validate_group_name(group);
	if (err > 0) {
		err = upwd_get_gid_byname(group, gid);
		if (!err)
			return 0;
	}

	enbox_assert(err < 0);
	switch (err) {
	case -ENODATA:
		enbox_conf_info(setting, "'%s': empty group name", group);
		break;
	case -ENAMETOOLONG:
		enbox_conf_info(setting, "'%s': group name too long", group);
		break;
	case -ENOENT:
		enbox_conf_info(setting, "'%s': no such group", group);
		break;
	default:
		enbox_conf_info(setting,
		                "'%s': unexpected group name: %s (%d)",
		                group,
		                strerror(-err),
		                -err);
	}

	enbox_conf_err(setting, "invalid group name");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_group_setting(const config_setting_t * __restrict setting,
                         gid_t * __restrict                  gid)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(gid);

	int ret;

	switch (config_setting_type(setting)) {
	case CONFIG_TYPE_INT:
		ret = enbox_load_group_gid_setting(setting, gid);
		break;
	case CONFIG_TYPE_STRING:
		ret = enbox_load_group_name_setting(setting, gid);
		break;
	default:
		enbox_conf_err(setting,
		               "positive integer or string required");
		ret = -EINVAL;
	}

	return ret;
}

static int __enbox_nonull(1, 2)
enbox_load_devid_major_setting(const config_setting_t * __restrict setting,
                               unsigned int * __restrict           major)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(!strcmp(config_setting_name(setting), "major"));

	int maj;

	if (config_setting_type(setting) != CONFIG_TYPE_INT) {
		enbox_conf_err(setting, "integer expected");
		return -EINVAL;
	}

	maj = config_setting_get_int(setting);
	if (maj < 1) {
		enbox_conf_err(setting, "invalid device ID major number");
		return -ERANGE;
	}

	*major = (unsigned int)maj;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_devid_minor_setting(const config_setting_t * __restrict setting,
                               unsigned int * __restrict           minor)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(!strcmp(config_setting_name(setting), "minor"));

	int min;

	if (config_setting_type(setting) != CONFIG_TYPE_INT) {
		enbox_conf_err(setting, "integer expected");
		return -EINVAL;
	}

	min = config_setting_get_int(setting);
	if (min < 0) {
		enbox_conf_err(setting, "invalid device ID minor number");
		return -ERANGE;
	}

	*minor = (unsigned int)min;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_path_setting(const config_setting_t * __restrict setting,
                        const char ** __restrict            path)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(path);

	const char * str;
	int          err;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

	err = (int)upath_validate_path_name(str);
	if (err < 0) {
		switch (err) {
		case -ENODATA:
			enbox_conf_err(setting, "empty pathname not allowed");
			break;
		case -ENAMETOOLONG:
			enbox_conf_err(setting, "pathname too long");
			break;
		default:
			enbox_conf_err(setting, "invalid pathname");
		}

		return err;
	}

	*path = str;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_path_entry_setting(const config_setting_t * __restrict setting,
                              void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type >= 0);
	enbox_assert(ent->type < ENBOX_ENTRY_TYPE_NR);

	return enbox_load_path_setting(setting, &ent->path);
}

static int __enbox_nonull(1, 2)
enbox_load_user_entry_setting(const config_setting_t * __restrict setting,
                              void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	int                   err;
	const struct passwd * pwd;
	struct enbox_entry *  ent = (struct enbox_entry *)data;

	enbox_assert(ent->type >= 0);
	enbox_assert(ent->type < ENBOX_ENTRY_TYPE_NR);

	err = enbox_load_pwd_setting(setting, &pwd);
	if (err)
		return err;

	ent->uid = pwd->pw_uid;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_group_entry_setting(const config_setting_t * __restrict setting,
                               void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type >= 0);
	enbox_assert(ent->type < ENBOX_ENTRY_TYPE_NR);

	return enbox_load_group_setting(setting, &ent->gid);
}

static int __enbox_nonull(1, 2)
enbox_load_mode_setting(const config_setting_t * __restrict setting,
                        mode_t * __restrict                 mode,
                        mode_t                              valid)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(mode);

	mode_t val;

	if (config_setting_type(setting) != CONFIG_TYPE_INT) {
		enbox_conf_err(setting, "integer expected");
		return -EINVAL;
	}

	val = (mode_t)config_setting_get_int(setting);
	if (val & ~valid) {
		enbox_conf_err(setting, "invalid mode bits");
		return -ERANGE;
	}

	*mode = val;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_dir_mode_setting(const config_setting_t * __restrict setting,
                            void * __restrict                   data)
{
	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type >= 0);
	enbox_assert(ent->type < ENBOX_ENTRY_TYPE_NR);

	return enbox_load_mode_setting(setting, &ent->dir.mode, ALLPERMS);
}

static int __enbox_nonull(1, 2)
enbox_validate_entry_path(const config_setting_t * __restrict   setting,
                          const struct enbox_entry * __restrict entry,
                          bool                                  allow_relative)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);

	if (!entry->path) {
		/* Path is mandatory. */
		enbox_conf_err(setting, "missing 'path' setting");
		return -ENODATA;
	}

	if (!allow_relative) {
		/* Reject relative paths. */
		if (entry->path[0] != '/') {
			enbox_conf_err(setting,
			               "relative 'path' setting rejected");
			return -EINVAL;
		}
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_dir_entry(const config_setting_t * __restrict setting,
                     struct enbox_entry * __restrict     entry,
                     bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_DIR_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",  .load = enbox_load_path_entry_setting },
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "user",  .load = enbox_load_user_entry_setting },
		{ .name = "group", .load = enbox_load_group_entry_setting },
		{ .name = "mode",  .load = enbox_load_dir_mode_setting }
	};

	entry->dir.mode = (mode_t)-1;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	err = enbox_validate_entry_path(setting, entry, allow_relative);
	if (err)
		goto err;

	if (entry->uid == ((uid_t)-1))
		/* User is optional, use current effective UID as default. */
		entry->uid = enbox_get_uid();

	if (entry->gid == ((gid_t)-1))
		/* Group is optional, use current effective GID as default. */
		entry->gid = enbox_get_gid();

	if (entry->dir.mode == ((mode_t)-1))
		/* Mode is optional, use current umask'ed 0777 value. */
		entry->dir.mode = ACCESSPERMS & ~enbox_get_umask();

	return 0;

err:
	enbox_conf_err(setting, "invalid directory entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_slink_target_setting(const config_setting_t * __restrict setting,
                                void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_SLINK_ENTRY_TYPE);

	return enbox_load_path_setting(setting, &ent->slink.target);
}

static int __enbox_nonull(1, 2)
enbox_load_slink_entry(const config_setting_t * __restrict setting,
                       struct enbox_entry * __restrict     entry,
                       bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_SLINK_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",   .load = enbox_load_path_entry_setting },
		{ .name = "type",   .load = enbox_skip_entry_setting },
		{ .name = "user",   .load = enbox_load_user_entry_setting },
		{ .name = "group",  .load = enbox_load_group_entry_setting },
		{ .name = "target", .load = enbox_load_slink_target_setting }
	};

	entry->slink.target = NULL;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	err = enbox_validate_entry_path(setting, entry, allow_relative);
	if (err)
		goto err;

	if (entry->uid == ((uid_t)-1))
		/* User is optional, use current effective UID as default. */
		entry->uid = enbox_get_uid();

	if (entry->gid == ((gid_t)-1))
		/* Group is optional, use current effective GID as default. */
		entry->gid = enbox_get_gid();

	if (!entry->slink.target) {
		/* Link target is mandatory. */
		enbox_conf_err(setting, "missing 'target' setting");
		err = -ENODATA;
		goto err;
	}

	return 0;

err:
	enbox_conf_err(setting, "invalid symbolic link entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_dev_mode_setting(const config_setting_t * __restrict setting,
                            void * __restrict                   data)
{
	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert((ent->type == ENBOX_CHRDEV_ENTRY_TYPE) ||
	             (ent->type == ENBOX_BLKDEV_ENTRY_TYPE));

	return enbox_load_mode_setting(setting, &ent->dev.mode, DEFFILEMODE);
}

static int __enbox_nonull(1, 2)
enbox_load_dev_major_setting(const config_setting_t * __restrict setting,
                             void * __restrict                   data)
{
	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert((ent->type == ENBOX_CHRDEV_ENTRY_TYPE) ||
	             (ent->type == ENBOX_BLKDEV_ENTRY_TYPE));

	return enbox_load_devid_major_setting(setting, &ent->dev.major);
}

static int __enbox_nonull(1, 2)
enbox_load_dev_minor_setting(const config_setting_t * __restrict setting,
                             void * __restrict                   data)
{
	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert((ent->type == ENBOX_CHRDEV_ENTRY_TYPE) ||
	             (ent->type == ENBOX_BLKDEV_ENTRY_TYPE));

	return enbox_load_devid_minor_setting(setting, &ent->dev.minor);
}

static int __enbox_nonull(1, 2)
enbox_load_dev_entry(const config_setting_t * __restrict setting,
                     struct enbox_entry * __restrict     entry,
                     bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert((entry->type == ENBOX_CHRDEV_ENTRY_TYPE) ||
	             (entry->type == ENBOX_BLKDEV_ENTRY_TYPE));

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",  .load = enbox_load_path_entry_setting },
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "user",  .load = enbox_load_user_entry_setting },
		{ .name = "group", .load = enbox_load_group_entry_setting },
		{ .name = "mode",  .load = enbox_load_dev_mode_setting },
		{ .name = "major", .load = enbox_load_dev_major_setting },
		{ .name = "minor", .load = enbox_load_dev_minor_setting }
	};

	entry->dev.mode = (mode_t)-1;
	entry->dev.major = UINT_MAX;
	entry->dev.minor = UINT_MAX;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		return err;

	err = enbox_validate_entry_path(setting, entry, allow_relative);
	if (err)
		return err;

	if (entry->uid == ((uid_t)-1))
		/* User is optional, use current effective UID as default. */
		entry->uid = enbox_get_uid();

	if (entry->gid == ((gid_t)-1))
		/* Group is optional, use current effective GID as default. */
		entry->gid = enbox_get_gid();

	if (entry->dev.mode == ((mode_t)-1))
		/* Mode is optional, use current umask'ed 0666 value. */
		entry->dir.mode = DEFFILEMODE & ~enbox_get_umask();

	if (entry->dev.major == UINT_MAX) {
		/* Device major number is mandatory. */
		enbox_conf_err(setting, "missing 'major' setting");
		return -ENODATA;
	}

	if (entry->dev.minor == UINT_MAX) {
		/* Device minor number is mandatory. */
		enbox_conf_err(setting, "missing 'minor' setting");
		return -ENODATA;
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_chrdev_entry(const config_setting_t * __restrict setting,
                        struct enbox_entry * __restrict     entry,
                        bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_CHRDEV_ENTRY_TYPE);

	int ret;

	ret = enbox_load_dev_entry(setting, entry, allow_relative);
	if (ret)
		enbox_conf_err(setting, "invalid character device entry");

	return ret;
}

static int __enbox_nonull(1, 2)
enbox_load_blkdev_entry(const config_setting_t * __restrict setting,
                        struct enbox_entry * __restrict     entry,
                        bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_BLKDEV_ENTRY_TYPE);

	int ret;

	ret = enbox_load_dev_entry(setting, entry, allow_relative);
	if (ret)
		enbox_conf_err(setting, "invalid block device entry");

	return ret;
}

static int __enbox_nonull(1, 2)
enbox_load_fifo_mode_setting(const config_setting_t * __restrict setting,
                            void * __restrict                   data)
{
	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_FIFO_ENTRY_TYPE);

	return enbox_load_mode_setting(setting, &ent->fifo.mode, DEFFILEMODE);
}

static int __enbox_nonull(1, 2)
enbox_load_fifo_entry(const config_setting_t * __restrict setting,
                      struct enbox_entry * __restrict     entry,
                      bool                                allow_relative)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_FIFO_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",  .load = enbox_load_path_entry_setting },
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "user",  .load = enbox_load_user_entry_setting },
		{ .name = "group", .load = enbox_load_group_entry_setting },
		{ .name = "mode",  .load = enbox_load_fifo_mode_setting }
	};

	entry->fifo.mode = (mode_t)-1;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	err = enbox_validate_entry_path(setting, entry, allow_relative);
	if (err)
		goto err;

	if (entry->uid == ((uid_t)-1))
		/* User is optional, use current effective UID as default. */
		entry->uid = enbox_get_uid();

	if (entry->gid == ((gid_t)-1))
		/* Group is optional, use current effective GID as default. */
		entry->gid = enbox_get_gid();

	if (entry->fifo.mode == ((mode_t)-1))
		/* Mode is optional, use current umask'ed 0666 value. */
		entry->fifo.mode = DEFFILEMODE & ~enbox_get_umask();

	return 0;

err:
	enbox_conf_err(setting, "invalid named pipe entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_host_entry(const config_setting_t * __restrict setting,
                      void * __restrict                   entry)
{
	enbox_assert(setting);
	enbox_assert(entry);

        struct enbox_entry * ent = (struct enbox_entry *)entry;
	int                  ret;

	switch (ent->type) {
	case ENBOX_DIR_ENTRY_TYPE:
		ret = enbox_load_dir_entry(setting, ent, false);
		break;

	case ENBOX_SLINK_ENTRY_TYPE:
		ret = enbox_load_slink_entry(setting, ent, false);
		break;

	case ENBOX_CHRDEV_ENTRY_TYPE:
		ret = enbox_load_chrdev_entry(setting, ent, false);
		break;

	case ENBOX_BLKDEV_ENTRY_TYPE:
		ret = enbox_load_blkdev_entry(setting, ent, false);
		break;

	case ENBOX_FIFO_ENTRY_TYPE:
		ret = enbox_load_fifo_entry(setting, ent, false);
		break;

	default:
		enbox_conf_err(setting, "unexpected host entry type");
		ret = -ENOSYS;
	}

	return ret;
}

__enbox_flag_descs_storage
const struct enbox_flag_desc enbox_mount_flag_descs[] = {
	/* Include generated mounting flag descriptor definitions. */
#include "mount_flags.i"
	{ NULL, }
};

static int __enbox_nonull(1, 3)
enbox_parse_mount_flags_setting(const config_setting_t * __restrict setting,
                                unsigned long                       valid,
                                unsigned long * __restrict          flags)
{
	enbox_assert(setting);
	enbox_assert(valid);
	enbox_assert(flags);

	const char * str;
	unsigned int d;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

	for (d = 0; enbox_mount_flag_descs[d].kword; d++) {
		if (!memcmp(str,
		            enbox_mount_flag_descs[d].kword,
		            enbox_mount_flag_descs[d].len + 1))
			break;
	}

	if (!enbox_mount_flag_descs[d].kword) {
		enbox_conf_err(setting, "unknown '%s' mount flag", str);
		return -ENOENT;
	}

	if (!(enbox_mount_flag_descs[d].value & valid)) {
		enbox_conf_err(setting, "invalid '%s' mount flag", str);
		return -EINVAL;
	}

	if (enbox_validate_mount_time_flags(*flags |
	                                    enbox_mount_flag_descs[d].value)) {
		enbox_conf_err(setting,
		               "conflicting '%s' time mount flag",
		               str);
		return -EINVAL;
	}

	if (*flags & enbox_mount_flag_descs[d].value) {
		enbox_conf_warn(setting,
		                "duplicate '%s' mount flag ignored",
		                str);
		return 0;
	}

	*flags |= enbox_mount_flag_descs[d].value;

	return 0;
}

static int __enbox_nonull(1, 3)
enbox_load_mount_flags_setting(const config_setting_t * __restrict setting,
                               unsigned long                       valid,
                               unsigned long * __restrict          flags)
{
	enbox_assert(setting);
	enbox_assert(valid);
	enbox_assert(flags);

	int           nr;
	int           e;
	unsigned long flg = 0;

	if (!config_setting_is_array(setting)) {
		enbox_conf_err(setting, "array of strings required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		/* Flags array is empty: clear default flags. */
		*flags = 0;
		return 0;
	}

	for (e = 0; e < nr; e++) {
		const config_setting_t * set;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)e);
		enbox_assert(set);

		err = enbox_parse_mount_flags_setting(set, valid, &flg);
		if (err)
			return err;
	}

	enbox_assert(!(flg & ~valid));
	*flags = flg;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_mount_opts_setting(const config_setting_t * __restrict setting,
                              const char ** __restrict            opts)
{
	enbox_assert(setting);
	enbox_assert(opts);

	const char * str;
	size_t       len;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

#define ENBOX_MOUNT_OPTS_LEN (1024U)
	len = strnlen(str, ENBOX_MOUNT_OPTS_LEN);
	if (len == ENBOX_MOUNT_OPTS_LEN) {
		enbox_conf_err(setting, "mount options too long");
		return -ENAMETOOLONG;
	}

	/*
	 * Replace default options with parsed option string if not empty,
	 * clear default option string otherwise.
	 */
	if (len)
		*opts = str;
	else
		*opts = NULL;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_bind_orig_entry_setting(const config_setting_t * __restrict setting,
                                   void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert((ent->type == ENBOX_FILE_ENTRY_TYPE) ||
	             (ent->type == ENBOX_TREE_ENTRY_TYPE));

	return enbox_load_path_setting(setting, &ent->bind.orig);
}

static int __enbox_nonull(1, 2)
enbox_load_bind_opts_entry_setting(const config_setting_t * __restrict setting,
                                   void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert((ent->type == ENBOX_FILE_ENTRY_TYPE) ||
	             (ent->type == ENBOX_TREE_ENTRY_TYPE));

	return enbox_load_mount_opts_setting(setting, &ent->bind.opts);
}

static int __enbox_nonull(1, 2)
enbox_load_file_flags_entry_setting(const config_setting_t * __restrict setting,
                                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_FILE_ENTRY_TYPE);

	return enbox_load_mount_flags_setting(setting,
	                                      ENBOX_FILE_VALID_FLAGS,
	                                      &ent->bind.flags);
}

/* Default file bind mount flags. */
#define ENBOX_BIND_FILE_FLAGS \
	(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | \
	 MS_NOSYMFOLLOW)

static int __enbox_nonull(1, 2)
enbox_load_file_entry(const config_setting_t * __restrict setting,
                      struct enbox_entry * __restrict     entry)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_FILE_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",  .load = enbox_load_path_entry_setting },
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "orig",  .load = enbox_load_bind_orig_entry_setting },
		{ .name = "flags", .load = enbox_load_file_flags_entry_setting },
		{ .name = "opts",  .load = enbox_load_bind_opts_entry_setting }
	};

	entry->bind.orig = NULL;
	entry->bind.flags = ENBOX_BIND_FILE_FLAGS;
	entry->bind.opts = NULL;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	err = enbox_validate_entry_path(setting, entry, true);
	if (err)
		goto err;

	if (!entry->bind.orig) {
		/* Bind mount source pathname is mandatory. */
		enbox_conf_err(setting, "missing 'orig' setting");
		err = -ENODATA;
		goto err;
	}

	return 0;

err:
	enbox_conf_err(setting, "invalid file bind mount entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_tree_flags_entry_setting(const config_setting_t * __restrict setting,
                                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_TREE_ENTRY_TYPE);

	return enbox_load_mount_flags_setting(setting,
	                                      ENBOX_TREE_VALID_FLAGS,
	                                      &ent->bind.flags);
}

/* Default (sub-)tree bind mount flags. */
#define ENBOX_BIND_TREE_FLAGS \
	(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | \
	 MS_NOSYMFOLLOW)

static int __enbox_nonull(1, 2)
enbox_load_tree_entry(const config_setting_t * __restrict setting,
                      struct enbox_entry * __restrict     entry)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_TREE_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "path",  .load = enbox_load_path_entry_setting },
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "orig",  .load = enbox_load_bind_orig_entry_setting },
		{ .name = "flags", .load = enbox_load_tree_flags_entry_setting },
		{ .name = "opts",  .load = enbox_load_bind_opts_entry_setting }
	};

	entry->bind.orig = NULL;
	entry->bind.flags = ENBOX_BIND_TREE_FLAGS;
	entry->bind.opts = NULL;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	err = enbox_validate_entry_path(setting, entry, true);
	if (err)
		goto err;

	if (!entry->bind.orig) {
		/* Bind mount source pathname is mandatory. */
		enbox_conf_err(setting, "missing 'orig' setting");
		err = -ENODATA;
		goto err;
	}

	return 0;

err:
	enbox_conf_err(setting, "invalid tree bind mount entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_proc_flags_entry_setting(const config_setting_t * __restrict setting,
                                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_PROC_ENTRY_TYPE);

	return enbox_load_mount_flags_setting(setting,
	                                      ENBOX_PROC_VALID_FLAGS,
	                                      &ent->mount.flags);
}

static int __enbox_nonull(1, 2)
enbox_load_mount_opts_entry_setting(const config_setting_t * __restrict setting,
                                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_entry * ent = (struct enbox_entry *)data;

	enbox_assert(ent->type == ENBOX_PROC_ENTRY_TYPE);

	return enbox_load_mount_opts_setting(setting, &ent->mount.opts);
}

/* Default procfs mount flags. */
#define ENBOX_MOUNT_PROC_FLAGS \
	(MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME)

/* Default procfs mount options. */
#define ENBOX_MOUNT_PROC_OPTS \
	"hidepid=invisible,subset=pid"

static int __enbox_nonull(1, 2)
enbox_load_proc_entry(const config_setting_t * __restrict setting,
                      struct enbox_entry * __restrict     entry)
{
	enbox_assert(setting);
	enbox_assert(config_setting_is_group(setting));
	enbox_assert(config_setting_length(setting) >= 2);
	enbox_assert(entry);
	enbox_assert(entry->type == ENBOX_PROC_ENTRY_TYPE);

	int                              err;
	static const struct enbox_loader loaders[] = {
		{ .name = "type",  .load = enbox_skip_entry_setting },
		{ .name = "flags", .load = enbox_load_proc_flags_entry_setting },
		{ .name = "opts",  .load = enbox_load_mount_opts_entry_setting }
	};

	entry->path = "proc";
	entry->uid = 0;
	entry->gid = 0;
	entry->mount.flags = ENBOX_MOUNT_PROC_FLAGS;
	entry->mount.opts = ENBOX_MOUNT_PROC_OPTS;

	err = enbox_load_setting(setting,
	                         entry,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	return 0;

err:
	enbox_conf_err(setting, "invalid procfs mount entry");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_jail_entry(const config_setting_t * __restrict setting,
                      void * __restrict                   entry)
{
	enbox_assert(setting);
	enbox_assert(entry);

        struct enbox_entry * ent = (struct enbox_entry *)entry;
	int                  ret;

	switch (ent->type) {
	case ENBOX_FILE_ENTRY_TYPE:
		ret = enbox_load_file_entry(setting, ent);
		break;

	case ENBOX_DIR_ENTRY_TYPE:
		ret = enbox_load_dir_entry(setting, ent, true);
		break;

	case ENBOX_SLINK_ENTRY_TYPE:
		ret = enbox_load_slink_entry(setting, ent, true);
		break;

	case ENBOX_TREE_ENTRY_TYPE:
		ret = enbox_load_tree_entry(setting, ent);
		break;

	case ENBOX_PROC_ENTRY_TYPE:
		ret = enbox_load_proc_entry(setting, ent);
		break;

	default:
		enbox_conf_err(setting, "unexpected jail entry type");
		ret = -ENOSYS;
	}

	return ret;
}

static int __enbox_nonull(1, 3, 4)
enbox_load_entry(const config_setting_t * __restrict setting,
                 unsigned int                        indx,
                 struct enbox_entry * __restrict     entry,
                 enbox_load_setting_fn *             loader)
{
	enbox_assert(setting);
	enbox_assert(entry);
	enbox_assert(loader);

        const config_setting_t * set;
	int                      nr;
	int                      ret;

	set = config_setting_get_elem(setting, indx);
	enbox_assert(set);

	if (!config_setting_is_group(set)) {
		enbox_conf_err(set, "dictionary required");
		return -EINVAL;
	}

	nr = config_setting_length(set);
	enbox_assert(nr >= 0);
	if (nr < 2) {
		/*
		 * Missing entry field definitions.
		 * 'path' and 'type' settings are mandatory for all entries.
		 */
		enbox_conf_err(set, "missing entry setting(s)");
		return -EINVAL;
	}

	entry->path = NULL;
	entry->uid = (uid_t)-1;
	entry->gid = (gid_t)-1;
	ret = enbox_load_type_setting(set, &entry->type);
	if (ret)
		return ret;

	return loader(set, entry);
}

static int __enbox_nonull(1, 2, 3)
enbox_load_fsset(const config_setting_t * __restrict setting,
                 struct enbox_fsset * __restrict     fsset,
                 enbox_load_setting_fn *             loader)
{
	enbox_assert(setting);
	enbox_assert(fsset);
	enbox_assert(!fsset->nr);
	enbox_assert(loader);

	int                  nr;
	struct enbox_entry * entries;
	int                  e;
	int                  err;

	if (!config_setting_is_list(setting)) {
		enbox_conf_err(setting, "list required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		/* No entry definition found. */
		enbox_conf_err(setting, "empty list not allowed");
		return -ENODATA;
	}

	entries = malloc((size_t)nr * sizeof(*entries));
	if (!entries)
		return -ENOMEM;

	for (e = 0; e < nr; e++) {
		err = enbox_load_entry(setting,
		                       (unsigned int)e,
		                       &entries[e],
		                       loader);
		if (err)
			goto free;
	}

	fsset->nr = (unsigned int)nr;
	fsset->entries = entries;

	return 0;

free:
	free(entries);

	return err;
}

static void __enbox_nonull(1)
enbox_unload_fsset(struct enbox_fsset * __restrict fsset)
{
	enbox_assert(fsset);
	enbox_assert(!fsset->nr || fsset->entries);

STROLL_IGNORE_WARN("-Wcast-qual")
	if (fsset->nr)
		free((void *)fsset->entries);
STROLL_RESTORE_WARN
}

static int __enbox_nonull(1, 2)
enbox_load_host(const config_setting_t * __restrict setting,
                void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);
	enbox_assert(!((struct enbox_conf *)data)->host);

	struct enbox_conf *  conf = (struct enbox_conf *)data;
	struct enbox_fsset * host;
	int                  err;

	host = calloc(1, sizeof(*host));
	if (!host)
		return -errno;

	err = enbox_load_fsset(setting, host, enbox_load_host_entry);
	if (err) {
		free(host);
		return err;
	}

	conf->host = host;

	return 0;
}

static void __enbox_nonull(1)
enbox_unload_host(struct enbox_fsset * __restrict host)
{
	enbox_assert(host);

	enbox_unload_fsset(host);
	free(host);
}

static int __enbox_nonull(1, 2)
enbox_load_ids_user(const config_setting_t * __restrict setting,
                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_ids * ids = (struct enbox_ids *)data;

	return enbox_load_pwd_setting(setting, &ids->pwd);
}

static int __enbox_nonull(1, 2, 3)
enbox_load_bool_setting(const config_setting_t * __restrict setting,
                        const char * __restrict             label __unused,
                        bool * __restrict                   value)
{
	enbox_assert(setting);
	enbox_assert(config_setting_name(setting));
	enbox_assert(!strcmp(config_setting_name(setting), label));
	enbox_assert(value);

	if (config_setting_type(setting) != CONFIG_TYPE_BOOL) {
		enbox_conf_err(setting, "boolean required");
		return -EINVAL;
	}

	*value = !!config_setting_get_bool(setting);

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_ids_drop_supp(const config_setting_t * __restrict setting,
                         void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_ids * ids = (struct enbox_ids *)data;

	return enbox_load_bool_setting(setting,
	                               "drop_supp",
	                               &ids->drop_supp);
}

static int __enbox_nonull(1, 2)
enbox_do_load_ids(const config_setting_t * __restrict setting,
                  struct enbox_ids * __restrict       ids)
{
	enbox_assert(setting);
	enbox_assert(ids);
	enbox_assert(!ids->pwd);
	enbox_assert(!ids->drop_supp);

	int                              err;
	int                              nr;
	static const struct enbox_loader loaders[] = {
		{ .name = "user",      .load = enbox_load_ids_user },
		{ .name = "drop_supp", .load = enbox_load_ids_drop_supp }
	};

	if (!config_setting_is_group(setting)) {
		enbox_conf_err(setting, "dictionary required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (nr < 1) {
		/* Missing field definitions. 'user' setting is mandatory. */
		enbox_conf_err(setting, "missing setting(s)");
		return -ENODATA;
	}

	err = enbox_load_setting(setting,
	                         ids,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		goto err;

	if (!ids->pwd) {
		enbox_conf_info(setting, "missing 'user' setting");
		err = -ENODATA;
		goto err;
	}
	enbox_assert(!enbox_validate_pwd(ids->pwd, true));

	return 0;

err:
	enbox_conf_err(setting, "invalid IDs setting");

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_ids(const config_setting_t * __restrict setting,
               void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);
	enbox_assert(!((struct enbox_conf *)data)->ids);

	struct enbox_conf * conf = (struct enbox_conf *)data;
	struct enbox_ids *  ids;
	int                 err;

	ids = calloc(1, sizeof(*ids));
	if (!ids)
		return -errno;

	err = enbox_do_load_ids(setting, ids);
	if (err) {
		free(ids);
		return err;
	}

	conf->ids = ids;

	return 0;
}

static void __enbox_nonull(1)
enbox_unload_ids(struct enbox_ids * __restrict ids)
{
	enbox_assert(ids);

	free((void *)ids);
}

__enbox_flag_descs_storage
const struct enbox_flag_desc enbox_namespace_descs[] = {
	/* Include generated mounting flag descriptor definitions. */
#include "namespaces.i"
	{ NULL, }
};

static int __enbox_nonull(1, 2)
enbox_parse_namespaces_setting(const config_setting_t * __restrict setting,
                               int * __restrict                    namespaces)
{
	enbox_assert(setting);
	enbox_assert(namespaces);

	const char * str;
	unsigned int d;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

	for (d = 0; enbox_namespace_descs[d].kword; d++) {
		if (!memcmp(str,
		            enbox_namespace_descs[d].kword,
		            enbox_namespace_descs[d].len + 1))
			break;
	}

	if (!enbox_namespace_descs[d].kword) {
		enbox_conf_err(setting, "unknown '%s' namespace", str);
		return -ENOENT;
	}

	if (!(enbox_namespace_descs[d].value & ENBOX_VALID_NAMESPACE_FLAGS)) {
		enbox_conf_err(setting, "invalid '%s' namespace", str);
		return -EINVAL;
	}

	if ((unsigned int)*namespaces & enbox_namespace_descs[d].value) {
		enbox_conf_warn(setting,
		                "duplicate '%s' namespace ignored",
		                str);
		return 0;
	}

	*namespaces |= (int)enbox_namespace_descs[d].value;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_namespaces_setting(const config_setting_t * __restrict setting,
                              int * __restrict                    namespaces)
{
	enbox_assert(setting);
	enbox_assert(namespaces);

	int nr;
	int n;
	int ns = 0;

	if (!config_setting_is_array(setting)) {
		enbox_conf_err(setting, "array of strings required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		/* Array is empty: clear all namespaces. */
		*namespaces = 0;
		return 0;
	}

	for (n = 0; n < nr; n++) {
		const config_setting_t * set;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)n);
		enbox_assert(set);

		err = enbox_parse_namespaces_setting(set, &ns);
		if (err)
			return err;
	}

	enbox_assert(!(ns & ~ENBOX_VALID_NAMESPACE_FLAGS));
	*namespaces = ns;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_jail_namespaces(const config_setting_t * __restrict setting,
                           void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_jail * jail = (struct enbox_jail *)data;

	return enbox_load_namespaces_setting(setting, &jail->namespaces);
}

static int __enbox_nonull(1, 2)
enbox_load_jail_root_path(const config_setting_t * __restrict setting,
                          void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_jail * jail = (struct enbox_jail *)data;

	return enbox_load_path_setting(setting, &jail->root_path);
}

static int __enbox_nonull(1, 2)
enbox_load_jail_fsset(const config_setting_t * __restrict setting,
                      void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_jail * jail = (struct enbox_jail *)data;

	return enbox_load_fsset(setting, &jail->fsset, enbox_load_jail_entry);
}

static int __enbox_nonull(1, 2)
enbox_do_load_jail(const config_setting_t * __restrict setting,
                   struct enbox_jail * __restrict      jail)
{
	enbox_assert(setting);
	enbox_assert(jail);
	enbox_assert(!jail->namespaces);
	enbox_assert(!jail->root_path);

	int                              err;
	int                              nr;
	static const struct enbox_loader loaders[] = {
		{ .name = "namespaces",  .load = enbox_load_jail_namespaces },
		{ .name = "path",        .load = enbox_load_jail_root_path },
		{ .name = "fsset",       .load = enbox_load_jail_fsset }
	};

	if (!config_setting_is_group(setting)) {
		enbox_conf_err(setting, "dictionary required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (nr < 1) {
		/*
		 * Missing field definitions:  'path' settings is mandatory.
		 */
		enbox_conf_err(setting, "missing setting(s)");
		return -ENODATA;
	}

	jail->namespaces = ENBOX_VALID_NAMESPACE_FLAGS;
	jail->root_path = NULL;
	jail->fsset.nr = 0;
	jail->fsset.entries = NULL;

	err = enbox_load_setting(setting,
	                         jail,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		return err;

	if (!jail->root_path) {
		enbox_conf_info(setting, "missing 'path' setting");
		return  -ENODATA;
	}

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_jail(const config_setting_t * __restrict setting,
                void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);
	enbox_assert(!((struct enbox_conf *)data)->jail);

	struct enbox_conf * conf = (struct enbox_conf *)data;
	struct enbox_jail * jail;
	int                 err;

	jail = calloc(1, sizeof(*jail));
	if (!jail)
		return -errno;

	err = enbox_do_load_jail(setting, jail);
	if (err) {
		free(jail);
		return err;
	}

	conf->jail = jail;

	return 0;
}

static void __enbox_nonull(1)
enbox_unload_jail(struct enbox_jail * __restrict jail)
{
	enbox_assert(jail);

	enbox_unload_fsset(&jail->fsset);
	free(jail);
}

static int __enbox_nonull(1, 2)
enbox_load_proc_umask(const config_setting_t * __restrict setting,
                      void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_proc * proc = (struct enbox_proc *)data;

	return enbox_load_mode_setting(setting, &proc->umask, ACCESSPERMS);
}

static int __enbox_nonull(1, 2)
enbox_parse_caps_setting(const config_setting_t * __restrict setting,
                         uint64_t * __restrict               caps)
{
	enbox_assert(setting);
	enbox_assert(caps);

	const char * str;
	unsigned int d;
	uint64_t     msk;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

	for (d = 0; enbox_caps_descs[d].kword; d++) {
		if (!memcmp(str,
		            enbox_caps_descs[d].kword,
		            enbox_caps_descs[d].len + 1))
			break;
	}

	if (!enbox_caps_descs[d].kword) {
		enbox_conf_err(setting, "unknown '%s' capability", str);
		return -ENOENT;
	}

	msk = enbox_cap((int)enbox_caps_descs[d].value);
	if (!(msk & ENBOX_CAPS_ALLOWED)) {
		enbox_conf_err(setting, "invalid '%s' capability", str);
		return -EINVAL;
	}

	if (*caps & msk) {
		enbox_conf_warn(setting,
		                "duplicate '%s' capability ignored",
		                str);
		return 0;
	}

	*caps |= msk;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_proc_caps(const config_setting_t * __restrict setting,
                     void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_proc * proc = (struct enbox_proc *)data;
	int                 nr;
	int                 e;
	uint64_t            caps = 0;

	if (!config_setting_is_array(setting)) {
		enbox_conf_err(setting, "array of strings required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		enbox_conf_err(setting, "empty list not allowed");
		return -ENODATA;
	}

	for (e = 0; e < nr; e++) {
		const config_setting_t * set;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)e);
		enbox_assert(set);

		err = enbox_parse_caps_setting(set, &caps);
		if (err)
			return err;
	}

	enbox_assert(caps);
	enbox_assert(!(caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	proc->caps = caps;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_proc_cwd(const config_setting_t * __restrict setting,
                    void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_proc * proc = (struct enbox_proc *)data;

	return enbox_load_path_setting(setting, &proc->cwd);
}

static int __enbox_nonull(1, 2)
enbox_parse_file_desc(const config_setting_t * __restrict setting,
                      int *                               fds,
                      unsigned int                        count)
{
	enbox_assert(setting);
	enbox_assert(fds);

	int          fd;
	unsigned int c;

	if (config_setting_type(setting) != CONFIG_TYPE_INT) {
		enbox_conf_err(setting, "integer expected");
		return -EINVAL;
	}

	fd = config_setting_get_int(setting);
	if (fd < 0) {
		enbox_conf_err(setting, "invalid file descriptor");
		return -ERANGE;
	}

	for (c = 0; c < count; c++) {
		if (fd == fds[c]) {
			enbox_conf_info(
				setting,
				"duplicate '%d' file descriptor ignored",
				fd);
			return -EEXIST;
		}
	}

	fds[count] = fd;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_proc_keep_fds(const config_setting_t * __restrict setting,
                         void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_proc * proc = (struct enbox_proc *)data;
	int                 nr;
	int                 a;
	int *               fds;
	unsigned int        cnt;

	if (!config_setting_is_array(setting)) {
		enbox_conf_err(setting, "array of integers required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		enbox_conf_err(setting, "empty list not allowed");
		return -ENODATA;
	}

	fds = malloc(((size_t)nr + 1) * sizeof(fds[0]));
	if (!fds)
		return -ENOMEM;

	cnt = 0;
	for (a = 0; a < nr; a++) {
		const config_setting_t * set;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)a);
		enbox_assert(set);

		err = enbox_parse_file_desc(set, fds, cnt);
		switch (err) {
		case 0:
			cnt++;
			break;

		case -EEXIST:
			break;

		default:
			free(fds);
			return err;
		}
	}

	proc->fds_nr = (unsigned int)nr;
	proc->fds = fds;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_do_load_proc(const config_setting_t * __restrict setting,
                   struct enbox_proc * __restrict      proc)
{
	enbox_assert(setting);
	enbox_assert(proc);
	enbox_assert(!proc->umask);
	enbox_assert(!proc->caps);
	enbox_assert(!proc->cwd);
	enbox_assert(!proc->fds_nr);
	enbox_assert(!proc->fds);

	int                              err;
	int                              nr;
	static const struct enbox_loader loaders[] = {
		{ .name = "umask",    .load = enbox_load_proc_umask },
		{ .name = "caps",     .load = enbox_load_proc_caps },
		{ .name = "cwd",      .load = enbox_load_proc_cwd },
		{ .name = "keep_fds", .load = enbox_load_proc_keep_fds }
	};

	if (!config_setting_is_group(setting)) {
		enbox_conf_err(setting, "dictionary required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (nr < 1) {
		/* Missing field definitions. */
		enbox_conf_err(setting, "missing setting(s)");
		return -ENODATA;
	}

	proc->umask = (mode_t)-1;

	err = enbox_load_setting(setting,
	                         proc,
	                         loaders,
	                         stroll_array_nr(loaders));
	if (err)
		return err;

	if (proc->umask == (mode_t)-1)
		proc->umask = 0077;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_proc(const config_setting_t * __restrict setting,
                void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);
	enbox_assert(!((struct enbox_conf *)data)->proc);

	struct enbox_conf * conf = (struct enbox_conf *)data;
	struct enbox_proc * proc;
	int                 err;

	proc = calloc(1, sizeof(*proc));
	if (!proc)
		return -errno;

	err = enbox_do_load_proc(setting, proc);
	if (err) {
		free(proc);
		return err;
	}

	conf->proc = proc;

	return 0;
}

static void __enbox_nonull(1)
enbox_unload_proc(struct enbox_proc * __restrict proc)
{
	enbox_assert(proc);

STROLL_IGNORE_WARN("-Wcast-qual")
	free((void *)proc->fds);
STROLL_RESTORE_WARN
	free(proc);
}

static int __enbox_nonull(1, 2)
enbox_parse_exec_arg(const config_setting_t * __restrict setting,
                     const char ** __restrict            arg)
{
	enbox_assert(setting);
	enbox_assert(arg);

	const char * str;
	int          err;

	str = config_setting_get_string(setting);
	if (!str) {
		enbox_conf_err(setting, "string required");
		return -EINVAL;
	}

	err = enbox_validate_exec_arg(str);
	switch (err) {
	case 0:
		break;

	case -ENODATA:
		enbox_conf_err(setting, "empty argument not allowed");
		return -ENODATA;

	case -ENAMETOOLONG:
		enbox_conf_err(setting, "argument too long");
		return -ENAMETOOLONG;

	default:
		enbox_assert(0);
	}

	*arg = str;

	return 0;
}

static int __enbox_nonull(1, 2)
enbox_load_cmd(const config_setting_t * __restrict setting,
               void * __restrict                   data)
{
	enbox_assert(setting);
	enbox_assert(data);

	struct enbox_conf * conf = (struct enbox_conf *)data;
	int                 nr;
	int                 a;
	const char **       exec;

	if (!config_setting_is_array(setting)) {
		enbox_conf_err(setting, "array of strings required");
		return -EINVAL;
	}

	nr = config_setting_length(setting);
	enbox_assert(nr >= 0);
	if (!nr) {
		enbox_conf_err(setting, "empty list not allowed");
		return -ENODATA;
	}
	else if ((unsigned int)nr > ENBOX_EXEC_ARGS_MAX) {
		enbox_conf_err(setting, "too many arguments");
		return -E2BIG;
	}

	exec = malloc(((size_t)nr + 1) * sizeof(exec[0]));
	if (!exec)
		return -ENOMEM;

	for (a = 0; a < nr; a++) {
		const config_setting_t * set;
		int                      err;

		set = config_setting_get_elem(setting, (unsigned int)a);
		enbox_assert(set);

		err = enbox_parse_exec_arg(set, &exec[a]);
		if (err) {
			free(exec);
			return err;
		}
	}

	exec[nr] = NULL;

	enbox_assert(!enbox_validate_exec(exec));
	conf->cmd = exec;

	return 0;
}

static void __enbox_nonull(1)
enbox_unload_cmd(const char ** __restrict cmd)
{
	enbox_assert(cmd);

	free((void *)cmd);
}

static void __enbox_nonull(1)
enbox_unload_conf(struct enbox_conf * __restrict conf)
{
	enbox_assert(conf);

	if (conf->host)
		enbox_unload_host(conf->host);
	if (conf->ids)
		enbox_unload_ids(conf->ids);
	if (conf->jail)
		enbox_unload_jail(conf->jail);
	if (conf->proc)
		enbox_unload_proc(conf->proc);
	if (conf->cmd)
		enbox_unload_cmd(conf->cmd);
}

static int __enbox_nonull(1)
enbox_load_conf(struct enbox_conf * __restrict conf)
{
	enbox_assert(conf);
	enbox_assert(!conf->host);
	enbox_assert(!conf->ids);
	enbox_assert(!conf->jail);
	enbox_assert(!conf->proc);
	enbox_assert(!conf->cmd);

	int                              err;
	const config_setting_t *         root;
	static const struct enbox_loader loaders[] = {
		{ .name = "host", .load = enbox_load_host },
		{ .name = "ids",  .load = enbox_load_ids },
		{ .name = "jail", .load = enbox_load_jail },
		{ .name = "proc", .load = enbox_load_proc },
		{ .name = "cmd",  .load = enbox_load_cmd }
	};

	/*
	 * Root / top-level setting should always exist since already parsed by
	 * caller.
	 */
	root = config_root_setting(&conf->lib);
	enbox_assert(root);

	err = enbox_load_setting(root, conf, loaders, stroll_array_nr(loaders));
	if (err)
		goto err;

	err = -ENODATA;
	if (conf->cmd) {
		if (!conf->proc) {
			/*
			 * 'proc' setting is mandatory when a 'cmd' setting is
			 * is enabled.
			 */
			enbox_err("%s: missing 'proc' setting",
			          config_setting_source_file(root));
			goto err;
		}
	}
	else {
		if (!conf->host) {
			/*
			 * 'host' setting is mandatory when no 'cmd' setting is
			 * is found.
			 */
			enbox_err("%s: missing 'host' setting",
			          config_setting_source_file(root));
			goto err;
		}

		if (conf->ids) {
			enbox_unload_ids(conf->ids);
			conf->ids = NULL;
			enbox_warn("%s: ignoring useless 'ids' setting",
			           config_setting_source_file(root));
		}

		if (conf->jail) {
			enbox_unload_jail(conf->jail);
			conf->jail = NULL;
			enbox_warn("%s: ignoring useless 'jail' setting",
			           config_setting_source_file(root));
		}

		if (conf->proc) {
			enbox_unload_proc(conf->proc);
			conf->proc = NULL;
			enbox_warn("%s: ignoring useless 'proc' setting",
			           config_setting_source_file(root));
		}
	}

	return 0;

err:
	enbox_unload_conf(conf);

	return err;
}

static int __enbox_nonull(1, 2)
enbox_load_conf_file(struct enbox_conf * __restrict conf,
                     const char * __restrict        path)
{
	enbox_assert(conf);
	enbox_assert(!conf->host);
	enbox_assert(!conf->jail);
	enbox_assert(!conf->proc);
	enbox_assert(!conf->cmd);
	enbox_assert(upath_validate_path_name(path) > 0);

	int err;

	config_init(&conf->lib);

	/* Setup default include directory path. */
	config_set_include_dir(&conf->lib, CONFIG_ENBOX_INCLUDE_DIR);

	/*
	 * Setup default parser options:
	 * - no setting value automatic type conversion,
	 * - no duplicate settings,
	 * - no required semicolon separators.
	 */
	config_set_options(&conf->lib, 0);

	if (!config_read_file(&conf->lib, path)) {
		switch (config_error_type(&conf->lib)) {
		case CONFIG_ERR_FILE_IO:
			err = -errno;
			enbox_err("%s: cannot load file: %s (%d)",
			          path,
			          strerror(-err),
			          -err);
			goto destroy;

		case CONFIG_ERR_PARSE:
			err = -EINVAL;
			enbox_err("%s: line %d: %s",
			          config_error_file(&conf->lib),
			          config_error_line(&conf->lib),
			          config_error_text(&conf->lib));
			goto destroy;

		default:
			enbox_assert(0);
		}
	}

	err = enbox_load_conf(conf);
	if (err)
		goto destroy;

	return 0;

destroy:
	enbox_err("%s: invalid configuration", path);
	config_destroy(&conf->lib);

	return err;
}

int
enbox_run_conf(const struct enbox_conf * __restrict conf)
{
	enbox_assert_setup();
	enbox_assert_conf(conf);

	int ret;

	if (conf->host) {
		ret = enbox_populate_host(conf->host);
		if (ret)
			goto out;
	}

	if (conf->proc) {
		ret = enbox_prep_proc(conf->proc, conf->ids, conf->jail);
		if (ret)
			goto out;

		ret = enbox_run_proc(conf->proc, conf->ids, conf->cmd);
		if (ret)
			goto out;
	}

	return 0;

out:
	{
		const config_setting_t * root;

		root = config_root_setting(&conf->lib);
		enbox_assert(root);

		enbox_err("%s: cannot run configuration: %s (%d)",
		          config_setting_source_file(root),
		          strerror(-ret),
		          -ret);
	}

	return ret;
}

struct enbox_conf *
enbox_create_conf_from_file(const char * __restrict path)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);

	struct enbox_conf * conf;
	int                 err;

	conf = calloc(1, sizeof(*conf));
	if (!conf)
		return NULL;

	err = enbox_load_conf_file(conf, path);
	if (err)
		goto free;

	return conf;

free:
	free(conf);
	errno = -err;

	return NULL;
}

void
enbox_destroy_conf(struct enbox_conf * __restrict conf)
{
	enbox_assert_setup();
	enbox_assert_conf(conf);

	enbox_unload_conf(conf);
	config_destroy(&conf->lib);
	free(conf);
}
