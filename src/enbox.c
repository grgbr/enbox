/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "conf.h"
#include <utils/path.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#if !defined(CONFIG_ELOG_HAVE_FACILITY)
#error eLog facility support required ! \
       Enable eLog CONFIG_ELOG_HAVE_FACILITY build configuration option !
#endif /* !defined(CONFIG_ELOG_HAVE_FACILITY) */

/******************************************************************************
 * Display logic
 ******************************************************************************/

#if defined(CONFIG_ENBOX_SHOW)

#include "show.h"
#include "namespaces.h"
#include "mount_flags.h"
#include "capabilities.h"
#include <stroll/bmap.h>

static __enbox_nonull(1)
void
enbox_show_dir_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SIZE];

	printf("d%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dir.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static __enbox_nonull(1)
void
enbox_show_slink_entry(const struct enbox_entry * __restrict ent)
{
	printf("lrwxrwxrwx %u(%s) %u(%s) %s -> %s\n",
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path,
	       ent->slink.target);
}

static __enbox_nonull(1)
void
enbox_show_chrdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SIZE];

	printf("c%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dev.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static __enbox_nonull(1)
void
enbox_show_blkdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SIZE];

	printf("b%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dev.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static __enbox_nonull(1)
void
enbox_show_fifo_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SIZE];

	printf("p%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->fifo.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static __enbox_nonull(2, 4) __enbox_nothrow __warn_result
size_t
enbox_fill_flag_descs_string(unsigned long                  flags,
                             char *                         string,
                             size_t                         size __unused,
                             const struct enbox_flag_desc * descs)
{
	enbox_assert(string);
	enbox_assert(size);
	enbox_assert(descs);

	unsigned int d;
	size_t       len = 0;

	for (d = 0; descs[d].kword; d++) {
		if (flags & descs[d].value) {
			enbox_assert((len + (len ? 1 : 0) + descs[d].len) <
			             size);

			if (len)
				string[len++] = ',';
			memcpy(&string[len], descs[d].kword, descs[d].len);
			len += descs[d].len;
		}
	}

	string[len] = '\0';

	return len;
}

static __nothrow __returns_nonull __warn_result
void *
xalloc(size_t size)
{
	void * ptr;

	ptr = malloc(size);
	if (!ptr)
		exit(EXIT_FAILURE);

	return ptr;
}

static __nothrow __returns_nonull __warn_result
char *
enbox_build_mount_flags_string(unsigned long flags, const char * opts)
{
	size_t olen = opts ? strlen(opts) : 0;
	char * str;
	size_t len;

	/*
	 * Allocate a string large enough to hold the full comma separated list
	 * of supported mounting flags + 1 comma character + the options string
	 * passed in arguments.
	 *
	 * ENBOX_MOUNT_FLAGS_LEN is defined into generated.h (see top-level
	 * header inclusions of this source file).
	 */
	str = xalloc(ENBOX_MOUNT_FLAGS_LEN + 1 + olen + 1);

	len = enbox_fill_flag_descs_string(flags,
	                                   str,
	                                   ENBOX_MOUNT_FLAGS_LEN + 1,
	                                   enbox_mount_flag_descs);
	/*
	 * Ensure the length of stringified comma separated keyword list is
	 * <= ENBOX_MOUNT_FLAGS_LEN.
	 */
	enbox_assert(len <= ENBOX_MOUNT_FLAGS_LEN);

	if (opts) {
		enbox_assert(opts[0]);

		if (len)
			str[len++] = ',';
		memcpy(&str[len], opts, olen);
		len += olen;
	}

	str[len] = '\0';

	return str;
}

static __enbox_nonull(1)
void
enbox_show_proc_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent);

	char * flags;

	flags = enbox_build_mount_flags_string(ent->mount.flags,
	                                       ent->mount.opts);

	printf("dr-xr-xr-x 0(root) 0(root) proc[none] <%s>\n",
	       flags ? flags : "??");

	/* Using glibc, we may safely free(NULL)... */
	free(flags);
}

static __enbox_nonull(1)
void
enbox_show_bind_entry(const struct enbox_entry * __restrict ent,
                      mode_t                                type)
{
	enbox_assert(ent);
	enbox_assert(!(type & ~((mode_t)S_IFMT)));

	int         err;
	struct stat stat;
	char *      flags;

	err = upath_lstat(ent->bind.orig, &stat);

	flags = enbox_build_mount_flags_string(ent->bind.flags, ent->bind.opts);

	if (!err) {
		char sym;
		char mode[ENBOX_MODE_STRING_SIZE];

		switch (stat.st_mode & type) {
		case S_IFDIR:
			sym = 'd';
			break;
		case S_IFCHR:
			sym = 'c';
			break;
		case S_IFBLK:
			sym = 'b';
			break;
		case S_IFREG:
			sym = '-';
			break;
		case S_IFIFO:
			sym = 'p';
			break;
		default:
			sym = 'X';
		}

		enbox_build_mode_string(mode, stat.st_mode & ALLPERMS);

		printf("%c%s %u(%s) %u(%s) %s[%s] <%s>\n",
		       sym,
		       mode,
		       stat.st_uid,
		       enbox_get_user_name(stat.st_uid),
		       stat.st_gid,
		       enbox_get_group_name(stat.st_gid),
		       ent->path,
		       ent->bind.orig,
		       flags ? flags : "??");
	}
	else {
		/* Escape trigraphs to avoid spurious warning... */
		printf("?????????? ?(?\?) ?(?\?) %s[%s] <%s>\n",
		       ent->path,
		       ent->bind.orig,
		       flags ? flags : "??");
	}

	/* Using glibc, we may safely free(NULL)... */
	free(flags);
}

static __enbox_nonull(1)
void
enbox_show_tree_entry(const struct enbox_entry * __restrict ent)
{
	enbox_show_bind_entry(ent, S_IFDIR);
}

static __enbox_nonull(1)
void
enbox_show_file_entry(const struct enbox_entry * __restrict ent)
{
	enbox_show_bind_entry(ent, S_IFREG | S_IFIFO);
}

typedef void (enbox_show_entry_fn)(const struct enbox_entry * __restrict entry)
	__enbox_nonull(1);

static __enbox_nonull(1)
void
enbox_show_fsset(const struct enbox_fsset * __restrict fsset,
                 enbox_show_entry_fn * const            showers[__restrict_arr])
{
	enbox_assert(fsset);
	enbox_assert(!fsset->nr || fsset->entries);
	enbox_assert(showers);

	if (fsset->nr) {
		unsigned int e;

		for (e = 0; e < fsset->nr; e++) {
			const struct enbox_entry * ent = &fsset->entries[e];

			enbox_assert_entry(ent);
			enbox_assert(showers[ent->type]);
			showers[ent->type](ent);
		}
	}
	else
		puts("No entry found");
}

static __enbox_nonull(1)
void
enbox_show_host_conf(const struct enbox_fsset * __restrict host)
{
	enbox_assert(host);
	enbox_assert(host->nr);
	enbox_assert(host->entries);

	static enbox_show_entry_fn * const showers[] = {
		[ENBOX_DIR_ENTRY_TYPE]    = enbox_show_dir_entry,
		[ENBOX_SLINK_ENTRY_TYPE]  = enbox_show_slink_entry,
		[ENBOX_CHRDEV_ENTRY_TYPE] = enbox_show_chrdev_entry,
		[ENBOX_BLKDEV_ENTRY_TYPE] = enbox_show_blkdev_entry,
		[ENBOX_FIFO_ENTRY_TYPE]   = enbox_show_fifo_entry,
		[ENBOX_PROC_ENTRY_TYPE]   = NULL,
		[ENBOX_TREE_ENTRY_TYPE]   = NULL,
		[ENBOX_FILE_ENTRY_TYPE]   = NULL
	};

	puts("\n### Host filesystem entries ###\n");
	enbox_show_fsset(host, showers);
}

static __enbox_nonull(1)
void
enbox_show_jail_conf(const struct enbox_jail * __restrict jail)
{
	enbox_assert_jail(jail);

	char *                             ns;
	size_t                             len __unused;
	static enbox_show_entry_fn * const showers[] = {
		[ENBOX_DIR_ENTRY_TYPE]    = enbox_show_dir_entry,
		[ENBOX_SLINK_ENTRY_TYPE]  = enbox_show_slink_entry,
		[ENBOX_CHRDEV_ENTRY_TYPE] = NULL,
		[ENBOX_BLKDEV_ENTRY_TYPE] = NULL,
		[ENBOX_FIFO_ENTRY_TYPE]   = NULL,
		[ENBOX_PROC_ENTRY_TYPE]   = enbox_show_proc_entry,
		[ENBOX_TREE_ENTRY_TYPE]   = enbox_show_tree_entry,
		[ENBOX_FILE_ENTRY_TYPE]   = enbox_show_file_entry
	};

	ns = xalloc(ENBOX_NAMESPACES_LEN + 1);

	len = enbox_fill_flag_descs_string((unsigned long)jail->namespaces,
	                                   ns,
	                                   ENBOX_NAMESPACES_LEN + 1,
	                                   enbox_namespace_descs);
	/*
	 * Ensure the length of stringified comma separated keyword list
	 * is <= ENBOX_NAMESPACES_LEN.
	 */
	enbox_assert(len <= ENBOX_NAMESPACES_LEN);

	puts("\n### Jail attributes ###\n");
	printf("Namespaces: %s\n", ns);
	printf("Root path : %s\n", jail->root_path);

	puts("\n### Jail filesystem entries ###\n");
	enbox_show_fsset(&jail->fsset, showers);

	free(ns);
}

static __enbox_nonull(2) __enbox_nothrow __warn_result
ssize_t
enbox_fill_group_name(gid_t gid, char * string, size_t size)
{
	enbox_assert(string);
	enbox_assert(size);

	const struct group * grp;
	size_t               len;

	grp = upwd_get_group_byid(gid);
	if (!grp)
		return -ENOENT;

	len = strnlen(grp->gr_name, LOGIN_NAME_MAX);
	if (!len || (len >= LOGIN_NAME_MAX))
		return -EINVAL;

	len = (size_t)snprintf(string, size, "%hu(%s)", gid, grp->gr_name);
	enbox_assert((int)len > 0);
	enbox_assert(len <= (SSIZE_MAX));
	if (len >= size)
		return -EMSGSIZE;

	return (ssize_t)len;
}

/*
 * Maximum size of string that may hold a comma separated list of user
 * supplementary groups and including primary group.
 *
 * NGROUPS_MAX + 1   : max number of supplementary groups + 1 primary group
 * LOGIN_NAME_MAX - 1: max length of a group name
 * NGROUPS_MAX       : max number of separating commas
 * 1                 : terminating NULL byte.
 */
#define ENBOX_GROUP_LIST_SIZE \
	(((NGROUPS_MAX + 1) * (LOGIN_NAME_MAX - 1)) + \
	 NGROUPS_MAX + \
	 1)

static __enbox_nonull(1, 2) __enbox_nothrow __warn_result
int
enbox_fill_user_groups(char                             string[__restrict_arr],
                       const struct passwd * __restrict pwd,
                       bool                             drop_supp)
{
	enbox_assert(string);
	enbox_assert(pwd);

	size_t  left = ENBOX_GROUP_LIST_SIZE;
	ssize_t ret;

	/* Fill in primary group first. */
	ret = enbox_fill_group_name(pwd->pw_gid, string, left);
	enbox_assert(ret);
	if (ret < 0)
		return (int)ret;

	enbox_assert((size_t)ret < left);

	if (!drop_supp) {
		gid_t * gids;
		int     nr = NGROUPS_MAX + 1;
		int     g;

		gids = xalloc((size_t)nr * sizeof(*gids));

		left -= (size_t)ret;

		/*
		 * Primary group shall always be part of the returned list.
		 * See getgrouplist(3) man page for more infos.
		 */
		ret = getgrouplist(pwd->pw_name, pwd->pw_gid, gids, &nr);
		enbox_assert(ret >= 0);
		if (ret < 1) {
			ret = -ENODATA;
			goto free;
		}

		for (g = 0; (g < nr) && (left > 2) ; g++) {
			enbox_assert(left > 2);
			enbox_assert(left < ENBOX_GROUP_LIST_SIZE);

			char * str = &string[ENBOX_GROUP_LIST_SIZE - left];

			/*
			 * Skip primary group since it has already been filled
			 * in first.
			 */
			if (gids[g] == pwd->pw_gid)
				continue;

			/* append comma... */
			str[0] = ',';

			ret = enbox_fill_group_name(gids[g], &str[1], left - 1);
			enbox_assert(ret);
			if (ret < 0)
				goto free;

			enbox_assert((size_t)ret <= (left - 1));
			left -= (size_t)ret + 1;
		}

		if (g == nr)
			/* Group list completed. */
			ret = 0;

free:
		free(gids);
	}
	else
		/* Group list completed. */
		ret = 0;

	return (int)ret;
}

static __enbox_nonull(1)
void
enbox_show_ids_conf(const struct enbox_ids * __restrict ids)
{
	enbox_assert(ids);
	enbox_assert(!enbox_validate_pwd(ids->pwd, true));

	const struct passwd * pwd = ids->pwd;
	char *                grps = NULL;

	puts("\n### Credentials ###\n");

	/*
	 * Allocate a string large enough to hold a comma separated list
	 * of supplementary groups (including primary group).
	 */
	grps = xalloc(ENBOX_GROUP_LIST_SIZE);

	if (!enbox_fill_user_groups(grps, pwd, ids->drop_supp)) {
		printf("User             : %u(%s)\n", pwd->pw_uid, pwd->pw_name);
		printf("Groups           : %s\n", grps);

		goto free;
	}

	puts("User               : ?(?\?)");
	puts("Groups             : ?");

free:
	free(grps);
}

static __enbox_nothrow __returns_nonull __warn_result
char *
enbox_build_caps_string(uint64_t caps)
{
	enbox_assert(caps);
	enbox_assert(!(caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	char *       str;
	uint64_t     iter;
	unsigned int c;
	size_t       len = 0;

	str = xalloc(ENBOX_CAPABILITIES_LEN + 1);

	stroll_bmap_foreach_set64(&iter, caps, &c) {
		enbox_assert((len + (len ? 1 : 0) + enbox_caps_descs[c].len) <=
		             ENBOX_CAPABILITIES_LEN);

		if (len)
			str[len++] = ',';
		memcpy(&str[len],
		       enbox_caps_descs[c].kword,
		       enbox_caps_descs[c].len);
		len += enbox_caps_descs[c].len;
	}

	str[len] = '\0';

	return str;
}

static __enbox_nonull(1)
void
enbox_show_proc_conf(const struct enbox_proc * __restrict proc)
{
	enbox_assert_proc(proc);

	unsigned int i;

	puts("\n### Process ###\n");

	printf("Umask            : %04o\n", proc->umask);

	if (proc->caps) {
		char * str;

		str = enbox_build_caps_string(proc->caps);
		printf("Capabilities     : %s\n", str);
		free(str);
	}
	else
		fputs("Capabilities     : none\n", stdout);

	printf("Working directory: %s\n", proc->cwd ? proc->cwd : "/");

	if (proc->fds_nr) {
		printf("Keep file descs  : %d", proc->fds[0]);
		for (i = 1; i < proc->fds_nr; i++)
			printf(", %d", proc->fds[i]);
		putchar('\n');
	}
	else
		fputs("Keep file descs  : none\n", stdout);

	if (proc->env_nr) {
		const struct enbox_env_var * var = &proc->env[0];

		printf("Environment      : %s%s%s%s",
		       var->name,
		       var->value ? "='" : "",
		       var->value ? var->value : "",
		       var->value ? "'" : "");
		for (i = 1; i < proc->env_nr; i++) {
			var = &proc->env[i];
			printf(", %s%s%s%s",
			       var->name,
			       var->value ? "='" : "",
			       var->value ? var->value : "",
			       var->value ? "'" : "");
		}
		putchar('\n');
	}
	else
		fputs("Environment      : none\n", stdout);
}

static __enbox_nonull(1)
void
enbox_show_cmd_conf(const char * const cmd[__restrict_arr])
{
	enbox_assert_cmd(cmd);

	unsigned int a = 0;

	puts("\n### Command ###\n");

	fputs(cmd[0], stdout);
	while (cmd[++a])
		printf(" %s", cmd[a]);
	putchar('\n');
}

static __enbox_nonull(1)
void
enbox_show_conf(const struct enbox_conf * __restrict conf)
{
	enbox_assert_conf(conf);

	if (conf->host)
		enbox_show_host_conf(conf->host);
	if (conf->ids)
		enbox_show_ids_conf(conf->ids);
	if (conf->jail)
		enbox_show_jail_conf(conf->jail);
	if (conf->proc)
		enbox_show_proc_conf(conf->proc);
	if (conf->cmd)
		enbox_show_cmd_conf(conf->cmd);
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

/******************************************************************************
 * Main logic
 ******************************************************************************/

#define show_error(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

/* Make sure configured log facility is consistent with <sys/syslog.h> */
#if (CONFIG_ENBOX_TOOL_LOG_FACILITY < 0) || \
    (CONFIG_ENBOX_TOOL_LOG_FACILITY >= LOG_NFACILITIES)
#error Log facility configured at build time is invalid !
#endif
#define ENBOX_TOOL_LOG_FACILITY \
	(CONFIG_ENBOX_TOOL_LOG_FACILITY << 3)

#if defined(CONFIG_ENBOX_SHOW)
#define SHOW_USAGE \
"\n" \
"    %1$s [OPTIONS] show <CONFIG>\n" \
"    Show configuration settings loaded from CONFIG\n" \
"\n" \
"    %1$s [OPTIONS] status\n" \
"    Show status\n"
#else  /* defined(CONFIG_ENBOX_SHOW) */
#define SHOW_USAGE
#endif /* defined(CONFIG_ENBOX_SHOW) */

#define USAGE \
"Usage: Enbox sandboxing tool.\n" \
SHOW_USAGE \
"\n" \
"    %1$s [OPTIONS] run <CONFIG>\n" \
"    Run / execute configuration loaded from CONFIG\n" \
"\n" \
"With OPTIONS:\n" \
"    --log-tag=TAG              -- log message using tag TAG\n" \
"                                  (defaults to `%1$s')\n" \
"    --stdlog-level=SEVERITY    -- set console log verbosity level to SEVERITY\n" \
"                                  (defaults to `%2$s')\n" \
"    --syslog-level=SEVERITY    -- set syslog verbosity level to SEVERITY\n" \
"                                  (defaults to `none')\n" \
"    --syslog-facility=FACILITY -- set syslog facility to FACILITY\n" \
"                                  (defaults to `%3$s')\n" \
"    --mqlog-level=SEVERITY     -- set message queue log verbosity level to SEVERITY\n" \
"                                  (defaults to `none')\n" \
"    --mqlog-facility=FACILITY  -- set syslog facility to FACILITY\n" \
"                                  (defaults to `%3$s')\n" \
"    --mqlog-name=NAME          -- use NAME as logging message queue name\n" \
"                                  (defaults to `" CONFIG_ENBOX_TOOL_MQLOG_NAME "')\n" \
"    -h | --help                -- this help message\n" \
"\n" \
"Where:\n" \
"    CONFIG   -- pathname to an Enbox configuration file\n" \
"    TAG      -- logging message tag\n" \
"    NAME     -- POSIX message queue name, including the leading `/'\n" \
"    SEVERITY := none|dflt|emerg|alert|crit|err|warn|notice|info\n" \
"    FACILITY := dflt|auth|authpriv|cron|daemon|ftp|lpr|mail|news|syslog|user\n" \
"                |local0|local1|local2|local3|local4|local5|local6|local7\n" \

static
void
show_usage(void)
{
	fprintf(stderr,
	        USAGE,
	        program_invocation_short_name,
	        elog_get_severity_label(CONFIG_ENBOX_TOOL_LOG_SEVERITY),
	        elog_get_facility_label(ENBOX_TOOL_LOG_FACILITY));
}

struct enbox_log_parse {
	struct elog_parse std;
	struct elog_parse sys;
	struct elog_parse mq;
};

enum enbox_log_kind {
	ENBOX_STDLOG = 1U << 0,
	ENBOX_SYSLOG = 1U << 1,
	ENBOX_MQLOG  = 1U << 2
};

struct enbox_log_conf {
	unsigned int            subs;
	struct elog_stdio_conf  std;
	struct elog_syslog_conf sys;
	struct elog_mqueue_conf mq;
};

static __enbox_nonull(1, 2, 4) __enbox_nothrow
int
enbox_log_parse_level(struct enbox_log_parse * __restrict parse,
                      struct enbox_log_conf * __restrict  config,
                      enum enbox_log_kind                 kind,
                      const char * __restrict             arg)
{
	enbox_assert(parse);
	enbox_assert(config);
	enbox_assert(kind);
	enbox_assert(arg);

	if (strcmp(arg, "none")) {
		struct elog_parse * prs;
		struct elog_conf *  cfg;

		switch (kind) {
		case ENBOX_STDLOG:
			prs = &parse->std;
			cfg = &config->std.super;
			break;

		case ENBOX_SYSLOG:
			prs = &parse->sys;
			cfg = &config->sys.super;
			break;

		case ENBOX_MQLOG:
			prs = &parse->mq;
			cfg = &config->mq.super;
			break;

		default:
			enbox_assert(0);
		}

		if (elog_parse_severity(prs, cfg, arg)) {
			show_error("%s.\n\n", prs->error);
			return EXIT_FAILURE;
		}

		config->subs |= kind;
	}
	else
		config->subs &= ~kind;

	return EXIT_SUCCESS;
}

static __enbox_nonull(1, 2)
int
enbox_log_realize_parse(struct enbox_log_parse * __restrict parse,
                        struct enbox_log_conf * __restrict  config)
{
	enbox_assert(parse);
	enbox_assert(config);

	if (config->subs & ENBOX_STDLOG) {
		if (elog_realize_parse(&parse->std, &config->std.super)) {
			show_error("%s.\n\n", parse->std.error);
			return EXIT_FAILURE;
		}
	}

	if (config->subs & ENBOX_SYSLOG) {
		if (elog_realize_parse(&parse->sys, &config->sys.super)) {
			show_error("%s.\n\n", parse->sys.error);
			return EXIT_FAILURE;
		}
	}

	if (config->subs & ENBOX_MQLOG) {
		if (elog_realize_parse(&parse->mq, &config->mq.super)) {
			show_error("%s.\n\n", parse->mq.error);
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

static __enbox_nonull(1, 2) __enbox_nothrow
void
enbox_log_init_parse(struct enbox_log_parse * __restrict parse,
                     struct enbox_log_conf * __restrict  config)
{
	enbox_assert(parse);
	enbox_assert(config);

	static const struct elog_stdio_conf  std_dflt = {
		.super.severity = CONFIG_ENBOX_TOOL_LOG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	static const struct elog_syslog_conf sys_dflt = {
		.super.severity = CONFIG_ENBOX_TOOL_LOG_SEVERITY,
		.format         = ELOG_PID_FMT,
		.facility       = ENBOX_TOOL_LOG_FACILITY
	};
	static const struct elog_mqueue_conf mq_dflt = {
		.super.severity = CONFIG_ENBOX_TOOL_LOG_SEVERITY,
		.facility       = ENBOX_TOOL_LOG_FACILITY,
		.name           = CONFIG_ENBOX_TOOL_MQLOG_NAME
	};

	elog_init_stdio_parse(&parse->std, &config->std, &std_dflt);
	config->subs = ENBOX_STDLOG;
	elog_init_syslog_parse(&parse->sys, &config->sys, &sys_dflt);
	elog_init_mqueue_parse(&parse->mq, &config->mq, &mq_dflt);
}

static __enbox_nonull(1) __enbox_nothrow
void
enbox_log_fini_parse(struct enbox_log_parse * __restrict parse)
{
	enbox_assert(parse);

	elog_fini_parse(&parse->mq);
	elog_fini_parse(&parse->sys);
	elog_fini_parse(&parse->std);
}

struct enbox_log {
	struct elog *      top;
	struct elog_multi  multi;
	struct elog_stdio  std;
	struct elog_syslog sys;
	struct elog_mqueue mq;
};

static __enbox_nonull(1, 3)
int
enbox_log_enable(struct enbox_log * __restrict      log,
                 const char * __restrict            tag,
                 struct enbox_log_conf * __restrict config)
{
	enbox_assert(log);
	enbox_assert(config);

	int err = -ENOMEM;

	if ((config->std.super.severity < 0) &&
	    (config->sys.super.severity < 0) &&
	    (config->mq.super.severity < 0)) {
		log->top = NULL;
		return 0;
	}

	elog_setup(tag, ELOG_DFLT_PID);

	elog_init_multi(&log->multi, elog_fini);

	if (config->subs & ENBOX_STDLOG) {
		elog_init_stdio(&log->std, &config->std);
		if(elog_register_multi_sublog(&log->multi, &log->std.super))
			goto fini;
	}

	if (config->subs & ENBOX_SYSLOG) {
		elog_init_syslog(&log->sys, &config->sys);
		if (elog_register_multi_sublog(&log->multi, &log->sys.super))
			goto fini;
	}

	if (config->subs & ENBOX_MQLOG) {
		err = elog_init_mqueue(&log->mq, &config->mq);
		if (err) {
			show_error("failed to initialize message queue logger: "
			           "%s (%d).\n",
			           strerror(-err),
			           -err);
			goto fini;
		}
		if (elog_register_multi_sublog(&log->multi, &log->mq.super))
			goto fini;
	}

	log->top = &log->multi.super;

	return 0;

fini:
	elog_fini_multi(&log->multi);

	return err;
}

static __enbox_nonull(1)
void
enbox_log_fini(struct enbox_log * __restrict log)
{
	enbox_assert(log);

	if (log->top)
		elog_fini(log->top);
}

enum {
	INVALID_CMD = -1,
	NONE_CMD,
	RUN_CMD,
#if defined(CONFIG_ENBOX_SHOW)
	SHOW_CMD,
	STAT_CMD
#endif /* defined(CONFIG_ENBOX_SHOW) */
};

static __enbox_nonull(2)
int
enbox_validate_conf_cmd(int argc, char * const argv[])
{
	enbox_assert(argv);

	if (argc != 2) {
		show_error("invalid number of arguments.\n\n");
		return EXIT_FAILURE;
	}

	if (upath_validate_path_name(argv[1]) < 0) {
		show_error("'%s': "
		           "invalid configuration file pathname.\n",
		           argv[1]);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __enbox_nonull(2, 3)
int
enbox_parse_cmdln(int                           argc,
                  char * const                  argv[],
                  struct enbox_log * __restrict log)
{
	enbox_assert(argv);
	enbox_assert(log);

	struct enbox_log_parse parse;
	struct enbox_log_conf  conf;
	const char *           tag = ELOG_DFLT_TAG;
	int                    ret = INVALID_CMD;

	enbox_log_init_parse(&parse, &conf);

	while (true) {
		enum {
			LOG_TAG_OPT         = 1U << 0,
			STDLOG_LEVEL_OPT    = 1U << 1,
			SYSLOG_LEVEL_OPT    = 1U << 2,
			SYSLOG_FACILITY_OPT = 1U << 3,
			MQLOG_LEVEL_OPT     = 1U << 4,
			MQLOG_FACILITY_OPT  = 1U << 5,
			MQLOG_NAME_OPT      = 1U << 6,
			HELP_OPT            = 'h',
			MISSING_OPT         = ':',
			UNKNOWN_OPT         = '?'
		};
		static const struct option opts[] = {
			{ "log-tag",         required_argument, NULL, LOG_TAG_OPT },
			{ "stdlog-level",    required_argument, NULL, STDLOG_LEVEL_OPT },
			{ "syslog-level",    required_argument, NULL, SYSLOG_LEVEL_OPT },
			{ "syslog-facility", required_argument, NULL, SYSLOG_FACILITY_OPT },
			{ "mqlog-level",     required_argument, NULL, MQLOG_LEVEL_OPT },
			{ "mqlog-facility",  required_argument, NULL, MQLOG_FACILITY_OPT },
			{ "mqlog-name",      required_argument, NULL, MQLOG_NAME_OPT },
			{ "help",            no_argument,       NULL, HELP_OPT },
			{ NULL,              0,                 NULL, 0 }
		};
		int                        opt;

		opt = getopt_long(argc, argv, "h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case LOG_TAG_OPT:
			if (!elog_is_tag_valid(optarg)) {
				show_error("invalid tag '%s' specified.\n\n",
				           optarg);
				goto fini_parse;
			}
			tag = optarg;
			break;

		case STDLOG_LEVEL_OPT:
			if (enbox_log_parse_level(&parse,
			                          &conf,
			                          ENBOX_STDLOG,
			                          optarg))
				goto fini_parse;
			break;

		case SYSLOG_LEVEL_OPT:
			if (enbox_log_parse_level(&parse,
			                          &conf,
			                          ENBOX_SYSLOG,
			                          optarg))
				goto fini_parse;
			break;

		case SYSLOG_FACILITY_OPT:
			if (elog_parse_syslog_facility(&parse.sys,
			                               &conf.sys,
			                               optarg)) {
				show_error("%s.\n\n", parse.sys.error);
				goto fini_parse;
			}
			conf.subs |= ENBOX_SYSLOG;
			break;

		case MQLOG_LEVEL_OPT:
			if (enbox_log_parse_level(&parse,
			                          &conf,
			                          ENBOX_MQLOG,
			                          optarg))
				goto fini_parse;
			break;

		case MQLOG_FACILITY_OPT:
			if (elog_parse_mqueue_facility(&parse.mq,
			                               &conf.mq,
			                               optarg)) {
				show_error("%s.\n\n", parse.mq.error);
				goto fini_parse;
			}
			conf.subs |= ENBOX_MQLOG;
			break;

		case MQLOG_NAME_OPT:
			if (elog_parse_mqueue_name(&parse.mq,
			                           &conf.mq,
			                           optarg)) {
				show_error("%s.\n\n", parse.mq.error);
				goto fini_parse;
			}
			conf.subs |= ENBOX_MQLOG;
			break;

		case HELP_OPT:
			ret = NONE_CMD;
			goto fini_parse;

		case MISSING_OPT:
			show_error("option '%s' requires an argument.\n\n",
			           argv[optind - 1]);
			goto fini_parse;

		case UNKNOWN_OPT:
			show_error("unrecognized option '%s'.\n\n",
			           argv[optind - 1]);
			goto fini_parse;

		default:
			show_error("unexpected option parsing error.\n\n");
			goto fini_parse;
		}
	}

	ret = enbox_log_realize_parse(&parse, &conf);
	enbox_log_fini_parse(&parse);
	if (ret)
		return INVALID_CMD;

	argc -= optind;
	if (argc < 1) {
		show_error("missing arguments.\n\n");
		goto usage;
	}

	if (!strcmp(argv[optind], "run")) {
		if (enbox_validate_conf_cmd(argc, &argv[optind]))
			goto usage;
		ret = RUN_CMD;
	}
#if defined(CONFIG_ENBOX_SHOW)
	else if (!strcmp(argv[optind], "show")) {
		if (enbox_validate_conf_cmd(argc, &argv[optind]))
			goto usage;
		ret = SHOW_CMD;
	}
	else if (!strcmp(argv[optind], "status")) {
		if (argc != 1) {
			show_error("invalid number of arguments.\n\n");
			goto usage;
		}
		ret = STAT_CMD;
	}
#endif /* defined(CONFIG_ENBOX_SHOW) */
	else {
		show_error("'%s': unknown command.\n", argv[optind]);
		goto usage;
	}

	if (enbox_log_enable(log, tag, &conf))
		return INVALID_CMD;

	return ret;

fini_parse:
	enbox_log_fini_parse(&parse);
usage:
	show_usage();

	return ret;
}

#if defined(CONFIG_ENBOX_DEBUG)

static __enbox_nonull(1)
void
enbox_destroy_file_conf(struct enbox_conf * __restrict conf)
{
	enbox_assert(conf);

	enbox_destroy_conf(conf);
}

#else  /* !defined(CONFIG_ENBOX_DEBUG) */

static __enbox_nonull(1)
void
enbox_destroy_file_conf(struct enbox_conf * __restrict conf __unused)
{
	enbox_assert(conf);
}

#endif /* !defined(CONFIG_ENBOX_DEBUG) */

#if !defined(CONFIG_ENBOX_DEBUG)

static
bool
enbox_isroot(void)
{
	uid_t uid, euid, suid;

	if (getresuid(&uid, &euid, &suid))
		return false;

	if (uid || euid || suid)
		return false;

	return true;
}

#else /* defined(CONFIG_ENBOX_DEBUG) */

static
bool
enbox_isroot(void)
{
	/*
	 * Allows to test that no particular problems may happens when running
	 * as an unprivileged user.
	 */
	return true;
}

#endif /* !defined(CONFIG_ENBOX_DEBUG) */

int
main(int argc, char * const argv[])
{
	struct enbox_log    log;
	int                 cmd;
	struct enbox_conf * conf;
	int                 ret = EXIT_FAILURE;

	cmd = enbox_parse_cmdln(argc, argv, &log);
	if (cmd == NONE_CMD)
		return EXIT_SUCCESS;
	else if (cmd == INVALID_CMD)
		return EXIT_FAILURE;

	if (!enbox_isroot()) {
		show_error("must be run as root.\n");
		return EXIT_FAILURE;
	}

	enbox_setup(log.top);

	switch (cmd) {
	case RUN_CMD:
		conf = enbox_create_conf_from_file(argv[optind + 1]);
		if (!conf)
			break;
		if (!enbox_run_conf(conf))
			ret = EXIT_SUCCESS;
		enbox_destroy_file_conf(conf);
		break;

#if defined(CONFIG_ENBOX_SHOW)
	case SHOW_CMD:
		conf = enbox_create_conf_from_file(argv[optind + 1]);
		if (!conf)
			break;
		enbox_show_conf(conf);
		enbox_destroy_file_conf(conf);
		ret = EXIT_SUCCESS;
		break;

	case STAT_CMD:
		enbox_show_status(stdout, 1, argc, (const char * const *)argv);
		ret = EXIT_SUCCESS;
		break;
#endif /* defined(CONFIG_ENBOX_SHOW) */

	default:
		enbox_assert(0);
	}

	enbox_log_fini(&log);

	return ret;
}
