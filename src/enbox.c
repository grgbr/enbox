#include "common.h"
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

#if defined(CONFIG_ENBOX_TOOL_SHOW)

#include "namespaces.h"
#include "mount_flags.h"
#include "capabilities.h"
#include <stroll/bmap.h>

#define ENBOX_MODE_STRING_SZ (10U)

static const char * __returns_nonull __nothrow
enbox_build_mode_string(char str[ENBOX_MODE_STRING_SZ], mode_t mode)
{
	str[0] = (mode & S_IRUSR) ? 'r' : '-';
	str[1] = (mode & S_IWUSR) ? 'w' : '-';
	switch (mode & (S_IXUSR | S_ISUID)) {
	case S_IXUSR:
		str[2] = 'x';
		break;
	case S_ISUID:
		str[2] = 'S';
		break;
	case S_IXUSR | S_ISUID:
		str[2] = 's';
		break;
	default:
		str[2] = '-';
	}

	str[3] = (mode & S_IRGRP) ? 'r' : '-';
	str[4] = (mode & S_IWGRP) ? 'w' : '-';
	switch (mode & (S_IXGRP | S_ISGID)) {
	case S_IXGRP:
		str[5] = 'x';
		break;
	case S_ISGID:
		str[5] = 'S';
		break;
	case S_IXGRP | S_ISGID:
		str[5] = 's';
		break;
	default:
		str[5] = '-';
	}

	str[6] = (mode & S_IROTH) ? 'r' : '-';
	str[7] = (mode & S_IWOTH) ? 'w' : '-';
	switch (mode & (S_IXOTH | S_ISVTX)) {
	case S_IXOTH:
		str[8] = 'x';
		break;
	case S_ISVTX:
		str[8] = 'T';
		break;
	case S_IXOTH | S_ISVTX:
		str[8] = 't';
		break;
	default:
		str[8] = '-';
	}

	str[9] = '\0';

	return str;
}

static void __enbox_nonull(1)
enbox_show_dir_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SZ];

	printf("d%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dir.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static void __enbox_nonull(1)
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

static void __enbox_nonull(1)
enbox_show_chrdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SZ];

	printf("c%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dev.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static void __enbox_nonull(1)
enbox_show_blkdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SZ];

	printf("b%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->dev.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static void __enbox_nonull(1)
enbox_show_fifo_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	char mode[ENBOX_MODE_STRING_SZ];

	printf("p%s %u(%s) %u(%s) %s\n",
	       enbox_build_mode_string(mode, ent->fifo.mode),
	       ent->uid,
	       enbox_get_user_name(ent->uid),
	       ent->gid,
	       enbox_get_group_name(ent->gid),
	       ent->path);
}

static size_t __enbox_nonull(2, 4) __enbox_nothrow
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

static void * __nothrow __warn_result
xalloc(size_t size)
{
	void * ptr;

	ptr = malloc(size);
	if (!ptr)
		exit(EXIT_FAILURE);

	return ptr;
}

static char * __nothrow
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

static void __enbox_nonull(1)
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

static void __enbox_nonull(1)
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
		char mode[ENBOX_MODE_STRING_SZ];

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

static void __enbox_nonull(1)
enbox_show_tree_entry(const struct enbox_entry * __restrict ent)
{
	enbox_show_bind_entry(ent, S_IFDIR);
}

static void __enbox_nonull(1)
enbox_show_file_entry(const struct enbox_entry * __restrict ent)
{
	enbox_show_bind_entry(ent, S_IFREG | S_IFIFO);
}

typedef void (enbox_show_entry_fn)(const struct enbox_entry * __restrict entry)
	__enbox_nonull(1);

static void __enbox_nonull(1)
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

static void __enbox_nonull(1)
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

static void __enbox_nonull(1)
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

static ssize_t __enbox_nonull(2) __enbox_nothrow
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

static int __enbox_nonull(1, 2) __enbox_nothrow
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

static void __enbox_nonull(1)
enbox_show_ids_conf(const struct enbox_ids * __restrict ids)
{
	enbox_assert(ids);
	enbox_assert(!enbox_validate_pwd(ids->pwd, true));

	const struct passwd * pwd = ids->pwd;
	char *                grps = NULL;

	puts("\n### User / group IDs ###\n");

	/*
	 * Allocate a string large enough to hold a comma separated list
	 * of supplementary groups (including primary group).
	 */
	grps = xalloc(ENBOX_GROUP_LIST_SIZE);

	if (!enbox_fill_user_groups(grps, pwd, ids->drop_supp)) {
		printf("User  : %u(%s)\n", pwd->pw_uid, pwd->pw_name);
		printf("Groups: %s\n", grps);

		goto free;
	}

	puts("User  : ?(?\?)");
	puts("Groups: ?");

free:
	free(grps);
}

static char * __enbox_nothrow
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

static void __enbox_nonull(1)
enbox_show_cmd_conf(const struct enbox_cmd * __restrict cmd)
{
	enbox_assert(cmd);
	enbox_assert(!(cmd->umask & ~((mode_t)ACCESSPERMS)));
	enbox_assert(!(cmd->caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!cmd->cwd || (upath_validate_path_name(cmd->cwd) > 0));
	enbox_assert(!enbox_validate_exec(cmd->exec));

	unsigned int a = 0;

	puts("\n### Command ###\n");

	printf("Umask            : %04o\n", cmd->umask);

	if (cmd->caps) {
		char * str;

		str = enbox_build_caps_string(cmd->caps);
		printf("Capabilities     : %s\n", str);
		free(str);
	}
	else
		fputs("Capabilities     : none\n", stdout);

	printf("Working directory: %s\n", cmd->cwd ? cmd->cwd : "/");

	fputs("Exec arguments   :", stdout);
	do {
		printf(" %s", cmd->exec[a]);
	} while (cmd->exec[++a]);
	putchar('\n');
}

static void __enbox_nonull(1)
enbox_show_conf(const struct enbox_conf * conf)
{
	enbox_assert(conf);

	if (conf->host)
		enbox_show_host_conf(conf->host);
	if (conf->ids)
		enbox_show_ids_conf(conf->ids);
	if (conf->jail)
		enbox_show_jail_conf(conf->jail);
	if (conf->cmd)
		enbox_show_cmd_conf(conf->cmd);
}

#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */

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

#if defined(CONFIG_ENBOX_TOOL_SHOW)
#define SHOW_USAGE \
"    show        -- show configuration settings loaded from CONFIG\n"
#else  /* defined(CONFIG_ENBOX_TOOL_SHOW) */
#define SHOW_USAGE
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */

#define USAGE \
"Usage: %1$s [OPTIONS] <CONFIG> <CMD>\n" \
"Enbox sandboxing tool.\n" \
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
"With CMD:\n" \
SHOW_USAGE \
"    run         -- run / execute configuration loaded from CONFIG\n" \
"\n" \
"Where:\n" \
"    CONFIG   -- pathname to an Enbox configuration file\n" \
"    TAG      -- logging message tag\n" \
"    NAME     -- POSIX message queue name, including the leading `/'\n" \
"    SEVERITY := none|dflt|emerg|alert|crit|err|warn|notice|info\n" \
"    FACILITY := dflt|auth|authpriv|cron|daemon|ftp|lpr|mail|news|syslog|user\n" \
"                |local0|local1|local2|local3|local4|local5|local6|local7\n" \

static void
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

static int __enbox_nonull(1, 2, 4) __enbox_nothrow
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

static int __enbox_nonull(1, 2)
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

static void __enbox_nonull(1, 2) __enbox_nothrow
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

static void __enbox_nonull(1) __enbox_nothrow
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

static int __enbox_nonull(1, 3)
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

static void __enbox_nonull(1)
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
#if defined(CONFIG_ENBOX_TOOL_SHOW)
	SHOW_CMD
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */
};

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

	if ((argc - optind) != 2) {
		show_error("invalid number of arguments.\n\n");
		goto usage;
	}

	if (!upath_validate_path_name(argv[optind])) {
		show_error("'%s': invalid configuration file pathname.\n",
		           argv[optind]);
		return INVALID_CMD;
	}

	if (!strcmp(argv[optind + 1], "run"))
		ret = RUN_CMD;
#if defined(CONFIG_ENBOX_TOOL_SHOW)
	else if (!strcmp(argv[optind + 1], "show"))
		ret = SHOW_CMD;
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */
	else {
		show_error("'%s': unknown command.\n", argv[optind + 1]);
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

	enbox_setup(log.top);

	conf = enbox_create_conf_from_file(argv[optind]);
	if (!conf)
		goto out;

	switch (cmd) {
	case RUN_CMD:
		if (!enbox_run_conf(conf))
			ret = EXIT_SUCCESS;
		break;

#if defined(CONFIG_ENBOX_TOOL_SHOW)
	case SHOW_CMD:
		enbox_show_conf(conf);
		ret = EXIT_SUCCESS;
		break;
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */

	default:
		enbox_assert(0);
	}

#if defined(CONFIG_ENBOX_DEBUG)
	enbox_destroy_conf(conf);
#endif /* defined(CONFIG_ENBOX_DEBUG) */

out:
	enbox_log_fini(&log);

	return ret;
}
