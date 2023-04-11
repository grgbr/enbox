#include "common.h"
#include <utils/path.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

/******************************************************************************
 * Display logic
 ******************************************************************************/

#if defined(CONFIG_ENBOX_TOOL_SHOW)

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

static size_t __enbox_nonull(2, 4) __nothrow
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
	enbox_assert(!(type & ~S_IFMT));

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

	len = enbox_fill_flag_descs_string(jail->namespaces,
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

static ssize_t __enbox_nonull(2) __nothrow
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

	len = snprintf(string, size, "%hu(%s)", gid, grp->gr_name);
	if (len >= size)
		return -EMSGSIZE;

	return len;
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

static int __enbox_nonull(1, 2) __nothrow
enbox_fill_user_groups(char                             string[__restrict_arr],
                       const struct passwd * __restrict pwd,
                       bool                             drop_supp)
{
	enbox_assert(string);
	enbox_assert(pwd);

	size_t  left = ENBOX_GROUP_LIST_SIZE;
	int     ret;

	/* Fill in primary group first. */
	ret = enbox_fill_group_name(pwd->pw_gid, string, left);
	enbox_assert(ret);
	if (ret < 0)
		return ret;

	enbox_assert((size_t)ret < left);

	if (!drop_supp) {
		gid_t * gids;
		int     nr = NGROUPS_MAX + 1;
		int     g;

		gids = xalloc(nr * sizeof(*gids));

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

	return ret;
}

static void __enbox_nonull(1)
enbox_show_ids_conf(const struct enbox_ids * __restrict ids)
{
	enbox_assert(ids);
	enbox_assert(!enbox_validate_pwd(ids->pwd, false));

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

static void __enbox_nonull(1)
enbox_show_cmd_conf(const struct enbox_cmd * __restrict cmd)
{
	enbox_assert(cmd);
	enbox_assert(!(cmd->umask & ~ACCESSPERMS));
	enbox_assert(!cmd->cwd || (upath_validate_path_name(cmd->cwd) > 0));
	enbox_assert(!enbox_validate_exec(cmd->exec));

	unsigned int a = 0;

	puts("\n### Command ###\n");

	printf("Umask            : %04o\n", cmd->umask);
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

#define USAGE \
"Usage: %1$s [OPTIONS] <CONFIG> <CMD>\n" \
"Run a program invocation with an Enbox sandbox.\n"

static void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

static struct elog_stdio      stdlog;
static struct elog_stdio_conf stdlog_conf = {
	.super.severity = CONFIG_ENBOX_TOOL_STDLOG_SEVERITY,
	.format         = CONFIG_ENBOX_TOOL_STDLOG_FORMAT
};

int
main(int argc, char * const argv[])
{
	int                 ret = EXIT_FAILURE;
	struct enbox_conf * conf;
	enum {
		INVALID,
		RUN,
#if defined(CONFIG_ENBOX_TOOL_SHOW)
		SHOW
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */
	}                   cmd = INVALID;

	while (true) {
		int                        opt;
		static const struct option opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ NULL,   0,           NULL,  0 }
		};

		opt = getopt_long(argc, argv, "h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'h':
			ret = EXIT_SUCCESS;
			goto usage;

		case ':':
			show_error("option '%s' requires an argument.\n\n",
			           argv[optind - 1]);
			goto usage;

		case '?':
			show_error("unrecognized option '%s'.\n\n",
			           argv[optind - 1]);
			goto usage;

		default:
			show_error("unexpected option parsing error.\n\n");
			goto usage;
		}
	}

	if ((argc - optind) < 2) {
		show_error("missing arguments.\n\n");
		goto usage;
	}

	if (!upath_validate_path_name(argv[optind])) {
		show_error("'%s': invalid configuration file pathname.\n",
		           argv[optind]);
		return EXIT_FAILURE;
	}

	if ((argc - optind) != 2) {
		show_error("invalid number of arguments.\n\n");
		goto usage;
	}

	if (!strcmp(argv[optind + 1], "run"))
		cmd = RUN;
#if defined(CONFIG_ENBOX_TOOL_SHOW)
	else if (!strcmp(argv[optind + 1], "show"))
		cmd = SHOW;
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */
	else {
		show_error("'%s': unknown command.\n", argv[optind + 1]);
		goto usage;
	}

	elog_init_stdio(&stdlog, &stdlog_conf);
	if (enbox_setup((struct elog *)&stdlog))
		goto out;

	conf = enbox_create_conf_from_file(argv[optind]);
	if (!conf)
		goto out;

	switch (cmd) {
	case RUN:
		ret = !enbox_run_conf(conf) ? EXIT_SUCCESS : EXIT_FAILURE;
		break;

#if defined(CONFIG_ENBOX_TOOL_SHOW)
	case SHOW:
		enbox_show_conf(conf);
		ret = EXIT_SUCCESS;
		break;
#endif /* defined(CONFIG_ENBOX_TOOL_SHOW) */

	default:
		enbox_assert(0);
	}

#if defined(CONFIG_ENBOX_DEBUG)
	enbox_destroy_conf(conf);

out:
	elog_fini_stdio(&stdlog);
#else  /* !defined(CONFIG_ENBOX_DEBUG) */
out:
	fflush(NULL);
#endif /* defined(CONFIG_ENBOX_DEBUG) */
	return ret;

usage:
	show_usage();
	return ret;
}
