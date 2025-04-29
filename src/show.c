#include "show.h"
#include "lib.h"
#include <utils/file.h>
#include <utils/fstree.h>
#include <utils/time.h>
#include <stdio.h>

static __enbox_nonull(1)
void
enbox_show_secbits(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	int bits;

	bits = enbox_load_secbits();

	fputs(  "SECUREBITS          STATE  LOCK\n", stdio);
	fprintf(stdio,
	        "noroot                 %s    %s\n",
	        (bits & SECBIT_NOROOT) ? "on" : " .",
	        (bits & SECBIT_NOROOT_LOCKED) ? "on" : " .");
	fprintf(stdio,
	        "no_setuid_fixup        %s    %s\n",
	        (bits & SECBIT_NO_SETUID_FIXUP) ? "on" : " .",
	        (bits & SECBIT_NO_SETUID_FIXUP_LOCKED) ? "on" : " .");
	fprintf(stdio,
	        "keep_caps              %s    %s\n",
	        (bits & SECBIT_KEEP_CAPS) ? "on" : " .",
	        (bits & SECBIT_KEEP_CAPS_LOCKED) ? "on" : " .");
	fprintf(stdio,
	        "no_cap_ambient_raise   %s    %s\n",
	        (bits & SECBIT_NO_CAP_AMBIENT_RAISE) ? "on" : " .",
	        (bits & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED) ? "on" : " .");
	fprintf(stdio,
	        "no_new_privs           %s    %s\n",
	        enbox_load_nonewprivs() ? "on" : " .",
	        "NA");
	fprintf(stdio,
	        "dumpable               %s    %s\n",
	        enbox_load_dump() ? "on" : " .",
	        "NA");
}

static __enbox_nonull(1)
void
enbox_show_caps(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	struct enbox_caps caps;
	uint64_t          eff;
	uint64_t          perm;
	uint64_t          inh;
	uint64_t          amb;
	uint64_t          bound;
	int               c;

	enbox_load_epi_caps(&caps);
	eff = enbox_get_eff_caps(&caps);
	perm = enbox_get_perm_caps(&caps);
	inh = enbox_get_inh_caps(&caps);
	amb = enbox_load_amb_caps();
	bound = enbox_load_bound_caps();

	fprintf(stdio,
	        "CAPABILITY         PERM.  EFF.  INH.  AMB.  BOUND.\n");

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		fprintf(stdio,
		        "%-18.18s   %s    %s    %s    %s      %s\n",
		        enbox_caps_descs[c].kword,
		        (perm & enbox_cap(c)) ? "on" : " .",
		        (eff & enbox_cap(c)) ? "on" : " .",
		        (inh & enbox_cap(c)) ? "on" : " .",
		        (amb & enbox_cap(c)) ? "on" : " .",
		        (bound & enbox_cap(c)) ? "on" : " .");
	}
}

static __enbox_nonull(1)
void
enbox_show_creds(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	uid_t   ruid;
	uid_t   euid;
	uid_t   suid;
	gid_t   rgid;
	gid_t   egid;
	gid_t   sgid;
	gid_t * supp;
	int     g;
	int     ret;

	ret = getresuid(&ruid, &euid, &suid);
	enbox_assert(!ret);
	ret = getresgid(&rgid, &egid, &sgid);
	enbox_assert(!ret);

	fputs(  "CREDENTIALS         UID         GID\n", stdio);
	fprintf(stdio,
	        "real         %10d  %10d\n",
	        ruid,
	        rgid);
	fprintf(stdio,
	        "effective    %10d  %10d\n",
	        euid,
	        egid);
	fprintf(stdio,
	        "saved        %10d  %10d\n",
	        suid,
	        sgid);

	supp = malloc(NGROUPS_MAX * sizeof(supp[0]));
	if (!supp)
		return;

	ret = getgroups(NGROUPS_MAX, supp);
	enbox_assert(ret >= 0);

	if (ret) {
		const struct group * grp;

		grp = upwd_get_group_byid(supp[0]);

		fputs(         "Supp. groups  ", stdio);
		fprintf(stdio, "%d(%s)", supp[0], grp ? grp->gr_name : "??");
		for (g = 1; g < ret; g++) {
			grp = upwd_get_group_byid(supp[g]);

			fprintf(stdio,
			        ", %d(%s)",
			        supp[g],
			        grp ? grp->gr_name : "??");
		}
		putc('\n', stdio);
	}
	else
		fputs(         "Supp. groups  none\n", stdio);

	free(supp);
}

#define ENBOX_SHOW_BUFF_SZ \
	STROLL_CONST_MAX(ENBOX_ARGS_MAX * ENBOX_ARG_SIZE, PATH_MAX)

struct enbox_show {
	int    depth;
	FILE * stdio;
	char   buff[ENBOX_SHOW_BUFF_SZ];
};

#define enbox_assert_show(_show) \
	enbox_assert(_show); \
	enbox_assert((_show)->stdio)

static  __enbox_nonull(1) __enbox_nothrow
struct enbox_show *
enbox_create_show(FILE * stdio, int depth)
{
	enbox_assert(stdio);

	struct enbox_show * show;

	show = malloc(sizeof(*show));
	if (!show)
		return NULL;

	show->depth = depth;
	show->stdio = stdio;

	return show;
}

static  __enbox_nonull(1) __enbox_nothrow
void
enbox_destroy_show(struct enbox_show * __restrict show)
{
	enbox_assert(show);

	free(show);
}

static  __enbox_nonull(1, 3)
void
enbox_show_next_err(const struct etux_fstree_iter * __restrict iter,
                    int                                        status,
                    const struct enbox_show * __restrict       show)
{
	enbox_assert(iter);
	enbox_assert(status < 0);
	enbox_assert(status != -ENOMEM);
	enbox_assert_show(show);

	fprintf(show->stdio,
	        "'%s': cannot iterate over entries: %s (%d).\n",
	        etux_fstree_iter_path(iter),
	        strerror(-status),
	        -status);
}

static  __enbox_nonull(2, 5) __warn_result
int
enbox_show_fsent_err(struct etux_fstree_entry * __restrict      entry,
                     const struct etux_fstree_iter * __restrict iter,
                     enum etux_fstree_event                     event,
                     int                                        status,
                     const struct enbox_show * __restrict       show)
{
	enbox_assert(iter);
	enbox_assert(status < 0);
	enbox_assert(status != -ENOMEM);
	enbox_assert_show(show);

	if (event == ETUX_FSTREE_LOAD_ERR_EVT) {
		const char * path;

		if ((status != -ENODATA) && (status != -ENAMETOOLONG))
			path = etux_fstree_entry_name(entry, iter);
		else
			path = "??";

		fprintf(show->stdio,
		        "'%s': cannot load entry: %s (%d).\n",
		        path,
		        strerror(-status),
		        -status);

		return ETUX_FSTREE_CONT_CMD;
	}
	else if (event == ETUX_FSTREE_NEXT_ERR_EVT) {
		/* Abort iteration process. */
		enbox_show_next_err(iter, status, show);
		return status;
	}
	else
		enbox_assert(0);

	unreachable();
}

static  __enbox_nonull(2, 5) __warn_result
int
enbox_show_proc_ns(struct etux_fstree_entry * __restrict      entry,
                   const struct etux_fstree_iter * __restrict iter,
                   enum etux_fstree_event                     event,
                   int                                        status,
                   void * __restrict                          data)
{
	enbox_assert(iter);
	enbox_assert(status != -ENOMEM);
	enbox_assert(data);

	struct enbox_show * show = (struct enbox_show *)data;

	enbox_assert_show(show);

	if (event == ETUX_FSTREE_ENT_EVT) {
		const char * name;

		if (etux_fstree_entry_isdot(entry, iter))
		    return ETUX_FSTREE_CONT_CMD;

		name = etux_fstree_entry_name(entry, iter);
		enbox_assert(name);

		if (etux_fstree_entry_type(entry, iter) == DT_LNK) {
			ssize_t      len;
			const char * ns;

#define ENBOX_PROC_NSLEN_MAX (32U)
#if ENBOX_PROC_NSLEN_MAX >= ENBOX_SHOW_BUFF_SZ
#error Invalid ENBOX_PROC_NSLEN_MAX !
#endif
			len = etux_fstree_entry_sized_slink(
				entry,
				iter,
				show->buff,
				ENBOX_PROC_NSLEN_MAX);
			if ((len < 5) || ((size_t)len > ENBOX_PROC_NSLEN_MAX))
				goto invalid;

			ns = strchr(show->buff, ':');
			if (!ns ||
			    (((size_t)len - (size_t)(ns - show->buff)) < 3U) ||
			    (ns[1] != '['))
				goto invalid;
			if (show->buff[--len] != ']')
				goto invalid;
			show->buff[len] = '\0';

			fprintf(show->stdio, "%s  %s\n", ns + 2, name);

			return ETUX_FSTREE_CONT_CMD;
		}

invalid:
		fprintf(show->stdio,
		        "??????????  %s  #unexpected format#\n",
		        name);

		return ETUX_FSTREE_CONT_CMD;
	}

	return enbox_show_fsent_err(entry, iter, event, status, show);
}

static  __enbox_nonull(2, 5) __warn_result
int
enbox_show_proc_fd(struct etux_fstree_entry * __restrict      entry,
                   const struct etux_fstree_iter * __restrict iter,
                   enum etux_fstree_event                     event,
                   int                                        status,
                   void * __restrict                          data)
{
	enbox_assert(iter);
	enbox_assert(status != -ENOMEM);
	enbox_assert(data);

	struct enbox_show * show = (struct enbox_show *)data;

	enbox_assert_show(show);

	if (event == ETUX_FSTREE_ENT_EVT) {
		const char * name;

		if (etux_fstree_entry_isdot(entry, iter))
		    return ETUX_FSTREE_CONT_CMD;

		name = etux_fstree_entry_name(entry, iter);
		enbox_assert(name);

		if (etux_fstree_entry_type(entry, iter) == DT_LNK) {
			char *        err;
			unsigned long fd;
			ssize_t       len;

			fd = strtoul(name, &err, 10);
			if (*err || (fd > INT_MAX))
				goto invalid;

			if ((int)fd == etux_fstree_iter_dirfd(iter))
				return ETUX_FSTREE_CONT_CMD;

			len = etux_fstree_entry_sized_slink(
				entry,
				iter,
				show->buff,
				PATH_MAX);
			enbox_assert(len <= PATH_MAX);
			if ((len < 1) || (len == PATH_MAX))
				goto invalid;

			fprintf(show->stdio, "%10lu  %s\n", fd, show->buff);

			return ETUX_FSTREE_CONT_CMD;
		}

invalid:
		fprintf(show->stdio,
		        "%10.10s  ??  #unexpected format#\n",
		        name);

		return ETUX_FSTREE_CONT_CMD;
	}

	return enbox_show_fsent_err(entry, iter, event, status, show);
}

static __enbox_nonull(1) __warn_result
ssize_t
enbox_load_cmdln(char * __restrict buffer, size_t size)
{
	enbox_assert(buffer);
	enbox_assert(size);

	int     fd;
	ssize_t ret;

	fd = ufile_nointr_open("/proc/self/cmdline",
	                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (ssize_t)fd;

	ret = ufile_nointr_read(fd, buffer, size);
	if (ret > 0) {
		char * curr = buffer;
		size_t left = (size_t)(--ret);

		if (curr[left] != '\0') {
			ret = -ENOMSG;
			goto close;
		}

		while (true) {
			size_t len;

			len = strnlen(curr, left);
			enbox_assert(len <= left);
			if (len == left)
				break;

			curr[len++] = ' ';

			curr += len;
			left -= len;
		}
	}
	else if (!ret)
		ret = -ENODATA;

close:
	ufile_close(fd);

	return ret;
}

static __enbox_nonull(1, 3, 4)
void
enbox_show_proc(FILE * __restrict  stdio,
                int                argc,
                const char * const argv[__restrict_arr],
                char * __restrict  buffer,
                size_t             size)
{
	enbox_assert(stdio);
	enbox_assert(argc);
	enbox_assert(argv);
	enbox_assert(buffer);
	enbox_assert(size >= PATH_MAX);

	ssize_t              sz;
	int                  a;
	const char * const * env = (const char * const *)environ;

	fprintf(stdio, "pid                %d\n", getpid());
	fprintf(stdio, "pgid               %d\n", getpgrp());
	fprintf(stdio, "ppid               %d\n", getppid());
	fprintf(stdio, "sid                %d\n", getsid(0));
	fprintf(stdio, "umask              %04o\n", enbox_get_umask());

	if (!getcwd(buffer, PATH_MAX)) {
		enbox_assert(errno != EFAULT);
		enbox_assert(errno != EINVAL);
		enbox_assert(errno != ERANGE);
		fprintf(stdio,
		        "working directory  ??  #%s (%d)#\n",
		        strerror(errno),
		        errno);
	}
	else
		fprintf(stdio, "working directory  %s\n", buffer);

	sz = enbox_load_cmdln(buffer, size);
	if (sz < 0)
		fprintf(stdio,
		        "command line       ??  #%s (%d)#\n",
		        strerror(-(int)sz),
		        -(int)sz);
	else
		fprintf(stdio, "command line       %s\n", buffer);

	fprintf(stdio, "exec line          %s", argv[0]);
	for (a = 1; a < argc; a++)
		fprintf(stdio, " %s", argv[a]);
	putc('\n', stdio);

	fputs("\nENVIRONMENT\n", stdio);
	if (env && *env) {
		do {
			fprintf(stdio, "%s\n", *env++);
		} while (*env);
	}
	else
		fputs("none\n", stdio);
}

const char *
enbox_build_mode_string(char str[ENBOX_MODE_STRING_SIZE], mode_t mode)
{
	enbox_assert(str);

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

static __enbox_nonull(1, 2, 3) __warn_result
int
enbox_show_path(struct etux_fstree_entry * __restrict      entry,
                const struct etux_fstree_iter * __restrict iter,
                struct enbox_show * __restrict             show)
{
	enbox_assert(entry);
	enbox_assert(iter);
	enbox_assert_show(show);

	if (!etux_fstree_entry_isdot(entry, iter)) {
		int                 ret;
		const char *        path;
		int                 type = '?';
		const struct stat * st;
		char                mod[ENBOX_MODE_STRING_SIZE];
		struct tm           tim;
		char                str[20];

		ret = (int)etux_fstree_entry_sized_path(entry,
		                                        iter,
		                                        show->buff,
		                                        sizeof(show->buff));
		if (ret < 0) {
			path = "??";
			goto invalid;
		}

		path = show->buff;

		ret = etux_fstree_entry_type(entry, iter);
		if (ret < 0)
			goto invalid;

		switch (ret) {
		case DT_REG:
			type = '-';
			break;
		case DT_DIR:
			type = 'd';
			break;
		case DT_LNK:
			type = 'l';
			break;
		case DT_FIFO:
			type = 'p';
			break;
		case DT_SOCK:
			type = 's';
			break;
		case DT_CHR:
			type = 'c';
			break;
		case DT_BLK:
			type = 'b';
			break;
		case DT_WHT:
			break;
		default:
			assert(0);
		}

		st = etux_fstree_entry_stat(entry, iter);
		if (!st) {
			ret = -errno;
			goto invalid;
		}

		enbox_build_mode_string(mod, st->st_mode);

		utime_gmtime_from_tspec(&tim, &st->st_ctim);
		strftime(str, sizeof(str), "%F %T", &tim);

		if (type == 'l') {
			const char * trgt;

			trgt = etux_fstree_entry_slink(entry, iter);
			if (trgt)
				fprintf(show->stdio,
				        "%c%s  %10lu  %10u  %10u  %4u  %7u"
				        "  %19lu  %19.19sZ  %s -> %s\n",
				        type,
				        mod,
				        (unsigned long)st->st_nlink,
				        (unsigned int)st->st_uid,
				        (unsigned int)st->st_gid,
				        major(st->st_dev),
				        minor(st->st_dev),
				        st->st_size,
				        str,
				        path,
				        trgt);
			else
				fprintf(show->stdio,
				        "%c%s  %10lu  %10u  %10u  %4u  %7u"
				        "  %19lu  %19.19sZ"
				        "  %s -> ??  #%s (%d)#\n",
				        type,
				        mod,
				        (unsigned long)st->st_nlink,
				        (unsigned int)st->st_uid,
				        (unsigned int)st->st_gid,
				        major(st->st_dev),
				        minor(st->st_dev),
				        st->st_size,
				        str,
				        path,
				        strerror(errno),
				        errno);
		}
		else
			fprintf(show->stdio,
			        "%c%s  %10lu  %10u  %10u  %4u  %7u  %19lu"
			        "  %19.19sZ  %s\n",
			        type,
			        mod,
			        (unsigned long)st->st_nlink,
			        (unsigned int)st->st_uid,
			        (unsigned int)st->st_gid,
			        major(st->st_dev),
			        minor(st->st_dev),
			        st->st_size,
			        str,
			        path);

		return ETUX_FSTREE_CONT_CMD;

invalid:
		if (ret == -ENOMEM)
			return -ENOMEM;

		fprintf(show->stdio,
		        "%c%s  %10.10s  %10.10s  %10.10s  %4.4s  %7.7s  %19.19s"
		        "  %19.19sZ  %s  #%s (%d)#\n",
		        type,
		        "?????????",
		        "??",
		        "??",
		        "??",
		        "??",
		        "??",
		        "??",
		        "???\?-?\?-?? ??:??:??",
		        path,
		        strerror(-ret),
		        -ret);
	}

	return ETUX_FSTREE_CONT_CMD;
}

static __enbox_nonull(2, 4) __warn_result
int
enbox_show_path_err(struct etux_fstree_entry * __restrict      entry,
                    const struct etux_fstree_iter * __restrict iter,
                    int                                        status,
                    struct enbox_show * __restrict             show)
{
	enbox_assert(iter);
	enbox_assert(status < 0);
	enbox_assert(status != -ENOMEM);
	enbox_assert_show(show);

	const char * path = "??";

	if ((status != -ENODATA) && (status != -ENAMETOOLONG)) {
		if (etux_fstree_entry_sized_path(entry,
		                                 iter,
		                                 show->buff,
		                                 sizeof(show->buff)) > 0)
			path = show->buff;
	}

	fprintf(show->stdio,
	        "'%s': cannot load entry: %s (%d).\n",
	        path,
	        strerror(-status),
	        -status);

	return ETUX_FSTREE_CONT_CMD;
}

static __enbox_nonull(1, 2, 4) __warn_result
int
enbox_show_dir_err(struct etux_fstree_entry * __restrict      entry,
                   const struct etux_fstree_iter * __restrict iter,
                   int                                        status,
                   struct enbox_show * __restrict             show)
{
	enbox_assert(entry);
	enbox_assert(iter);
	enbox_assert(!etux_fstree_entry_isdot(entry, iter));
	enbox_assert(etux_fstree_entry_type(entry, iter) == DT_DIR);
	enbox_assert(status < 0);
	enbox_assert(status != -ENOMEM);
	enbox_assert_show(show);

	const char * path = "??";

	if (etux_fstree_entry_sized_path(entry,
	                                 iter,
	                                 show->buff,
	                                 sizeof(show->buff)) > 0)
		path = show->buff;

	fprintf(show->stdio,
	        "'%s': cannot change to directory: %s (%d).\n",
	        path,
	        strerror(-status),
	        -status);

	return ETUX_FSTREE_CONT_CMD;
}

static __enbox_nonull(1, 2, 3) __warn_result
int
enbox_show_pre_dir(struct etux_fstree_entry * __restrict      entry,
                   const struct etux_fstree_iter * __restrict iter,
                   struct enbox_show * __restrict             show)
{
	enbox_assert(entry);
	enbox_assert(iter);
	enbox_assert(etux_fstree_entry_type(entry, iter) == DT_DIR);
	enbox_assert_show(show);

	int err;

	err = enbox_show_path(entry, iter, show);
	if (err)
		return err;

	if ((show->depth < 0) ||
	    (etux_fstree_iter_depth(iter) < (unsigned int)show->depth))
		return  ETUX_FSTREE_CONT_CMD;

	return ETUX_FSTREE_SKIP_CMD;
}

static __enbox_nonull(2, 5) __warn_result
int
enbox_show_root_fs(struct etux_fstree_entry *      entry,
                   const struct etux_fstree_iter * iter,
                   enum etux_fstree_event          event,
                   int                             status,
                   void *                          data)
{
	enbox_assert(iter);
	enbox_assert(status != -ENOMEM);
	enbox_assert(data);

	struct enbox_show * show = (struct enbox_show *)data;

	switch (event) {
	case ETUX_FSTREE_ENT_EVT:
		return enbox_show_path(entry, iter, show);

	case ETUX_FSTREE_PRE_EVT:
		return enbox_show_pre_dir(entry, iter, show);

	case ETUX_FSTREE_LOAD_ERR_EVT:
		return enbox_show_path_err(entry, iter, status, show);

	case ETUX_FSTREE_DIR_ERR_EVT:
		return enbox_show_dir_err(entry, iter, status, show);

	case ETUX_FSTREE_NEXT_ERR_EVT:
		enbox_show_next_err(iter, status, show);
		return ETUX_FSTREE_STOP_CMD;

	case ETUX_FSTREE_LOOP_EVT: /*
	                            * Should never happen since
	                            * ETUX_FSTREE_FOLLOW_OPT option is disabled.
	                            */
	case ETUX_FSTREE_POST_EVT: /*
                                    * Should never happen since
                                    * ETUX_FSTREE_POST_OPT option is disabled.
                                    */
	default:
		enbox_assert(0);
	}

	unreachable();
}

void
enbox_show_status(FILE * __restrict  stdio,
                  int                depth,
                  int                argc,
                  const char * const argv[__restrict_arr])
{
	enbox_assert_setup();
	enbox_assert(stdio);
	enbox_assert(argc);
	enbox_assert(argv);

	struct enbox_show * show;
	int                 ret;

	show = enbox_create_show(stdio, depth);
	if (!show)
		return;

	fputs("NAMESPACES  TYPE\n", stdio);
	ret = etux_fstree_walk("/proc/self/ns", 0, enbox_show_proc_ns, show);
	if (ret)
		fprintf(stdio,
		        "cannot retrieve namespaces: %s (%d).\n",
		        strerror(-ret),
		        -ret);

	putc('\n', stdio);
	enbox_show_caps(stdio);

	putc('\n', stdio);
	enbox_show_secbits(stdio);

	putc('\n', stdio);
	enbox_show_creds(stdio);

	fputs("\nPROCESS\n", stdio);
	enbox_show_proc(stdio, argc, argv, show->buff, sizeof(show->buff));

	fputs("\nFILE DESC.  PATHNAME\n", stdio);
	ret = etux_fstree_walk("/proc/self/fd", 0, enbox_show_proc_fd, show);
	if (ret)
		fprintf(stdio,
		        "cannot retrieve opened file descriptors: %s (%d).\n",
		        strerror(-ret),
		        -ret);

	/* TODO: show mountpoint informations (/proc/self/mountinfo) ?? */

	if (depth) {
		fputs("\nT     MODE       #LINK         UID         GID   MAJ      MIN                 SIZE                 CTIME  PATH\n",
		      stdio);
		ret = etux_fstree_scan("/",
		                       ETUX_FSTREE_PRE_OPT | ETUX_FSTREE_XDEV_OPT,
		                       enbox_show_root_fs,
		                       show);
		if (ret)
			fprintf(stdio,
			        "cannot scan root filesystem: %s (%d).\n",
			        strerror(-ret),
			        -ret);
	}

	enbox_destroy_show(show);
}
