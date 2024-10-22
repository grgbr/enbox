#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <stroll/cdefs.h>
#include <utils/pwd.h>
#include <utils/file.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <linux/capability.h>
#include <linux/securebits.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#warning REMOVE ME
#define CONFIG_ENBOX_ASSERT 1

#if defined(CONFIG_ENBOX_ASSERT)

#define enbox_assert(_expr) \
	stroll_assert("enbox", _expr)

#else /* !defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert(_expr)

#endif /* defined(CONFIG_ENBOX_ASSERT) */

#define enbox_err(_msg, ...) \
	fprintf(stderr, \
	        "%s: " _msg ".\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

/******************************************************************************
 * Low-level / syscall helpers.
 ******************************************************************************/

static int __upath_nonull(1) __nothrow
enbox_make_dir(const char * path, uid_t uid, gid_t gid, mode_t mode)
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(uid >= 0);
	enbox_assert(gid >= 0);
	enbox_assert(!(mode & ~ALLPERMS));
	enbox_assert(mode & (S_IXUSR | S_IXGRP | S_IXOTH));

	int err;

	err = upath_mkdir(path, S_IRWXU);
	if (err)
		return err;

	err = upath_chown(path, uid, gid);
	if (err)
		return err;

	err = upath_chmod(path, mode);
	if (err)
		return err;

	return 0;
}

static int __nothrow
enbox_unshare(int flags)
{
	if (!unshare(flags))
		return 0;

	enbox_assert(errno != EINVAL);

	return -errno;
}

#define ENBOX_MOUNT_TIME_FLAGS \
	(MS_LAZYTIME | MS_NOATIME | MS_RELATIME | MS_STRICTATIME | \
	 MS_NODIRATIME)

/*
 * Notes:
 * - MS_NOATIME implies MS_NODIRATIME
 */
#define enbox_assert_mount_time_flags(_flags) \
	enbox_assert(!((_flags) & ENBOX_MOUNT_TIME_FLAGS) || \
	             (((_flags) & (MS_NOATIME | MS_NODIRATIME)) != \
	              (MS_NOATIME | MS_NODIRATIME))); \
	enbox_assert(!((_flags) & ENBOX_MOUNT_TIME_FLAGS) || \
	             (((_flags) & (MS_NOATIME | MS_RELATIME)) != \
	              (MS_NOATIME | MS_RELATIME))); \
	enbox_assert(!((_flags) & ENBOX_MOUNT_TIME_FLAGS) || \
	             (((_flags) & (MS_NOATIME | MS_STRICTATIME)) != \
	              (MS_NOATIME | MS_STRICTATIME))); \
	enbox_assert(!((_flags) & ENBOX_MOUNT_TIME_FLAGS) || \
	             (((_flags) & (MS_NOATIME | MS_LAZYTIME)) != \
	              (MS_NOATIME | MS_LAZYTIME))); \
	enbox_assert(!((_flags) & ENBOX_MOUNT_TIME_FLAGS) || \
	             (((_flags) & (MS_RELATIME | MS_STRICTATIME)) != \
	              (MS_RELATIME | MS_STRICTATIME)))

static int __nothrow
enbox_mount(const char * source,
            const char * target,
            const char * fstype,
            int          flags,
            const char * data)
{
	enbox_assert_mount_time_flags(flags);

	if (!mount(source, target, fstype, flags, data))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != ENAMETOOLONG);

	return -errno;
}

static int __nothrow
enbox_umount(const char * path, int flags)
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(!(flags & ~(MNT_FORCE | MNT_DETACH |
	                         MNT_EXPIRE | UMOUNT_NOFOLLOW)));
	enbox_assert(!(flags & MNT_EXPIRE) ||
	             !(flags & (MNT_FORCE | MNT_DETACH)));

	if (!umount2(path, flags))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != ENAMETOOLONG);

	return 0;
}


static int __nothrow
enbox_pivot_root(const char * __restrict new_root,
                 const char * __restrict old_root)
{
	enbox_assert(upath_validate_path_name(new_root) > 0);
	enbox_assert(upath_validate_path_name(old_root) > 0);

	int err;

	if (!syscall(__NR_pivot_root, new_root, old_root))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != ENAMETOOLONG);

	return -errno;
}

/******************************************************************************
 * Populating vault
 ******************************************************************************/

#define ENBOX_SOURCE_UID  ((uid_t)-1)
#define ENBOX_SOURCE_GID  ((gid_t)-1)
#define ENBOX_SOURCE_MODE ((mode_t)-1)
#define ENBOX_NODATA      (NULL)

struct enbox_dir {
	const char * path;
	uid_t        uid;
	gid_t        gid;
	mode_t       mode;
};

#define ENBOX_DIR(_path, _uid, _gid, _mode) \
	{ \
		.populate     = enbox_settle_dir, \
		.dir          = { \
			.path = _path, \
			.uid  = _uid, \
			.gid  = _gid, \
			.mode = _mode \
		} \
	}

enum enbox_proc_hide {
	ENBOX_PROC_HIDE_OFF       = 0,
	ENBOX_PROC_HIDE_NOACCESS  = 1,
	ENBOX_PROC_HIDE_INVISIBLE = 2,
	ENBOX_PROC_HIDE_PTRACE    = 4
};

/* See <linux>/Documentation/filesystems/proc.rst for hidepid setting. */
struct enbox_proc {
	mode_t               mode;
	int                  flags;
	enum enbox_proc_hide hide;
	bool                 subset;
};

#define ENBOX_PROC_DFLT_FLAGS \
	(MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NOEXEC)

#define ENBOX_PROC_ALL_PIDS \
	(false)

#define ENBOX_PROC_TASK_PIDS \
	(true)

#define ENBOX_PROC(_mode, _flags, _hide, _subset) \
	{ \
		.populate       = enbox_settle_proc, \
		.proc           = { \
			.mode   = _mode, \
			.flags  = _flags, \
			.hide   = _hide, \
			.subset = _subset \
		} \
	}

struct enbox_bind {
	const char * src;
	const char * dst;
	uid_t        uid;
	gid_t        gid;
	mode_t       mode;
	int          flags;
};

#define ENBOX_BIND_DFLT_FLAGS \
	(MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOATIME)

#define ENBOX_BIND(_src, _dst, _uid, _gid, _mode, _flags) \
	{ \
		.populate       = enbox_settle_bind, \
		.bind           = { \
			.src    = _src, \
			.dst    = _dst, \
			.uid    = _uid, \
			.gid    = _gid, \
			.mode   = _mode, \
			.flags  = _flags \
		} \
	}

struct enbox_file {
	const char * src;
	const char * dst;
	uid_t        uid;
	gid_t        gid;
	mode_t       mode;
	int          flags;
};

#define ENBOX_FILE_DFLT_FLAGS \
	(MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOATIME | MS_NOEXEC)

#define ENBOX_EXE_DFLT_FLAGS \
	(MS_RDONLY | MS_NODEV | MS_NOSUID | MS_NOATIME)

#define ENBOX_FILE(_src, _dst, _uid, _gid, _mode, _flags) \
	{ \
		.populate       = enbox_settle_file, \
		.file           = { \
			.src    = _src, \
			.dst    = _dst, \
			.uid    = _uid, \
			.gid    = _gid, \
			.mode   = _mode, \
			.flags  = _flags \
		} \
	}

struct enbox_slink {
	const char * path;
	const char * target;
	uid_t        uid;
	gid_t        gid;
};

#define ENBOX_SLINK(_src, _dst, _uid, _gid, _mode, _flags) \
	{ \
		.populate       = enbox_settle_slink, \
		.slink          = { \
			.path   = _path, \
			.target = _target, \
			.uid    = _uid, \
			.gid    = _gid \
		} \
	}

struct enbox_entry;

typedef int (enbox_populate_fn)(const struct enbox_entry * entry);

struct enbox_entry {
	enbox_populate_fn *        populate;
	union {
		struct enbox_dir   dir;
		struct enbox_proc  proc;
		struct enbox_bind  bind;
		struct enbox_file  file;
		struct enbox_slink slink;
	};
};

#define enbox_assert_entry(_entry) \
	enbox_assert(_entry); \
	enbox_assert((_entry)->populate)

#if defined(CONFIG_ENBOX_ASSERT)

static ssize_t
enbox_normalize_path(const char * path, char ** normalized)
{
	ssize_t len;
	char *  norm;

	len = upath_validate_path_name(path);
	if (len < 0)
		return len;

	norm = malloc(len + 1);
	if (!norm)
		return -errno;

	len = upath_normalize(path, len + 1, norm, len + 1);
	if (len < 0) {
		free(norm);
		return len;
	}

	*normalized = norm;
	
	return len;
}

static int
enbox_validate_dst(const char * path)
{
	char *  norm;
	ssize_t len;
	int     ret = 0;

	len = enbox_normalize_path(path, &norm);
	if (len <= 0)
		return len ? len : -ENODATA;

	if (norm[0] == '/')
		goto einval;

	if (norm[0] != '.')
		goto free;

	if ((len < 2) || (norm[1] != '.'))
		goto free;

	if ((norm[2] != '/') && (norm[2] != '\0'))
		goto free;

einval:
	ret = -EINVAL;
free:
	free(norm);

	return ret;
}

#define enbox_assert_dst(_path) \
	enbox_assert(!enbox_validate_dst(_path))

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert_dst(_path)

#endif /* defined(CONFIG_ENBOX_ASSERT) */

#define ENBOX_VALID_MOUNT_FLAGS \
	(MS_DIRSYNC | MS_MANDLOCK | MS_NODEV | MS_NOEXEC | MS_NOSUID | \
	 MS_RDONLY | MS_SILENT | MS_SYNCHRONOUS | ENBOX_MOUNT_TIME_FLAGS)

static int __nothrow
enbox_remount(const char * __restrict path,
              int                     flags,
              const char * __restrict data)
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(!(flags & ~(MS_BIND | ENBOX_VALID_MOUNT_FLAGS)));

	/*
	 * Source and filesystem type arguments are ignored.
	 *
	 * The flags and data arguments should match the values used in the
	 * original mount() call, except for those parameters that are being
	 * deliberately changed.
	 *
	 * MS_SILENT and MS_DIRSYNC flags will be silently ignored.
	 *
	 * See also «Remounting an existing mount» section of mount(2) man page.
	 */

	return enbox_mount(NULL, path, NULL, MS_REMOUNT | flags, data);
}

static int __nothrow
enbox_bind_mount(const char * __restrict source, const char * __restrict target)
{
	enbox_assert(upath_validate_path_name(source) > 0);
	enbox_assert(upath_validate_path_name(target) > 0);
	enbox_assert(strncmp(source, target, PATH_MAX));

	int ret;

	/*
	 * At initial binding time, flags are ignored except MS_REC.
	 * In addition, filesystem type and data arguments are also ignored.
	 *
	 * See «Creating a bind mount» section of mount(2) man page.
	 */
	ret = enbox_mount(source, target, NULL, MS_BIND, NULL);
	if (ret)
		return ret;

	/*
	 * Prevent further operations from binding this mountpoint again.
	 *
	 * The only other flags that can be specified while changing the
	 * propagation type are MS_REC (described below) and MS_SILENT (which is
	 * ignored).
	 *
	 * See «Changing the propagation type of an existing mount» section of
	 * mount(2) man page.
	 */
	return enbox_mount(NULL, target, NULL, MS_UNBINDABLE, NULL);
}

static int
enbox_settle_dir(const struct enbox_entry * entry)
{
	enbox_assert_entry(entry);

	const struct enbox_dir * dir = &entry->dir;
	int                      ret;

	enbox_assert_dst(dir->path);
	enbox_assert(dir->uid >= 0);
	enbox_assert(dir->gid >= 0);
	enbox_assert(!(dir->mode & ~ACCESSPERMS));
	enbox_assert(dir->mode & (S_IXUSR | S_IXGRP | S_IXOTH));

	ret = enbox_make_dir(dir->path, dir->uid, dir->gid, dir->mode);
	if (ret)
		enbox_err("'%s': cannot create directory: %s (%d)",
		          dir->path,
		          strerror(-ret),
		          -ret);

	return ret;
}

#define ENBOX_PROC_OPTS_LEN \
	(sizeof("hidepid=") - 1 + \
	 1 + \
	 sizeof(",subset=") - 1 + \
	 10)

static int
enbox_settle_proc(const struct enbox_entry * entry)
{
	enbox_assert_entry(entry);

	const struct enbox_proc * proc = &entry->proc;
	char                      opts[ENBOX_PROC_OPTS_LEN + 1];
	size_t                    len;
	int                       err;

	enbox_assert(!(proc->mode & ~ACCESSPERMS));
	enbox_assert(proc->mode & (S_IXUSR | S_IXGRP | S_IXOTH));
	enbox_assert(!(proc->flags & ~ENBOX_VALID_MOUNT_FLAGS));
	enbox_assert_mount_time_flags(proc->flags);
	enbox_assert(proc->hide >= 0);
	enbox_assert(proc->hide <= ENBOX_PROC_HIDE_PTRACE);

	err = enbox_make_dir("proc", 0, 0, proc->mode);
	if (err)
		goto err;

	len = snprintf(opts, sizeof(opts), "hidepid=%d", proc->hide);
	enbox_assert(len > 0);
	enbox_assert(len < sizeof(opts));

	if (proc->subset) {
		size_t l;

		l = snprintf(&opts[len],
		             sizeof(opts) - len,
		             ",subset=%d",
		             getpid());
		enbox_assert(l > 0);
		enbox_assert((len + l) < sizeof(opts));

		len += l;
	}

	err = enbox_mount("proc", "proc", "proc", proc->flags, opts);
	if (err)
		goto err;

	err = enbox_mount(NULL, "proc", NULL, MS_UNBINDABLE, NULL);
	if (err)
		goto err;

	return 0;

err:
	enbox_err("cannot mount proc filesystem: %s (%d)",
	          strerror(-err),
	          -err);

	return err;
}

static int
enbox_settle_bind(const struct enbox_entry * entry)
{
	enbox_assert_entry(entry);

	const struct enbox_bind * bind = &entry->bind;
	struct stat               stat;
	int                       err;

	enbox_assert(upath_validate_path_name(bind->src) > 0);
	enbox_assert_dst(bind->dst);
	enbox_assert(bind->uid >= 0);
	enbox_assert(bind->gid >= 0);
	enbox_assert(!(bind->mode & ~ACCESSPERMS));
	enbox_assert(bind->mode & (S_IXUSR | S_IXGRP | S_IXOTH));
	enbox_assert(!(bind->flags & ~ENBOX_VALID_MOUNT_FLAGS));
	enbox_assert_mount_time_flags(bind->flags);

	err = upath_lstat(bind->src, &stat);
	if (err < 0)
		goto err;

	if (!S_ISDIR(stat.st_mode)) {
		err = -EPERM;
		goto err;
	}

	err = upath_mkdir(bind->dst, S_IRWXU);
	if (err)
		goto err;

	err = upath_chown(bind->dst, bind->uid, bind->gid);
	if (err)
		goto err;

	err = enbox_bind_mount(bind->src, bind->dst);
	if (err)
		goto err;

	err = upath_chmod(bind->dst, bind->mode);
	if (err)
		goto err;

	if (bind->flags) {
		/*
		 * To change the bind mount properties, we have to remount it
		 * with new flags in addition to MS_BIND.
		 *
		 * See also «Remounting an existing mount» section of mount(2)
		 * man page.
		 */
		err = enbox_remount(bind->dst, MS_BIND | bind->flags, NULL);
		if (err)
			goto err;
	}

	return 0;

err:
	enbox_err("'%s': cannot bind mount directory: %s (%d)",
	          bind->dst,
	          strerror(-err),
	          -err);

	return err;
}

#define ENBOX_FILE_VALID_FLAGS \
	(MS_MANDLOCK | MS_NODEV | MS_NOEXEC | MS_NOSUID | \
	 MS_RDONLY | MS_SILENT | MS_SYNCHRONOUS | \
	 MS_LAZYTIME | MS_NOATIME | MS_RELATIME | MS_STRICTATIME)

static int
enbox_settle_file(const struct enbox_entry * entry)
{
	enbox_assert_entry(entry);

	const struct enbox_file * file = &entry->file;
	struct stat               stat;
	int                       err;
	int                       fd;

	enbox_assert(upath_validate_path_name(file->src) > 0);
	enbox_assert_dst(file->dst);
	enbox_assert(file->uid >= 0);
	enbox_assert(file->gid >= 0);
	enbox_assert(!(file->mode & ~ACCESSPERMS));
	enbox_assert(!(file->flags & ~ENBOX_FILE_VALID_FLAGS));
	enbox_assert_mount_time_flags(file->flags);
	enbox_assert((file->flags & MS_NOEXEC) ^
	             (file->mode & (S_IXUSR | S_IXGRP | S_IXOTH)));
	
	err = upath_lstat(file->src, &stat);
	if (err < 0)
		goto err;

	if (!S_ISREG(stat.st_mode)) {
		err = -EPERM;
		goto err;
	}

	fd = ufile_new(file->dst,
	               O_WRONLY | O_EXCL | O_CLOEXEC | O_NOATIME | O_NOFOLLOW |
	               O_NONBLOCK,
	               S_IRWXU);
	if (fd < 0) {
		err = fd;
		goto err;
	}

	err = ufile_fchown(fd, file->uid, file->gid);
	if (err)
		goto err;

	err = enbox_bind_mount(file->src, file->dst);
	if (err)
		goto err;

	err = upath_chmod(file->dst, file->mode);
	if (err)
		goto err;

	if (file->flags) {
		/*
		 * To change the bind mount properties, we have to remount it
		 * with new flags in addition to MS_BIND.
		 *
		 * See also «Remounting an existing mount» section of mount(2)
		 * man page.
		 */
		err = enbox_remount(file->dst, MS_BIND | file->flags, NULL);
		if (err)
			goto err;
	}

	return 0;

err:
	enbox_err("'%s': cannot bind mount file: %s (%d)",
	          file->dst,
	          strerror(-err),
	          -err);

	return err;
}

static int
enbox_settle_slink(const struct enbox_entry * entry)
{
	enbox_assert_entry(entry);

	const struct enbox_slink * slink = &entry->slink;
	int                        err;

	enbox_assert_dst(slink->path);
	enbox_assert(upath_validate_path_name(slink->target) > 0);
	enbox_assert(strncmp(slink->path, slink->target, PATH_MAX));
	enbox_assert(slink->uid >= 0);
	enbox_assert(slink->gid >= 0);

	err = upath_symlink(slink->target, slink->path);
	if (err)
		goto err;

	err = upath_chown(slink->path, slink->uid, slink->gid);
	if (err)
		goto err;

	return 0;

err:
	enbox_err("'%s': cannot create symbolic link: %s (%d)",
	          slink->path,
	          strerror(-err),
	          -err);

	return err;
}

#if defined(CONFIG_ENBOX_ASSERT)

static void
enbox_ensure_cwd_is_root(void)
{
	char * wd;

	/* Rely upon glibc's extension to return a malloc'ed buffer here... */
	wd = getcwd(NULL, 0);

	enbox_assert(!strcmp(wd, "/"));

	free(wd);
}

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

static inline void enbox_ensure_cwd_is_root(void) { }

#endif /* defined(CONFIG_ENBOX_ASSERT) */

static int
enbox_chroot_vault(void)
{
	int err;

	/*
	 * Moves the root mount to the current working directory and make it the
	 * new root mount within current (mount) namespace.
	 *
	 * pivot_root() changes the root directory and the current working
	 * directory of each process or thread in the same mount namespace
	 * to the new root if they point to the old root directory.  (See also
	 * NOTES.)  On the other hand, pivot_root() does not change the
	 * caller's current working directory (unless it is on the old root
	 * directory), and thus it should be followed by a chdir("/") call.
	 */
	err = enbox_pivot_root(".", ".");
	if (err)
		return err;

	/*
	 * This sequence succeeds because the pivot_root() call stacks the
	 * old root mount point on top of the new root mount point at /.  At
	 * that point, the calling process's root directory and current
	 * working directory refer to the new root mount point (new_root).
	 * During the subsequent umount() call, resolution of "."  starts
	 * with new_root and then moves up the list of mounts stacked at /,
	 * with the result that old root mount point is unmounted.
	 */
	err = enbox_umount(".", MNT_DETACH);
	if (err)
		return err;

	/*
	 * rssert if current working directory is not "/" (see above comment
	 * related to pivot_root().
	 */
	enbox_ensure_cwd_is_root();

	return 0;
}

#define ENBOX_ROOTFS_MNTOPTS \
	(MS_NOATIME | MS_NODEV | MS_NOSUID)

#define ENBOX_ROOTFS_EXTOPTS \
	"mode=0555,size=4k,nr_inodes="

#define ENBOX_ROOTFS_EXTOPTS_LEN \
	(sizeof(ENBOX_ROOTFS_EXTOPTS) - 1 + 10)

static int
enbox_mount_root(const char * __restrict path,
                 unsigned int            inodes_nr,
                 char                    options[__restrict_arr])
{
	int err;

	/*
	 * Make all currently mounted filesystems private so that filesystems
	 * mounted later on do not get propagated / shared with other mount
	 * namespaces.
	 */
	err = enbox_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (err)
		return err;

	/*
	 * Give mount the maximum number of allowed inodes (+ 1 for the
	 * top-level root directory).
	 */
	snprintf(options,
	         ENBOX_ROOTFS_EXTOPTS_LEN + 1,
	         ENBOX_ROOTFS_EXTOPTS "%u",
	         inodes_nr + 1);

	err = enbox_mount("root", path, "tmpfs", ENBOX_ROOTFS_MNTOPTS, options);
	if (err)
		return err;

	/* Make root filesystem private and not bindable... */
	err = enbox_mount(NULL, path, NULL, MS_UNBINDABLE, NULL);
	if (err)
		return err;

	return 0;
}

static int
enbox_remount_root(const char * __restrict path,
                   const char              options[__restrict_arr])
{
	int err;

	/*
	 * We need to close every file descriptors opened onto root filesystem
	 * to be allowed to remount it with the right options.
	 */
	err = ufd_close_fds(STDERR_FILENO + 1, ~(0));
	if (err)
		return err;

	/* Remount root read-only with given options. */
	err = enbox_remount(path, MS_RDONLY | ENBOX_ROOTFS_MNTOPTS, options);
	if (err)
		return err;

	return 0;
}

static int
enbox_setup_vault(const char * __restrict  path,
                  const struct enbox_entry entries[__restrict_arr],
                  size_t                   nr)
{
	const char * msg;
	int          err;
	char         opts[ENBOX_ROOTFS_EXTOPTS_LEN + 1];
	unsigned int e;

	/*
	 * Dissociate from parent process namespaces.
	 *
	 * Note:
	 * - CLONE_FILES not needed since current file descriptor table is
	 *   duplicated at execve() time.
	 *
	 * TODO: CLONE_FS ??
	 */
	err = enbox_unshare(CLONE_NEWCGROUP |
	                    CLONE_NEWIPC |
	                    CLONE_NEWNS |
	                    CLONE_NEWNET |
	                    CLONE_NEWUTS |
	                    CLONE_SYSVSEM);
	if (err) {
		msg = "cannot dissociate from parent namespaces";
		goto err;
	}

	err = enbox_mount_root(path, nr, opts);
	if (err) {
		msg = "cannot mount vault's initial filesystem";
		goto err;
	}

	err = upath_chdir(path);
	enbox_assert(!err);

	for (e = 0; e < nr; e++) {
		const struct enbox_entry * ent = &entries[e];

		enbox_assert(ent);
		enbox_assert(ent->populate);

		err = ent->populate(ent);
		if (err) {
			msg = "cannot populate vault's filesystem";
			goto err;
		}
	}

	err = enbox_remount_root(path, opts);
	if (err) {
		msg = "cannot remount vault's final filesystem";
		goto err;
	}

	err = enbox_chroot_vault();
	if (err) {
		msg = "cannot chroot into vault";
		goto err;
	}

	return 0;

err:
	enbox_err("%s: %s (%d)", msg, strerror(-err), -err);

	return err;
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

enum enbox_dumpable {
	/* Disable coredump generation */
	ENBOX_DISABLE_DUMP = 0,
	/* Coredump generation allowed. */
	ENBOX_ENABLE_DUMP  = 1,
	/* Coredump generation allowed but readable by root only. */
	ENBOX_RDROOT_DUMP  = 2
};

/*
 * Disable generation of coredumps for current process.
 * As side effect, it can not be attached via ptrace(2) PTRACE_ATTACH either.
 *
 * Normally, the "dumpable" attribute is set to 1. However, it is reset to the
 * current value contained in the file /proc/sys/fs/suid_dumpable (which by
 * default has the value 0), in the following circumstances:
 * - current process EUID or EGID is changed ;
 * - current process FSUID or FSGID is changed ;
 * - current process execve(2) a SUID / SGID program incurring a EUID / EGID
 *   change ;
 * - current process execve(2) a program that has file capabilities exceeding
 *   those already permitted.
 */
static int
enbox_setup_dump(enum enbox_dumpable dump)
{
	if (!prctl(PR_SET_DUMPABLE, dump, 0, 0, 0))
		return 0;

	return -errno;
}

static void
enbox_prepare_execve(const struct passwd * __restrict user,
                     bool                             drop,
                     const char * __restrict          path,
                     const struct enbox_entry         entries[__restrict_arr],
                     size_t                           nr)
{
	enbox_assert(user);
	enbox_assert(user->pw_uid > 0);

	int          err;
	const char * msg;

	err = clearenv();
	if (err) {
		msg = "cannot clear environment";
		goto err;
	}

	err = enbox_caps_lock();
	if (err) {
		msg = "cannot lock capabilities";
		goto err;
	}

	err = enbox_setup_dump(ENBOX_DISABLE_DUMP);
	if (err) {
		msg = "cannot disable coredump generation";
		goto err;
	}

	/*
	 * Clear bounding set capabilities.
	 * Effective, permitted, inheritable and ambient sets will be cleared at
	 * execve() time.
	 */
	err = enbox_caps_drop_bounding();
	if (err) {
		msg = "cannot drop bounding set capabilities";
		goto err;
	}

	err = enbox_setup_vault(path, entries, nr);
	if (err) {
		msg = "cannot setup vault";
		goto err;
	}

#if 1
	/*
	 * Switch to user's primary group, i.e. set real, effective and saved
	 * set-group-ID GIDs to user's primary GID given in argument.
	 */
	err = enbox_change_gid(user->pw_gid);
	if (err) {
		msg = "cannot switch to primary group";
		goto err;
	}

	if (drop) {
		/* Clear / leave all supplementary groups. */
		err = enbox_drop_supp_groups();
		if (err) {
			msg = "cannot drop supplementary groups";
			goto err;
		}
	}
	else {
		/*
		 * Load / join user's supplementary groups from list retreived
		 * from system password databases.
		 */
		err = enbox_raise_supp_groups(user->pw_name, user->pw_gid);
		if (err) {
			msg = "cannot initialize supplementary groups";
			goto err;
		}
	}

	/*
	 * Switch to user, i.e. set real, effective and saved set-user-ID UIDs
	 * to user's UID given in argument.
	 */
	err = enbox_change_uid(user->pw_uid);
	if (err) {
		msg = "cannot switch to user";
		goto err;
	}
#endif

	return;

err:
	enbox_err("%s: %s (%d)", msg, strerror(-err), -err);
exit:
	exit(EXIT_FAILURE);
}

void
enbox_prepare_execve_byuid(uid_t                    uid,
                           bool                     drop,
                           const char * __restrict  path,
                           const struct enbox_entry entries[__restrict_arr],
                           size_t                   nr)

{
	enbox_assert(uid > 0);

	const struct passwd * user;

	user = upwd_get_user_byid(uid);
	if (!user) {
		enbox_err("invalid UID specified: %s (%d)",
		          strerror(errno),
		          errno);
		exit(EXIT_FAILURE);
	}

	enbox_prepare_execve(user, drop, path, entries, nr);
}

void
enbox_prepare_execve_byuser(const char * __restrict  name,
                            bool                     drop,
                            const char * __restrict  path,
                            const struct enbox_entry entries[__restrict_arr],
                            size_t                   nr)
{
	enbox_assert(upwd_validate_user_name(name) > 0);

	const struct passwd * user;

	user = upwd_get_user_byname(name);
	if (!user) {
		enbox_err("invalid user name specified: %s (%d)",
		          strerror(errno),
		          errno);
		exit(EXIT_FAILURE);
	}

	enbox_prepare_execve(user, drop, path, entries, nr);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static const struct enbox_entry sample_entries[] = {
	ENBOX_PROC(0755,
	           ENBOX_PROC_DFLT_FLAGS,
	           ENBOX_PROC_HIDE_INVISIBLE,
	           ENBOX_PROC_ALL_PIDS),
	           //ENBOX_PROC_TASK_PIDS),
	ENBOX_BIND("/lib",          "lib",         0, 0, 0555, ENBOX_BIND_DFLT_FLAGS),
	ENBOX_BIND("/lib64",        "lib64",       0, 0, 0555, ENBOX_BIND_DFLT_FLAGS),
	ENBOX_DIR(                  "usr",         0, 0, 0555                       ),
	ENBOX_BIND("/usr/lib",      "usr/lib",     0, 0, 0555, ENBOX_BIND_DFLT_FLAGS),
	ENBOX_DIR(                  "bin",         0, 0, 0555                       ),
	ENBOX_FILE("/bin/cat",      "bin/cat",     0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/chmod",    "bin/chmod",   0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/df",       "bin/df",      0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/usr/bin/env",  "bin/env",     0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/usr/bin/find", "bin/find",    0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/findmnt",  "bin/findmnt", 0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/ls",       "bin/ls",      0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/ps",       "bin/ps",      0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/rm",       "bin/rm",      0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
	ENBOX_FILE("/bin/bash",     "bin/sh",      0, 0, 0555, ENBOX_EXE_DFLT_FLAGS ),
};

int
main(void)
{
	int err;

	enbox_prepare_execve_byuser("test",
	                            false,
	                            "/tmp/jail",
	                            sample_entries,
	                            stroll_array_nr(sample_entries));

	//execl("/bin/sh", "/bin/sh", "-c", CMD, NULL);
	//execl("/bin/ls", "/bin/ls", "-al", "/", NULL);
	//execl("/usr/bin/touch", "/usr/bin/touch", "/mytest", NULL);
	//execl("/bin/findmnt", "/bin/findmnt", "-o", "TARGET,SOURCE,FSTYPE,PROPAGATION,OPTIONS", NULL);
	//execl("/bin/ls", "/bin/ls", "-al", "/", "/bin", NULL);
	execl("/bin/sh", "/bin/sh", NULL);
}
