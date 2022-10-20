#include "common.h"
#include <utils/path.h>
#include <utils/file.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <linux/capability.h>
#include <linux/securebits.h>

struct elog * enbox_logger;
mode_t        enbox_umask = (mode_t)-1;
uid_t         enbox_uid = (uid_t)-1;
gid_t         enbox_gid = (gid_t)-1;

/******************************************************************************
 * Raw API
 ******************************************************************************/

static int __enbox_nonull(1) __nothrow
enbox_chown(const char * path, uid_t uid, gid_t gid)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert((uid != ENBOX_KEEP_UID) || (gid != ENBOX_KEEP_GID));

	int err;

	err = upath_chown(path, uid, gid);
	if (!err)
		return 0;

	enbox_info("'%s': cannot change ownership: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

static int __enbox_nonull(1) __nothrow
enbox_chmod(const char * path, mode_t mode)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(!(mode & ~ALLPERMS));

	int err;

	err = upath_chmod(path, mode);
	if (!err)
		return 0;

	enbox_info("'%s': cannot change mode: %s (%d)",
	           path,
	           strerror(-err),
	           -err);
	return err;
}

int
enbox_change_perms(const char * path, uid_t uid, gid_t gid, mode_t mode)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(!(mode & ~ALLPERMS) || (mode == ENBOX_KEEP_MODE));
	enbox_assert((uid != ENBOX_KEEP_UID) ||
	             (gid != ENBOX_KEEP_GID) ||
	             (mode != ENBOX_KEEP_MODE));

	int err;

	if ((uid != ENBOX_KEEP_UID) || (gid != ENBOX_KEEP_GID)) {
		err = enbox_chown(path, uid, gid);
		if (err)
			goto err;
	}

	if (mode != ENBOX_KEEP_MODE) {
		err = enbox_chmod(path, mode);
		if (err)
			goto err;
	}

	return 0;

err:
	enbox_info("'%s': cannot change permissions: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_make_dir(const char * path, uid_t uid, gid_t gid, mode_t mode)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);
	enbox_assert(!(mode & ~ALLPERMS));

	int err;

	err = upath_mkdir(path, S_IRWXU);
	if (err) {
		/* Directory creation failed... */
		if (err == -EEXIST) {
			/*
			 * ... because it already exists: ensure it complies
			 * with requested UID, GID and permissions.
			 */
			struct stat stat;

			/* Prevent from following symlinks ! */
			err = upath_lstat(path, &stat);
			if (err)
				goto err;

			/* Not a directory: not of our business. */
			if (!S_ISDIR(stat.st_mode)) {
				err = -ENOTDIR;
				goto err;
			}

			if ((uid != stat.st_uid) || (gid != stat.st_gid)) {
				err = enbox_chown(path, uid, gid);
				if (err)
					goto err;
			}

			if (mode != (stat.st_mode & ALLPERMS)) {
				err = enbox_chmod(path, mode);
				if (err)
					goto err;
			}
		}
		else
			goto err;
	}
	else {
		/* Directory has been successfully created. */
		if ((uid != enbox_uid) || (gid != enbox_gid)) {
			err = enbox_chown(path, uid, gid);
			if (err)
				goto rmdir;
		}

		if (mode != S_IRWXU) {
			err = enbox_chmod(path, mode);
			if (err)
				goto rmdir;
		}
	}

	return 0;

rmdir:
	/* In case of error: remove the directory just created. */
	upath_rmdir(path);
err:
	enbox_info("'%s': cannot create directory: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_make_slink(const char * __restrict path,
                 const char * __restrict target,
                 uid_t                   uid,
                 gid_t                   gid)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(upath_validate_path_name(target) > 0);
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);

	int    err;
	char * lnk;

	err = upath_symlink(target, path);
	if (err) {
		if (err == -EEXIST) {
			struct stat stat;

			err = upath_lstat(path, &stat);
			if (err)
				goto err;

			if (!S_ISLNK(stat.st_mode)) {
				err = -EEXIST;
				goto err;
			}

			lnk = malloc(PATH_MAX);
			if (!lnk) {
				err = -errno;
				goto err;
			}

			err = readlink(path, lnk, PATH_MAX);
			enbox_assert(err);
			enbox_assert(err < PATH_MAX);
			if (err < 0) {
				enbox_assert(errno != EFAULT);
				err = -errno;
				goto free;
			}
			lnk[err] = '\0';

			if (strncmp(target, lnk, err + 1)) {
				err = -EPERM;
				goto free;
			}

			free(lnk);

			if ((uid != stat.st_uid) || (gid != stat.st_gid)) {
				err = enbox_chown(path, uid, gid);
				if (err)
					goto err;
			}
		}
		else
			goto err;
	}
	else {
		if ((uid != enbox_uid) || (gid != enbox_gid)) {
			err = enbox_chown(path, uid, gid);
			if (err) {
				upath_unlink(path);
				goto err;
			}
		}
	}

	return 0;

free:
	free(lnk);
err:
	enbox_info("'%s': cannot create symbolic link: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

static int __enbox_nonull(1) __nothrow
enbox_make_node(const char * path, mode_t mode, dev_t dev, uid_t uid, gid_t gid)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(!(mode & ~(S_IFCHR | S_IFBLK | DEFFILEMODE)));
	enbox_assert(S_ISCHR(mode) ^ S_ISBLK(mode));
	upath_assert((major(dev) > 0) || !(mode & (S_IFCHR | S_IFBLK)));
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);

	int    err;
	mode_t type = mode & S_IFMT;

	err = upath_mknod(path, type | S_IRUSR | S_IWUSR, dev);
	if (err) {
		if (err == -EEXIST) {
			struct stat stat;

			err = upath_lstat(path, &stat);
			if (err)
				goto err;

			if (type != (stat.st_mode & S_IFMT)) {
				err = -EEXIST;
				goto err;
			}

			if ((uid != stat.st_uid) || (gid != stat.st_gid)) {
				err = enbox_chown(path, uid, gid);
				if (err)
					goto err;
			}

			if ((mode & ALLPERMS) != (stat.st_mode & ALLPERMS)) {
				err = enbox_chmod(path, mode & DEFFILEMODE);
				if (err)
					goto err;
			}
		}
		else
			goto err;
	}
	else {
		if ((uid != enbox_uid) || (gid != enbox_gid)) {
			err = enbox_chown(path, uid, gid);
			if (err)
				goto unlink;
		}

		if ((mode & ALLPERMS) != (S_IRUSR | S_IWUSR)) {
			err = enbox_chmod(path, mode & DEFFILEMODE);
			if (err)
				goto unlink;
		}
	}

	return 0;

unlink:
	upath_unlink(path);
err:
	return err;
}

int
enbox_make_chrdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);
	enbox_assert(!(mode & ~DEFFILEMODE));
	enbox_assert(major > 0);

	int err;

	err = enbox_make_node(path,
	                      S_IFCHR | mode,
	                      makedev(major, minor),
	                      uid,
	                      gid);
	if (!err)
		return 0;

	enbox_info("'%s': cannot create character device: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_make_blkdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(major > 0);
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);
	enbox_assert(!(mode & ~DEFFILEMODE));

	int err;

	err = enbox_make_node(path,
	                      S_IFBLK | mode,
	                      makedev(major, minor),
	                      uid,
	                      gid);
	if (!err)
		return 0;

	enbox_info("'%s': cannot create block device: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_make_fifo(const char * path, uid_t uid, gid_t gid, mode_t mode)
{
	enbox_assert_setup();
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(uid != ENBOX_KEEP_UID);
	enbox_assert(gid != ENBOX_KEEP_GID);
	enbox_assert(!(mode & ~DEFFILEMODE));

	int err;

	err = upath_mkfifo(path, S_IRUSR | S_IWUSR);
	if (err) {
		if (err == -EEXIST) {
			struct stat stat;

			err = upath_lstat(path, &stat);
			if (err)
				goto err;

			if (!S_ISFIFO(stat.st_mode)) {
				err = -EEXIST;
				goto err;
			}

			if ((uid != stat.st_uid) || (gid != stat.st_gid)) {
				err = enbox_chown(path, uid, gid);
				if (err)
					goto err;
			}

			if (mode != (stat.st_mode & ALLPERMS)) {
				err = enbox_chmod(path, mode);
				if (err)
					goto err;
			}
		}
		else
			goto err;
	}
	else {
		if ((uid != enbox_uid) || (gid != enbox_gid)) {
			err = enbox_chown(path, uid, gid);
			if (err)
				goto unlink;
		}

		if (mode != (S_IRUSR | S_IWUSR)) {
			err = enbox_chmod(path, mode);
			if (err)
				goto unlink;
		}
	}

	return 0;

unlink:
	upath_unlink(path);
err:
	enbox_info("'%s': cannot create named pipe: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_clear_ambient_caps(void)
{
	enbox_assert_setup();

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) {
		int err = errno;

		enbox_info("cannot clear ambient capability set: %s (%d)",
		           strerror(err),
		           err);
		return -err;
	}

	return 0;
}

int
enbox_clear_bounding_caps(void)
{
	enbox_assert_setup();

	int cap = 0;

	do {
		if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) < 0) {
			int err = errno;

			enbox_info("cannot drop bounding set capabilities: "
			           "%s (%d)",
			           strerror(err),
			           err);
			return -err;
		}

		cap++;
	} while (cap_valid(cap));

	return 0;
}

int
enbox_lock_caps(void)
{
	enbox_assert_setup();

	int err;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		goto err;

	if (prctl(PR_SET_SECUREBITS,
	          SECBIT_NOROOT |
	          /*SECBIT_NO_SETUID_FIXUP |*/
	          SECBIT_NO_CAP_AMBIENT_RAISE |
	          SECURE_ALL_LOCKS,
	          0,
	          0,
	          0,
	          0))
		goto err;

	return 0;

err:
	err = errno;
	enbox_info("cannot lock capabilities: %s (%d)", strerror(err), err);

	return -err;
}

/*
 * Require the CAP_SETUID capability.
 */
static int __nothrow __warn_result
enbox_change_uid(uid_t uid)
{
	if (!setresuid(uid, uid, uid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static int __nothrow __warn_result
enbox_change_gid(gid_t gid)
{
	if (!setresgid(gid, gid, gid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static int __nothrow
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
static int __enbox_nonull(1)
enbox_raise_supp_groups(const char * user, gid_t gid)
{
	enbox_assert(upwd_validate_user_name(user) > 0);

	if (!initgroups(user, gid))
		return 0;

	return -errno;
}

int
enbox_validate_pwd(const struct passwd * __restrict pwd, bool allow_root)
{
	enbox_assert(pwd);

	int err;

	if ((pwd->pw_uid == (uid_t)-1) || (pwd->pw_gid == (gid_t)-1))
		return -ERANGE;

	if (!pwd->pw_name)
		return -EINVAL;

	err = upwd_validate_user_name(pwd->pw_name);
	if (err < 0)
		return err;

	if (!allow_root) {
		if (!strcmp(pwd->pw_name, "root") ||
		    !pwd->pw_uid ||
		    !pwd->pw_gid)
			return -EPERM;
	}

	return 0;
}

static int __enbox_nonull(1) __nothrow
enbox_switch_ids(const struct passwd * __restrict pwd, bool drop_supp)
{
	enbox_assert(!enbox_validate_pwd(pwd, false));

	int err;

	err = enbox_change_gid(pwd->pw_gid);
	if (err) {
		enbox_info("cannot switch to GID %hu(%s): %s (%d)",
		           pwd->pw_gid,
		           enbox_get_group_name(pwd->pw_gid),
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_gid = pwd->pw_gid;

	if (drop_supp)
		err = enbox_drop_supp_groups();
	else
		err = enbox_raise_supp_groups(pwd->pw_name, pwd->pw_gid);
	if (err) {
		enbox_info("cannot setup %d(%s) users's supplementary groups: "
		           "%s (%d)",
		           pwd->pw_uid,
		           pwd->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	err = enbox_change_uid(pwd->pw_uid);
	if (err) {
		enbox_info("cannot switch to UID %d(%s): %s (%d)",
		           pwd->pw_uid,
		           pwd->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_uid = pwd->pw_uid;

	return 0;
}

int
enbox_change_ids(const char * __restrict user, bool drop_supp)
{
	enbox_assert_setup();
	enbox_assert(upwd_validate_user_name(user) > 0);

	const struct passwd * pwd;
	int                   err;

	pwd = upwd_get_user_byname(user);
	if (!pwd || enbox_validate_pwd(pwd, false)) {
		err = -errno;
		enbox_info("invalid '%s' user name: %s (%d)",
		           user,
		           strerror(errno),
		           errno);
		goto err;
	}

	err = enbox_switch_ids(pwd, drop_supp);
	if (err)
		goto err;

	return 0;

err:
	enbox_info("cannot change to '%s' user / groups IDs: %s (%d)",
	           user,
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_setup_dump(bool on)
{
	enbox_assert_setup();

	if (prctl(PR_SET_DUMPABLE, (int)on, 0, 0, 0)) {
		int err = errno;

		enbox_info("cannot setup dumpable attribute: %s (%d)",
		           strerror(err),
		           err);
		return -err;
	}

	return 0;
}

/******************************************************************************
 * High-level API
 ******************************************************************************/

static int __enbox_nonull(1) __nothrow
enbox_make_dir_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	return enbox_make_dir(ent->path,
	                      ent->uid,
	                      ent->gid,
	                      ent->dir.mode);
}

static int __enbox_nonull(1) __nothrow
enbox_make_slink_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	return enbox_make_slink(ent->path,
	                        ent->slink.target,
	                        ent->uid,
	                        ent->gid);
}

static int __enbox_nonull(1) __nothrow
enbox_make_chrdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	return enbox_make_chrdev(ent->path,
	                         ent->uid,
	                         ent->gid,
	                         ent->dev.mode,
	                         ent->dev.major,
	                         ent->dev.minor);
}

static int __enbox_nonull(1) __nothrow
enbox_make_blkdev_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	return enbox_make_blkdev(ent->path,
	                         ent->uid,
	                         ent->gid,
	                         ent->dev.mode,
	                         ent->dev.major,
	                         ent->dev.minor);
}

static int __enbox_nonull(1) __nothrow
enbox_make_fifo_entry(const struct enbox_entry * __restrict ent)
{
	enbox_assert(ent->uid != (uid_t)-1);
	enbox_assert(ent->gid != (gid_t)-1);

	return enbox_make_fifo(ent->path,
	                       ent->uid,
	                       ent->gid,
	                       ent->fifo.mode);
}

typedef int  (enbox_make_entry_fn)(const struct enbox_entry * __restrict entry)
	__enbox_nonull(1);

static int __enbox_nonull(1, 3) __nothrow
enbox_make_entries(const struct enbox_entry    entries[__restrict_arr],
                   unsigned int                nr,
                   enbox_make_entry_fn * const makers[__restrict_arr])
{
	enbox_assert(entries);
	enbox_assert(nr);
	enbox_assert(makers);

	unsigned int e;

	for (e = 0; e < nr; e++) {
		const struct enbox_entry * ent = &entries[e];
		int                        err;

		enbox_assert_entry(ent);
		enbox_assert(makers[ent->type]);

		err = makers[ent->type](ent);
		if (err)
			return err;
	}

	return 0;
}

int
enbox_populate_host(const struct enbox_fsset * __restrict host)
{
	int                                err;
	static enbox_make_entry_fn * const makers[ENBOX_ENTRY_TYPE_NR] = {
		[ENBOX_DIR_ENTRY_TYPE]    = enbox_make_dir_entry,
		[ENBOX_SLINK_ENTRY_TYPE]  = enbox_make_slink_entry,
		[ENBOX_CHRDEV_ENTRY_TYPE] = enbox_make_chrdev_entry,
		[ENBOX_BLKDEV_ENTRY_TYPE] = enbox_make_blkdev_entry,
		[ENBOX_FIFO_ENTRY_TYPE]   = enbox_make_fifo_entry
	};

	err = enbox_make_entries(host->entries, host->nr, makers);
	if (err) {
		enbox_err("cannot populate host filesystem: %s (%d)",
		          strerror(-err),
		          -err);
		return err;
	}

	return 0;
}

static int __nothrow
enbox_unshare(int flags)
{
	enbox_assert(flags);

	if (!unshare(flags))
		return 0;

	enbox_assert(errno != EINVAL);

	return -errno;
}

/*
 * Ensure the given combination of inode timestamp related mounting flags is
 * valid.
 */
int
enbox_validate_mount_time_flags(unsigned long flags)
{
	if (!(flags & ENBOX_MOUNT_TIME_FLAGS))
		return 0;

	if ((flags & (MS_NOATIME | MS_NODIRATIME)) ==
	    (MS_NOATIME | MS_NODIRATIME))
		/* MS_NOATIME implies MS_NODIRATIME */
		return -EINVAL;

	if ((flags & (MS_NOATIME | MS_RELATIME)) ==
	    (MS_NOATIME | MS_RELATIME))
		/* MS_NOATIME conflicts with MS_RELATIME... */
		return -EINVAL;

	if ((flags & (MS_NOATIME | MS_STRICTATIME)) ==
	    (MS_NOATIME | MS_STRICTATIME))
		/* ...as well as with MS_STRICTATIME... */
		return -EINVAL;

	if ((flags & (MS_NOATIME | MS_LAZYTIME)) ==
	    (MS_NOATIME | MS_LAZYTIME))
		/* ...as well as with MS_LAZYTIME... */
		return -EINVAL;

	if ((flags & (MS_RELATIME | MS_STRICTATIME)) ==
	    (MS_RELATIME | MS_STRICTATIME))
		/* MS_RELATIME conflicts with MS_STRICTATIME... */
		return -EINVAL;

	/* OK. */
	return 0;
}

#define enbox_assert_mount_time_flags(_flags) \
	enbox_assert(!enbox_validate_mount_time_flags(_flags))

static int __nothrow
enbox_mount(const char *  source,
            const char *  target,
            const char *  fstype,
            unsigned long flags,
            const char *  data)
{
	enbox_assert_mount_time_flags(flags);

	if (!mount(source, target, fstype, flags, data))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != ENAMETOOLONG);

	return -errno;
}

static int __enbox_nonull(1) __nothrow
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

	return -errno;
}

static int __enbox_nonull(1) __nothrow
enbox_remount(const char * __restrict path,
              unsigned long           flags,
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

static int __enbox_nonull(1, 2) __nothrow
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

/*
 * Must be called as root from within an empty jail creation context only.
 */
static int __nothrow
enbox_mount_proc(unsigned long           flags,
                 const char * __restrict opts)
{
	enbox_assert(!enbox_get_uid());
	enbox_assert(!enbox_get_gid());
	enbox_assert(!(flags & ~ENBOX_PROC_VALID_FLAGS));
	enbox_assert_mount_time_flags(flags);
	enbox_assert(!opts || opts[0]);

	int err;

	/*
	 * Create ./proc mountpoint.
	 * This will fail if it already exists since we are meant to mount
	 * procfs from an initialy empty jail tmpfs.
	 */
	err = upath_mkdir("proc", S_IRWXU);
	if (err)
		goto err;

	/*
	 * Mount procfs under ./proc directory according to flags and options
	 * given in argument.
	 * Mountpoint permissions will be set to 0555 after mount completion.
	 */
	err = enbox_mount("proc", "proc", "proc", flags, opts);
	if (err)
		return err;

	/* Make procfs just mounted private and unbindable. */
	err = enbox_mount(NULL, "proc", NULL, MS_UNBINDABLE, NULL);
	if (err)
		goto err;

	return 0;

err:
	enbox_info("cannot mount proc filesystem: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

static int __enbox_nonull(1) __nothrow
enbox_mount_proc_entry(const struct enbox_entry * __restrict ent)
{
	return enbox_mount_proc(ent->mount.flags, ent->mount.opts);
}

#if defined(CONFIG_ENBOX_ASSERT)

static ssize_t __enbox_nonull(1, 2)
enbox_normalize_path(const char * __restrict path,
                     char ** __restrict      normalized)
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

static int __enbox_nonull(1)
enbox_validate_bind_mntpt(const char * __restrict path)
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

#define enbox_assert_bind_mntpt(_path) \
	enbox_assert(!enbox_validate_bind_mntpt(_path))

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert_bind_mntpt(_path)

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/*
 * Must be called as root from within an empty jail creation context only.
 */
static int __enbox_nonull(1, 2) __nothrow
enbox_bind_tree(const char * __restrict path,
                const char * __restrict orig,
                int                     flags,
                const char * __restrict opts)
{
	struct stat stat;
	int         err;

	enbox_assert(!enbox_get_uid());
	enbox_assert(!enbox_get_gid());
	enbox_assert(upath_validate_path_name(orig) > 0);
	enbox_assert_bind_mntpt(path);
	enbox_assert(!(flags & ~ENBOX_TREE_VALID_FLAGS));
	enbox_assert_mount_time_flags(flags);
	enbox_assert(!opts || *opts);

	/* Check that orig points to an existing directory. */
	err = upath_lstat(orig, &stat);
	if (err < 0)
		goto err;
	if (!S_ISDIR(stat.st_mode)) {
		err = -EPERM;
		goto err;
	}

	/*
	 * Create mountpoint.
	 * This will fail if it already exists since we are meant to bind mount
	 * from an initialy empty jail tmpfs.
	 */
	err = upath_mkdir(path, S_IRWXU);
	if (err)
		goto err;

	/* Perform the bind mount... */
	err = enbox_bind_mount(orig, path);
	if (err)
		goto err;

	if (flags) {
		/*
		 * ... and change mount properties if requested.
		 *
		 * To change the bind mount properties, we have to remount it
		 * with new flags in addition to MS_BIND.
		 *
		 * See also «Remounting an existing mount» section of mount(2)
		 * man page.
		 */
		err = enbox_remount(path, MS_BIND | flags, opts);
		if (err)
			goto err;
	}

	return 0;

err:
	enbox_info("'%s': cannot bind mount tree: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

static int __enbox_nonull(1) __nothrow
enbox_bind_tree_entry(const struct enbox_entry * __restrict ent)
{
	return enbox_bind_tree(ent->path,
	                       ent->bind.orig,
	                       ent->bind.flags,
	                       ent->bind.opts);
}

/*
 * Must be called as root from within an empty jail creation context only.
 */
static int __enbox_nonull(1, 2) __nothrow
enbox_bind_file(const char * __restrict path,
                const char * __restrict orig,
                int                     flags,
                const char * __restrict opts)
{
	struct stat stat;
	int         err;

	enbox_assert(!enbox_get_uid());
	enbox_assert(!enbox_get_gid());
	enbox_assert(upath_validate_path_name(orig) > 0);
	enbox_assert_bind_mntpt(path);
	enbox_assert(!(flags & ~ENBOX_FILE_VALID_FLAGS));
	enbox_assert_mount_time_flags(flags);
	
	err = upath_lstat(orig, &stat);
	if (err < 0)
		goto err;
	if (!S_ISREG(stat.st_mode)) {
		err = -EPERM;
		goto err;
	}

	/*
	 * Create an empty new file to provide the bind mount operation a
	 * "mount point"...
	 * Since we are going to call execve() or exit() after jail creation,
	 * use close-on-exec flag to prevent from calling an extra close().
	 */
	err = ufile_new(path,
	                O_WRONLY | O_EXCL | O_CLOEXEC | O_NOATIME | O_NOFOLLOW |
	                O_NONBLOCK,
	                S_IRUSR | S_IWUSR);
	if (err < 0)
		goto err;

	/* Perform the bind mount... */
	err = enbox_bind_mount(orig, path);
	if (err)
		goto err;

	if (flags) {
		/*
		 * ... and change mount properties if requested.
		 *
		 * To change the bind mount properties, we have to remount it
		 * with new flags in addition to MS_BIND.
		 *
		 * See also «Remounting an existing mount» section of mount(2)
		 * man page.
		 */
		err = enbox_remount(path, MS_BIND | flags, opts);
		if (err)
			goto err;
	}

	return 0;

err:
	enbox_info("'%s': cannot bind mount file: %s (%d)",
	           path,
	           strerror(-err),
	           -err);

	return err;
}

static int __enbox_nonull(1) __nothrow
enbox_bind_file_entry(const struct enbox_entry * __restrict ent)
{
	return enbox_bind_file(ent->path,
	                       ent->bind.orig,
	                       ent->bind.flags,
	                       ent->bind.opts);
}

static int __enbox_nonull(1) __nothrow
enbox_populate_jail(const struct enbox_entry entries[__restrict_arr],
                    unsigned int             nr)
{
	static enbox_make_entry_fn * const makers[ENBOX_ENTRY_TYPE_NR] = {
		[ENBOX_DIR_ENTRY_TYPE]   = enbox_make_dir_entry,
		[ENBOX_SLINK_ENTRY_TYPE] = enbox_make_slink_entry,
		[ENBOX_PROC_ENTRY_TYPE]  = enbox_mount_proc_entry,
		[ENBOX_TREE_ENTRY_TYPE]  = enbox_bind_tree_entry,
		[ENBOX_FILE_ENTRY_TYPE]  = enbox_bind_file_entry,
	};

	return enbox_make_entries(entries, nr, makers);
}

#define ENBOX_JAIL_ROOTFS_MNTOPTS \
	(MS_NOATIME | MS_NODEV | MS_NOSUID)

#define ENBOX_JAIL_ROOTFS_EXTOPTS \
	"uid=0,mode=0750,size=4k"

#define ENBOX_JAIL_ROOTFS_EXTOPTS_LEN \
	(sizeof(ENBOX_JAIL_ROOTFS_EXTOPTS) - 1 + \
	 1 + sizeof("gid=") - 1 + 5 + \
	 1 + sizeof("nr_inodes=") - 1 + 10)

static int __enbox_nonull(1) __nothrow
enbox_init_jail_root(const char * __restrict path,
                     gid_t                   gid,
                     unsigned int            inodes_nr,
                     char                    options[__restrict_arr])
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(options);

	int err;

	/* Create root mount point owned by root.root with 0700 permissions. */
	err = enbox_make_dir(path, 0, 0, S_IRWXU);
	if (err)
		return err;

	/*
	 * Make all currently mounted filesystems private so that filesystems
	 * mounted later on do not get propagated / shared with other mount
	 * namespaces.
	 */
	err = enbox_mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	if (err)
		return err;

	/*
	 * Make the mount point owned by root.<gid> with 0750 permissions.
	 * Give mount the maximum number of allowed inodes (+ 1 for the
	 * top-level root directory).
	 */
	snprintf(options,
	         ENBOX_JAIL_ROOTFS_EXTOPTS_LEN + 1,
	         ENBOX_JAIL_ROOTFS_EXTOPTS ",gid=%hu,nr_inodes=%u",
	         gid,
	         inodes_nr + 1);

	err = enbox_mount("root",
	                  path,
	                  "tmpfs",
	                  ENBOX_JAIL_ROOTFS_MNTOPTS,
	                  options);
	if (err)
		return err;

	/* Make root filesystem private and not bindable... */
	err = enbox_mount(NULL, path, NULL, MS_UNBINDABLE, NULL);
	if (err)
		return err;

	return 0;
}

static int
enbox_seal_jail_root(const char * __restrict path,
                     const char              options[__restrict_arr])
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(options);

	int err;

	/*
	 * We need to close every file descriptors opened onto root filesystem
	 * to be allowed to remount it with the right options.
	 */
	err = ufd_close_fds(STDERR_FILENO + 1, ~(0));
	if (err)
		return err;

	/* Remount root read-only with given options. */
	err = enbox_remount(path,
	                    MS_RDONLY | ENBOX_JAIL_ROOTFS_MNTOPTS,
	                    options);
	if (err)
		return err;

	return 0;
}

static int __enbox_nonull(1, 3) __nothrow
enbox_setup_jail(const char * __restrict  path,
                 gid_t                    gid,
                 const struct enbox_entry entries[__restrict_arr],
                 size_t                   nr)
{
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(entries);
	enbox_assert(nr);

	int          err;
	const char * msg;
	char         opts[ENBOX_JAIL_ROOTFS_EXTOPTS_LEN + 1];

	/* Mount future root filesystem. */
	err = enbox_init_jail_root(path, gid, nr, opts);
	if (err) {
		msg = "cannot mount jail root filesystem";
		goto err;
	}

	/* Change to future root filesystem top-level directory. */
	err = upath_chdir(path);
	enbox_assert(!err);

	/* Populate initial root filesystem entries. */
	err = enbox_populate_jail(entries, nr);
	if (err) {
		msg = "cannot populate jail root filesystem";
		goto err;
	}

	/* Remount future filesystem read-only. */
	err = enbox_seal_jail_root(path, opts);
	if (err) {
		msg = "cannot seal jail root filesystem";
		goto err;
	}

	return 0;

err:
	enbox_info("%s: %s (%d)", msg, strerror(-err), -err);

	return err;
}

static int __enbox_nonull(1, 2) __nothrow
enbox_pivot_root(const char * __restrict new_root,
                 const char * __restrict old_root)
{
	enbox_assert(upath_validate_path_name(new_root) > 0);
	enbox_assert(upath_validate_path_name(old_root) > 0);

	if (!syscall(__NR_pivot_root, new_root, old_root))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != ENAMETOOLONG);

	return -errno;
}

static int
enbox_chroot_jail_from_realfs(void)
{
	int err;

	/*
	 * Moves the root mount to the current working directory and make it the
	 * new root mount within current (mount) namespace.
	 *
	 * pivot_root() changes the root directory and the current working
	 * directory of each process or thread in the same mount namespace
	 * to the new root if they point to the old root directory. On the other
	 * hand, pivot_root() does not change the caller's current working
	 * directory (unless it is on the old root directory), and thus it
	 * should be followed by a chdir("/") call.
	 *
	 * See also «NOTES» section of pivot_root(2).
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
	return enbox_umount(".", MNT_DETACH);
}

/*
 * Chroot from an initramfs root device.
 *
 * Unlike the initrd, Linux does not allow to unmount the initramfs. Hence,
 * you can neither pivot_root(2) nor unmount(2) it.
 * Instead, overmount rootfs with the new root and chroot(2) into it.
 *
 * See Linux kernel documentation about switching an initramfs based root
 * filesystem to another root devices: head to section «What is initramfs» of
 * initramfs documentation located into file
 * <linux>/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt
 */
static int
enbox_chroot_jail_from_initramfs(void)
{
	int err;

	/* Overmount rootfs with the new root.*/
	err = enbox_mount(".", "/", NULL, MS_MOVE, NULL);
	if (err)
		return err;

	/* Chroot into it. */
	if (chroot(".")) {
		enbox_assert(errno != EFAULT);
		enbox_assert(errno != ENAMETOOLONG);
		enbox_assert(errno != EPERM);

		return -errno;
	}

	return 0;
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
enbox_chroot_jail(void)
{
	struct statfs stat;
	int           err;

	if (statfs("/", &stat)) {
		enbox_assert(errno != EFAULT);
		enbox_assert(errno != ENAMETOOLONG);

		return -errno;
	}

	if (stat.f_type != TMPFS_MAGIC)
		err = enbox_chroot_jail_from_realfs();
	else
		err = enbox_chroot_jail_from_initramfs();
	if (err)
		return err;

	/*
	 * Assert if current working directory is not "/" (see above comment
	 * related to pivot_root() and chroot().
	 */
	enbox_ensure_cwd_is_root();

	return 0;
}

static int __enbox_nonull(3, 4) __nothrow
enbox_enter_jail_bypwd(int                              namespaces,
                       gid_t                            gid,
                       const char * __restrict          path,
                       const struct enbox_entry         entries[__restrict_arr],
                       size_t                           nr)
{
	enbox_assert(!(namespaces & ~ENBOX_VALID_NAMESPACE_FLAGS));
	enbox_assert(gid != (gid_t)-1);
	enbox_assert(upath_validate_path_name(path) > 0);
	enbox_assert(entries);
	enbox_assert(nr);

	int          err;
	const char * msg;

	err = clearenv();
	if (err) {
		msg = "cannot clear environment";
		goto err;
	}

	err = enbox_lock_caps();
	if (err)
		return err;

	/*
	 * Clear bounding set capabilities.
	 * Effective, permitted, inheritable and ambient sets will be cleared at
	 * execve() time.
	 */
	err = enbox_clear_bounding_caps();
	if (err)
		return err;

	/*
	 * Dissociate from parent process namespaces.
	 *
	 * Note:
	 * - CLONE_FILES not needed since current file descriptor table is
	 *   duplicated at execve() time.
	 */
	err = enbox_unshare(namespaces | CLONE_FS | CLONE_SYSVSEM);
	if (err) {
		msg = "cannot dissociate from parent namespaces";
		goto err;
	}

	err = enbox_setup_jail(path, gid, entries, nr);
	if (err) {
		msg = "cannot setup jail filesystem";
		goto err;
	}

	/* Switch root filesystem to the new one created just above. */
	err = enbox_chroot_jail();
	if (err) {
		msg = "cannot chroot into jail";
		goto err;
	}

	return 0;

err:
	enbox_info("%s: %s (%d)", msg, strerror(-err), -err);

	return err;
}

int
enbox_enter_jail(const struct enbox_jail * __restrict jail,
                 const struct enbox_ids * __restrict  ids)
{
	enbox_assert_jail(jail);
	enbox_assert(ids);
	enbox_assert(ids->pwd);

	int err;

	err = enbox_enter_jail_bypwd(jail->namespaces,
	                             ids->pwd->pw_gid,
	                             jail->root_path,
	                             jail->fsset.entries,
	                             jail->fsset.nr);
	if (err) {
		enbox_err("cannot enter jail: %s (%d)",
		          strerror(-err),
		          -err);
		return err;
	}

	return 0;
}

int
enbox_load_ids_byid(struct enbox_ids * __restrict ids,
                    uid_t                         id,
                    bool                          drop_supp)
{
	enbox_assert(ids);

	const struct passwd * pwd;
	int                   err;

	pwd = upwd_get_user_byid(id);
	if (pwd) {
		ids->pwd = pwd;
		ids->drop_supp = drop_supp;
		return 0;
	}

	err = errno;

	enbox_assert(err > 0);
	switch (err) {
	case ERANGE:
		enbox_info("'%d': positive integer expected", id);
		break;
	case ENOENT:
		enbox_info("'%d': no such user", id);
		break;
	default:
		enbox_info("'%d': unexpected user ID: %s (%d)",
		           id,
		           strerror(err),
		           err);
	}

	return -err;
}

int
enbox_load_ids_byname(struct enbox_ids * __restrict ids,
                      const char * __restrict       user,
                      bool                          drop_supp)
{
	enbox_assert(ids);
	enbox_assert(user);

	const struct passwd * pwd;
	int                   err;

	pwd = upwd_get_user_byname(user);
	if (pwd) {
		ids->pwd = pwd;
		ids->drop_supp = drop_supp;
		return 0;
	}

	err = errno;

	enbox_assert(err > 0);
	switch (err) {
	case ENODATA:
		enbox_info("'%s': empty user name", user);
		break;
	case ENAMETOOLONG:
		enbox_info("'%s': user name too long", user);
		break;
	case ENOENT:
		enbox_info("'%s': no such user", user);
		break;
	default:
		enbox_info("'%s': unexpected user name: %s (%d)",
		           user,
		           strerror(err),
		           err);
	}

	return -err;
}

int
enbox_validate_exec_arg(const char * __restrict arg)
{
	enbox_assert(arg);

	size_t len;

#define ENBOX_EXEC_ARG_SIZE (1024U)
	len = strnlen(arg, ENBOX_EXEC_ARG_SIZE);
	if (!len)
		return -ENODATA;
	else if (len == ENBOX_EXEC_ARG_SIZE)
		return -ENAMETOOLONG;
	else
		return 0;
}

#if defined(CONFIG_ENBOX_ASSERT)

/*
 * TODO: Also check against ARG_MAX / MAX_ARG_STRLEN / MAX_ARG_STRINGS ?
 *       Watch out ! ARG_MAX depends onto RLIMIT_STACK rlimit (should use
 *       getconf() / sysconf() to retrieve its value)...
 */
int
enbox_validate_exec(const char * const args[__restrict_arr])
{
	enbox_assert(args);

	unsigned int cnt = 0;

	while (args[cnt]) {
		int err;

		if (cnt >= ENBOX_EXEC_ARGS_MAX)
			return -E2BIG;

		err = enbox_validate_exec_arg(args[cnt]);
		if (err)
			return err;

		cnt++;
	}

	return cnt ? 0 : -ENODATA;
}

#endif /* defined(CONFIG_ENBOX_ASSERT) */

int
enbox_run_cmd(const struct enbox_cmd * __restrict cmd,
              const struct enbox_ids * __restrict ids)
{
	enbox_assert(cmd);
	enbox_assert(!(cmd->umask & ~ALLPERMS));
	enbox_assert(!cmd->cwd ||
	             (upath_validate_path_name(cmd->cwd) > 0));
	enbox_assert(!enbox_validate_exec(cmd->exec));
	enbox_assert(ids);
	enbox_assert(ids->pwd);

	int err;

	enbox_umask = umask(cmd->umask);

	err = enbox_switch_ids(ids->pwd, ids->drop_supp);
	if (err)
		goto err;

	if (cmd->cwd) {
		err = upath_chdir(cmd->cwd);
		if (err) {
			enbox_info("cannot change to working directory: "
			           "%s (%d)",
			           strerror(-err),
			           -err);
			goto err;
		}
	}
	else
		enbox_ensure_cwd_is_root();

	execve(cmd->exec[0], (char * const *)cmd->exec, NULL);

	err = -errno;

err:
	enbox_err("cannot run command: %s (%d)", strerror(-err), -err);

	return err;
}

/******************************************************************************
 * Initialization API
 ******************************************************************************/

static mode_t
enbox_read_umask(void)
{
	mode_t msk;

	/*
	 * This is likely the most simple and efficient way to retrieve current
	 * process file mode creation mask value.
	 * On Linux, the only alternative I'm aware of involves parsing the
	 * `/proc/<pid>/status` file to retrieve the `Umask` field content.
	 */
	msk = umask(0);
	umask(msk);

	return msk;
}

int
enbox_setup(struct elog * __restrict logger)
{
	enbox_assert(logger);

	enbox_logger = logger;

	enbox_uid = geteuid();
	enbox_gid = getegid();
	enbox_umask = enbox_read_umask();

#if defined(CONFIG_ENBOX_DISABLE_DUMP)
	return enbox_setup_dump(ENBOX_DISABLE_DUMP);
#else  /* ! defined(CONFIG_ENBOX_DISABLE_DUMP) */
	return 0;
#endif /* defined(CONFIG_ENBOX_DISABLE_DUMP) */
}
