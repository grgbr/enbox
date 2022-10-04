/**
 * @file enbox.h
 * Enbox API interface.
 *
 */
#ifndef _ENBOX_H
#define _ENBOX_H

#include <enbox/config.h>
#include <utils/pwd.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>

/*
 * Depending on glibc version, this definition may be missing although handled
 * by kernel...
 */
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW (1UL << 8)
#endif

#if defined(CONFIG_ENBOX_ASSERT)

#include <utils/assert.h>

#define __enbox_nonull(_arg_index, ...)

#define enbox_assert(_expr) \
	uassert("enbox", _expr)

#define enbox_assert_setup() \
	enbox_assert(enbox_uid != (uid_t)-1); \
	enbox_assert(enbox_gid != (gid_t)-1); \
	enbox_assert(!(enbox_umask & ~ALLPERMS))

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define __enbox_nonull(_arg_index, ...) \
	__nonull(_arg_index, ## __VA_ARGS__)

#define enbox_assert(_expr)

#define enbox_assert_setup()

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/******************************************************************************
 * Raw API
 ******************************************************************************/

/**
 * @internal
 *
 * Current process file creation mode mask.
 *
 * @warning Do not reference this directly ! This is for internal use only. Use
 *          enbox_get_umask() and / or enbox_set_umask() instead.
 *
 * @see [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * @see enbox_get_umask()
 * @see enbox_set_umask()
 */
extern mode_t enbox_umask;

/**
 * @internal
 *
 * Current process user ID.
 *
 * @warning Do not reference this directly ! This is for internal use only. Use
 *          enbox_get_uid() instead.
 *
 * @see [getuid(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
 * @see [setuid(2)](https://man7.org/linux/man-pages/man2/setuid.2.html)
 * @see enbox_get_uid()
 */
extern uid_t enbox_uid;

/**
 * @internal
 *
 * Current process group ID.
 *
 * @warning Do not reference this directly ! This is for internal use only. Use
 *          enbox_get_gid() instead.
 *
 * @see [getgid(2)](https://man7.org/linux/man-pages/man2/getgid.2.html)
 * @see [setgid(2)](https://man7.org/linux/man-pages/man2/setgid.2.html)
 * @see enbox_get_gid()
 */
extern gid_t enbox_gid;

/**
 * Retreive current process file creation mode mask.
 *
 * @return file creation mode mask.
 *
 * @see [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * @see enbox_set_umask().
 */
static inline mode_t __nothrow __pure
enbox_get_umask(void)
{
	enbox_assert_setup();

	return enbox_umask;
}

/**
 * Modify current process file creation mode mask.
 *
 * @return file creation mode mask value prior to this function call.
 *
 * @see [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * @see enbox_get_umask()
 */
static inline mode_t __nothrow
enbox_set_umask(mode_t mask)
{
	enbox_assert_setup();

	mode_t old;

	old = umask(mask);
	enbox_assert(old == enbox_umask);

	enbox_umask = mask;

	return old;
}

/**
 * Retreive current process user ID.
 *
 * @return user ID.
 *
 * @see [getuid(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
 * @see [geteuid(2)](https://man7.org/linux/man-pages/man2/geteuid.2.html)
 * @see enbox_get_gid().
 */
static inline uid_t __nothrow __pure
enbox_get_uid(void)
{
	enbox_assert_setup();

	return enbox_uid;
}

/**
 * Retreive current process group ID.
 *
 * @return group ID.
 *
 * @see [getgid(2)](https://man7.org/linux/man-pages/man2/getgid.2.html)
 * @see [getegid(2)](https://man7.org/linux/man-pages/man2/getegid.2.html)
 * @see enbox_get_uid().
 */
static inline gid_t __nothrow __pure
enbox_get_gid(void)
{
	enbox_assert_setup();

	return enbox_gid;
}

/**
 * Keep filesystem entry owner UID unchanged.
 *
 * @see enbox_change_perms()
 */
#define ENBOX_KEEP_UID  ((uid_t)-1)

/**
 * Keep filesystem entry group GID unchanged.
 *
 * @see enbox_change_perms()
 */
#define ENBOX_KEEP_GID  ((gid_t)-1)

/**
 * Keep filesystem entry permissions unchanged.
 *
 * @see enbox_change_perms()
 */
#define ENBOX_KEEP_MODE ((mode_t)-1)

/**
 * Change ownership, group membership and permissions of a filesystem entry.
 *
 * Basically calls [chown(2)] then [chmod(2)] onto filesystem entry pointed to
 * by @p path.
 * Ownership is modified according to user ID @p uid or left untouched in case
 * @p uid equals #ENBOX_KEEP_UID.
 * Group membership is modified according to group ID @p gid passed in argument
 * or left untouched in case @p gid equals #ENBOX_KEEP_GID.
 * Permissions are modified according to @p mode passed in argument or left
 * untouched in case @p mode equals #ENBOX_KEEP_MODE.
 *
 * @param[in] path Pathname to filesystem entry to modify
 * @param[in] uid  Owner UID
 * @param[in] gid  Group GID
 * @param[in] mode Filesystem permissions
 *
 * @return An errno-like error code.
 *
 * @see #ENBOX_KEEP_UID
 * @see #ENBOX_KEEP_GID
 * @see #ENBOX_KEEP_MODE
 * @see [chown(2)]
 * @see [chmod(2)]
 *
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 */
extern int
enbox_change_perms(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

/**
 * Ensure a filesystem directory is properly created.
 *
 * Basically calls [mkdir(2)] to create a directory pointed to by @p path
 * according to @p uid user ID, @p gid group ID and @p mode permissions.
 * In case the directory already existed, ensure it is consistent with @p uid
 * user ID, @p gid group ID and @p mode permissions passed in arguments.
 *
 * Should an error occur:
 * - an entry existing (and matching @p path pathname) prior to this call will
 *   be left in an unpredicted state ;
 * - otherwise, the new directory will be deleted using [rmdir(2)] before
 *   returning to the caller.
 *
 * @param[in] path Pathname to filesystem directory
 * @param[in] uid  Directory owner UID
 * @param[in] gid  Directory group GID
 * @param[in] mode Directory permissions
 *
 * @return An errno-like error code.
 *
 * @see [mkdir(2)]
 * @see [chown(2)]
 * @see [chmod(2)]
 * @see [rmdir(2)]
 *
 * [mkdir(2)]: https://man7.org/linux/man-pages/man2/mkdir.2.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [rmdir(2)]: https://man7.org/linux/man-pages/man2/rmdir.2.html
 */
extern int
enbox_make_dir(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_slink(const char * __restrict path,
                 const char * __restrict target,
                 uid_t                   uid,
                 gid_t                   gid)
	__enbox_nonull(1, 2) __nothrow;

extern int
enbox_make_chrdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_blkdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_fifo(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

extern int
enbox_drop_ambient_caps(void) __nothrow;

extern int
enbox_drop_bounding_caps(void) __nothrow;

extern int
enbox_lock_caps(void) __nothrow;

/**
 * Enable process *dumpable* attribute.
 *
 * @see enbox_setup_dump()
 */
#define ENBOX_ENABLE_DUMP  (1)
/**
 * Disable process *dumpable* attribute.
 *
 * @see enbox_setup_dump()
 */
#define ENBOX_DISABLE_DUMP (0)

/**
 * Setup current process *dumpable* attribute.
 *
 * Enable or disable generation of coredumps for current process.
 * In addition, attaching to the process via [ptrace(2)] PTRACE_ATTACH is
 * restricted according to multiple logics introduced below.
 *
 * As stated into section «PR_SET_DUMPABLE» of [prctl(2)], the *dumpable*
 * attribute is normally set to 1. However, it is reset to the current value
 * contained in the file `/proc/sys/fs/suid_dumpable` (which defaults to value
 * 0), in the following circumstances:
 * - current process EUID or EGID is changed ;
 * - current process FSUID or FSGID is changed ;
 * - current process [execve(2)] a SUID / SGID program incurring a EUID / EGID
 *   change ;
 * - current process [execve(2)] a program that has file capabilities exceeding
 *   those already permitted.
 * The `/proc/sys/fs/suid_dumpable` file is documented into [proc(5)].
 *
 *
 * As stated in [ptrace(2)], Linux kernel performs so-called "ptrace access
 * mode" checks whose outcome determines whether [ptrace(2)] operations are
 * permitted in addition to `CAP_SYS_PTRACE` capability and Linux Security
 * Module ptrace access checks.
 * See section «Ptrace access mode checking» of [ptrace(2)] for more
 * informations.
 *
 * Finally, the [Yama] Linux Security Module may further restrict [ptrace(2)]
 * operations thanks to the runtime controllable sysctl `/proc/sys/kernel/yama`.
 * See «PR_SET_PTRACER» section in [prctl(2)] and [Yama] section in
 * [The Linux kernel user’s and administrator’s guide].
 *
 * @param[in] on Enable coredumps generation if `true`, disable it otherwise.
 *
 * @see #ENBOX_ENABLE_DUMP
 * @see #ENBOX_DISABLE_DUMP
 * @see enbox_setup()
 *
 * [The Linux kernel user’s and administrator’s guide]: https://www.kernel.org/doc/html/latest/admin-guide/index.html
 * [Yama]:                                              https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
 * [execve(2)]:                                         https://man7.org/linux/man-pages/man2/execve.2.html
 * [prctl(2)]:                                          https://man7.org/linux/man-pages/man2/prctl.2.html
 * [proc(5)]:                                           https://man7.org/linux/man-pages/man5/proc.5.html
 * [ptrace(2)]:                                         https://man7.org/linux/man-pages/man2/ptrace.2.html
 */
static inline void __nothrow
enbox_setup_dump(bool on)
{
	enbox_assert_setup();

	int err;

	err = prctl(PR_SET_DUMPABLE, (int)on, 0, 0, 0);
	enbox_assert(!err);
}

#define ENBOX_KEEP_SUPP_GROUPS (false)
#define ENBOX_DROP_SUPP_GROUPS (true)

extern int
enbox_change_ids(const char * __restrict user, bool drop_supp)
	__enbox_nonull(1);

/******************************************************************************
 * High-level API
 ******************************************************************************/

enum enbox_entry_type {
	ENBOX_DIR_ENTRY_TYPE = 0,
	ENBOX_SLINK_ENTRY_TYPE,
	ENBOX_CHRDEV_ENTRY_TYPE,
	ENBOX_BLKDEV_ENTRY_TYPE,
	ENBOX_FIFO_ENTRY_TYPE,
	ENBOX_PROC_ENTRY_TYPE,
	ENBOX_TREE_ENTRY_TYPE,
	ENBOX_FILE_ENTRY_TYPE,
	ENBOX_ENTRY_TYPE_NR
};

struct enbox_dir_entry {
	mode_t mode;
};

struct enbox_slink_entry {
	const char * target;
};

struct enbox_dev_entry {
	mode_t       mode;
	unsigned int major;
	unsigned int minor;
};

struct enbox_fifo_entry {
	mode_t mode;
};

struct enbox_mount_entry {
	unsigned long flags;
	const char *  opts;
};

struct enbox_bind_entry {
	const char *  orig;
	unsigned long flags;
	const char *  opts;
};

struct enbox_entry {
	const char *                     path;
	enum enbox_entry_type            type;
	uid_t                            uid;
	gid_t                            gid;
	union {
		struct enbox_dir_entry   dir;
		struct enbox_slink_entry slink;
		struct enbox_dev_entry   dev;
		struct enbox_fifo_entry  fifo;
		struct enbox_mount_entry mount;
		struct enbox_bind_entry  bind;
	};
};

struct enbox_fsset {
	unsigned int               nr;
	const struct enbox_entry * entries;
};

extern int
enbox_populate_host(const struct enbox_fsset * __restrict host)
	__enbox_nonull(1);

#define ENBOX_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

struct enbox_ids {
	const struct passwd * pwd;
	bool                  drop_supp;
};

extern int
enbox_load_ids_byid(struct enbox_ids * __restrict ids,
                    uid_t                         id,
                    bool                          drop_supp)
	__enbox_nonull(1);

extern int
enbox_load_ids_byname(struct enbox_ids * __restrict ids,
                      const char * __restrict       user,
                      bool                          drop_supp)
	__enbox_nonull(1, 2);

struct enbox_jail {
	int                namespaces;
	const char *       root_path;
	struct enbox_fsset fsset;
};

extern int
enbox_enter_jail(const struct enbox_jail * __restrict jail,
                 const struct enbox_ids * __restrict  ids)
	__enbox_nonull(1, 2) __nothrow;

struct enbox_cmd {
	mode_t               umask;
	const char *         cwd;
	const char * const * exec;
};

extern int
enbox_run_cmd(const struct enbox_cmd * __restrict exec,
              const struct enbox_ids * __restrict ids)
	__enbox_nonull(1, 2) __nothrow;

/******************************************************************************
 * Configuration API
 ******************************************************************************/

struct enbox_conf;

extern int
enbox_run_conf(const struct enbox_conf * __restrict conf) __enbox_nonull(1);

extern struct enbox_conf *
enbox_create_conf_from_file(const char * __restrict path) __enbox_nonull(1);

void
enbox_destroy_conf(struct enbox_conf * __restrict conf) __enbox_nonull(1);

/******************************************************************************
 * Initialization API
 ******************************************************************************/

struct elog;

/**
 * Initialize Enbox library.
 *
 * May alter calling process *dumpable* attribute according to
 * #CONFIG_ENBOX_DISABLE_DUMP build option.
 *
 * @param[inout] logger an initialized Elog logger instance.
 *
 * @see enbox_setup_dump()
 */
extern void
enbox_setup(struct elog * __restrict logger)
	__enbox_nonull(1) __nothrow;

#endif /* _ENBOX_H */
