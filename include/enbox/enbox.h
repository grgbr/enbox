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
 *
 * Permissions are either left untouched in case @p mode equals
 * #ENBOX_KEEP_MODE, or modified according to @p mode passed in argument. In the
 * latter case, @p mode MUST fit within the bitmask defined by the octal value
 * `07777`.
 *
 * @param[in] path Pathname to filesystem entry to modify
 * @param[in] uid  Owner UID
 * @param[in] gid  Group GID
 * @param[in] mode Filesystem permissions
 *
 * @return 0 if successful, an errno-like error code otherwise.
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
 * In case the directory already exists, ensure it is consistent with @p uid
 * user ID, @p gid group ID and @p mode permissions passed in arguments.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a directory will be left untouched ;
 * - a directory matching @p path pathname existing prior to this call will be
 *   left in an unpredictable state ;
 * - otherwise, the new directory just created will be deleted using [rmdir(2)]
 *   before returning to the caller.
 *
 * @param[in] path Pathname to filesystem directory
 * @param[in] uid  Directory owner UID
 * @param[in] gid  Directory group GID
 * @param[in] mode Directory permissions
 *
 * @return 0 if successful, an errno-like error code otherwise.
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

/**
 * Ensure a filesystem symbolic link is properly created.
 *
 * Basically calls [symlink(2)] to create a symbolic link @p path targeting @p
 * target according to @p uid user ID and @p gid group ID.
 * In case the symbolic link already exists, ensure it is consistent with @p
 * uid user ID, @p gid group ID and @p target passed in arguments.
 *
 * @p mode MUST fit within the bitmask defined by the octal value `07777`.
 *
 * @note Permissions of symbolic links are irrelevant.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a symbolic link will be left untouched ;
 * - a symbolic link existing and matching @p path pathname prior to this call
 *   will be left in an unpredictable state ;
 * - otherwise, the new symbolic link will be deleted using [unlink(2)] before
 *   returning to the caller.
 *
 * @param[in] path   Pathname to filesystem symbolic link
 * @param[in] target Target pathname which @p path will point to
 * @param[in] uid    Symbolic link owner UID
 * @param[in] gid    Symbolic link group GID
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see [symlink(2)]
 * @see [readlink(2)]
 * @see [chown(2)]
 * @see [unlink(2)]
 *
 * [symlink(2)]: https://man7.org/linux/man-pages/man2/symlink.2.html
 * [readlink(2)]: https://man7.org/linux/man-pages/man2/readlink.2.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [unlink(2)]: https://man7.org/linux/man-pages/man2/unlink.2.html
 */
extern int
enbox_make_slink(const char * __restrict path,
                 const char * __restrict target,
                 uid_t                   uid,
                 gid_t                   gid)
	__enbox_nonull(1, 2) __nothrow;

/**
 * Ensure a filesystem character devide node is properly created.
 *
 * Basically calls [mknod(2)] to create a character device node pointed to by
 * @p path according to @p uid user ID, @p gid group ID, @p mode permissions,
 * @p major and @p minor numbers.
 * In case the character device node already exists, ensure it is consistent
 * with @p uid user ID, @p gid group ID, @p mode permissions, @p major and @p
 * minor numbers passed in arguments.
 *
 * @p mode MUST fit within the bitmask defined by the octal value `0666`.
 * @p major MUST be `> 0`.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a character device node will be left untouched ;
 * - a character device node existing and matching @p path pathname prior to
 *   this call will be left in an unpredictable state ;
 * - otherwise, the new character device node will be deleted using [unlink(2)]
 *   before returning to the caller.
 *
 * @param[in] path   Pathname to filesystem device node
 * @param[in] uid    Device node owner UID
 * @param[in] gid    Device node group GID
 * @param[in] mode   Device node permissions
 * @param[in] major  Device node major number
 * @param[in] minor  Device node minor number
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see [mknod(2)]
 * @see [makedev(3)]
 * @see [chown(2)]
 * @see [chmod(2)]
 * @see [unlink(2)]
 *
 * [mknod(2)]: https://man7.org/linux/man-pages/man2/mknod.2.html
 * [makedev(3)]: https://man7.org/linux/man-pages/man3/makedev.3.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [unlink(2)]: https://man7.org/linux/man-pages/man2/unlink.2.html
 */
extern int
enbox_make_chrdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

/**
 * Ensure a filesystem block devide node is properly created.
 *
 * Basically calls [mknod(2)] to create a block device node pointed to by
 * @p path according to @p uid user ID, @p gid group ID, @p mode permissions,
 * @p major and @p minor numbers.
 * In case the block device node already exists, ensure it is consistent
 * with @p uid user ID, @p gid group ID, @p mode permissions, @p major and @p
 * minor numbers passed in arguments.
 *
 * @p mode MUST fit within the bitmask defined by the octal value `0666`.
 * @p major MUST be `> 0`.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a block device node will be left untouched ;
 * - a block device node existing and matching @p path pathname prior to this
 *   call will be left in an unpredictable state ;
 * - otherwise, the new block device node will be deleted using [unlink(2)]
 *   before returning to the caller.
 *
 * @param[in] path   Pathname to filesystem device node
 * @param[in] uid    Device node owner UID
 * @param[in] gid    Device node group GID
 * @param[in] mode   Device node permissions
 * @param[in] major  Device node major number
 * @param[in] minor  Device node minor number
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see [mknod(2)]
 * @see [makedev(3)]
 * @see [chown(2)]
 * @see [chmod(2)]
 * @see [unlink(2)]
 *
 * [mknod(2)]: https://man7.org/linux/man-pages/man2/mknod.2.html
 * [makedev(3)]: https://man7.org/linux/man-pages/man3/makedev.3.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [unlink(2)]: https://man7.org/linux/man-pages/man2/unlink.2.html
 */
extern int
enbox_make_blkdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

/**
 * Ensure a filesystem named pipe is properly created.
 *
 * Basically calls [mkfifo(3)] to create a named pipe (FIFO) pointed to by
 * @p path according to @p uid user ID, @p gid group ID and @p mode permissions.
 * In case the named pipe already exists, ensure it is consistent
 * with @p uid user ID, @p gid group ID and @p mode permissions passed in
 * arguments.
 *
 * @p mode MUST fit within the bitmask defined by the octal value `0666`.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a named pipe will be left untouched ;
 * - a named pipe existing and matching @p path pathname prior to this call will
 *   be left in an unpredictable state ;
 * - otherwise, the new named pipe will be deleted using [unlink(2)] before
 *   returning to the caller.
 *
 * @param[in] path   Pathname to filesystem named pipe
 * @param[in] uid    Named pipe owner UID
 * @param[in] gid    Named pipe group GID
 * @param[in] mode   Named pipe permissions
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see [mkfifo(3)]
 * @see [pipe(7)]
 * @see [chown(2)]
 * @see [chmod(2)]
 * @see [unlink(2)]
 *
 * [mkfifo(3)]: https://man7.org/linux/man-pages/man3/mkfifo.3.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [unlink(2)]: https://man7.org/linux/man-pages/man2/unlink.2.html
 * [pipe(7)]: https://man7.org/linux/man-pages/man7/pipe.7.html
 */
extern int
enbox_make_fifo(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

/**
 * Clear ambient capability set.
 *
 * Remove all capabilities from current thread's ambient set.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of [capabilities(7)].
 *
 * @warning Requires CAP_SETPCAP capability.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see sections `Thread capability sets` and `CAP_SETPCAP` of [capabilities(7)]
 * @see section `PR_CAP_AMBIENT_CLEAR_ALL` of [prctl(2)]
 *
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [prctl(2)]:        https://man7.org/linux/man-pages/man2/prctl.2.html
 */
extern int
enbox_clear_ambient_caps(void) __nothrow;

/**
 * Clear bounding capability set.
 *
 * Remove all capabilities from current thread's bounding set.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of [capabilities(7)].
 *
 * @warning Requires CAP_SETPCAP capability.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see sections `Thread capability sets` and `CAP_SETPCAP` of [capabilities(7)]
 * @see section `PR_CAPBSET_DROP` of [prctl(2)]
 *
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [prctl(2)]:        https://man7.org/linux/man-pages/man2/prctl.2.html
 */
extern int
enbox_clear_bounding_caps(void) __nothrow;

/**
 * Lock capability sets.
 *
 * This will basically setup the following Linux kernel's security and
 * capability related features:
 * - set the [no_new_privs] attribute to 1, instructing next [execve(2)] call
 *   not to grant privileges to do anything that could not have been done
 *   without the [execve(2)] call ;
 * - set the `SECBIT_NOROOT` securebits flag to 1 to disable the granting of
 *   capabilities when a SUID root program is executed or when a process with an
 *   effective or real UID of 0 calls [execve(2)] ;
 * - set the `SECBIT_NO_CAP_AMBIENT_RAISE` securebits flag to 1 to disallow
 *   raising ambient capabilities ;
 * - clear all other available securebits flags ;
 * - lock all securebits flags in an irreversible manner.
 *
 * @warning Requires CAP_SETPCAP capability.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see sections `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECUREBITS` of [prctl(2)]
 * @see sections `Thread capability sets` and `The securebits flags` of
 *      [capabilities(7)]
 *
 * [no_new_privs]:    https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html
 * [execve(2)]:       https://man7.org/linux/man-pages/man2/execve.2.html
 * [prctl(2)]:        https://man7.org/linux/man-pages/man2/prctl.2.html
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 */
extern int
enbox_lock_caps(void) __nothrow;

/**
 * Request to setup current process's list of supplementary group IDs.
 *
 * @see enbox_change_ids()
 */
#define ENBOX_RAISE_SUPP_GROUPS (false)

/**
 * Request to clear current process's list of supplementary group IDs.
 *
 * @see enbox_change_ids()
 */
#define ENBOX_DROP_SUPP_GROUPS (true)

/**
 * Switch to user / group IDs.
 *
 * Change current process's real, effective and saved user ID to UID matching
 * @p user user name passed in argument.
 *
 * In addition, change current process's real, effective and saved group ID to
 * primary GID of @p user.
 *
 * Finally, setup current process's list of supplementary group IDs according
 * to the following :
 * - when @p drop_supp argument equals #ENBOX_RAISE_SUPP_GROUPS, setup
 *   supplementary group IDs from system group database in addition to primary
 *   group ID,
 * - when @p drop_supp argument equals #ENBOX_DROP_SUPP_GROUPS, clear
 *   supplementary group list.
 *
 * @warning Requires CAP_SETUID capability.
 *
 * @param[in] user      Name of user which UID to change to
 * @param[in] drop_supp Load or clear supplementary groups list (see
 *                      #ENBOX_RAISE_SUPP_GROUPS and #ENBOX_DROP_SUPP_GROUPS)
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see #ENBOX_RAISE_SUPP_GROUPS
 * @see #ENBOX_DROP_SUPP_GROUPS
 * @see [setresuid(2)]
 * @see [initgroups(3)]
 * @see [setgroups(2)]
 *
 * [setresuid(2)]:  https://man7.org/linux/man-pages/man2/setresuid.2.html
 * [initgroups(3)]: https://man7.org/linux/man-pages/man3/initgroups.3.html
 * [setgroups(2)]:  https://man7.org/linux/man-pages/man2/setgroups.2.html
 */
extern int
enbox_change_ids(const char * __restrict user, bool drop_supp)
	__enbox_nonull(1);

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
 * @return 0 if successful, an errno-like error code otherwise.
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
extern int
enbox_setup_dump(bool on) __nothrow;

/******************************************************************************
 * High-level API
 ******************************************************************************/

/**
 * File system entry type identifier.
 *
 * Identifies types of filesystem entries that Enbox may create when populating
 * jail and / or host filesystems.
 */
enum enbox_entry_type {
	/** Directory entry. @see enbox_dir_entry */
	ENBOX_DIR_ENTRY_TYPE = 0,
	/** Symbolic link entry. @see enbox_slink_entry */
	ENBOX_SLINK_ENTRY_TYPE,
	/** Character device node entry. @see enbox_dev_entry */
	ENBOX_CHRDEV_ENTRY_TYPE,
	/** Block device node entry. @see enbox_dev_entry */
	ENBOX_BLKDEV_ENTRY_TYPE,
	/** Named pipe entry. @see enbox_fifo_entry */
	ENBOX_FIFO_ENTRY_TYPE,
	/** `/proc` mount point entry. @see enbox_mount_entry */
	ENBOX_PROC_ENTRY_TYPE,
	/** (sub-)tree bind mount point entry. @see enbox_bind_entry */
	ENBOX_TREE_ENTRY_TYPE,
	/** File bind mount point entry. @see enbox_bind_entry */
	ENBOX_FILE_ENTRY_TYPE,
	/** Number of entry types. */
	ENBOX_ENTRY_TYPE_NR
};

/**
 * Directory entry descriptor.
 *
 * Depicts how to create a directory entry when :
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_DIR_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_enter_jail() to create a directory entry.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_DIR_ENTRY_TYPE
 * @see #enbox_entry
 * @see enbox_populate_host()
 * @see enbox_enter_jail()
 * @see enbox_make_dir()
 * @see section «The file type and mode» of [inode(7)]
 *
 * [inode(7)]: https://man7.org/linux/man-pages/man7/inode.7.html
 */
struct enbox_dir_entry {
	/** Mode, i.e., permission bits for the directory. */
	mode_t mode;
};

/**
 * Symbolic link entry descriptor.
 *
 * Depicts how to create a symbolic link entry when :
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_SLINK_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_enter_jail() to create a symbolic link entry.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_SLINK_ENTRY_TYPE
 * @see #enbox_entry
 * @see enbox_populate_host()
 * @see enbox_enter_jail()
 * @see enbox_make_slink()
 */
struct enbox_slink_entry {
	/** Symbolic link target, i.e., pathname this symlink will point to. */
	const char * target;
};

/**
 * Device node entry descriptor.
 *
 * Depicts how to create a device node entry (wether character or block) when :
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_CHRDEV_ENTRY_TYPE or #ENBOX_BLKDEV_ENTRY_TYPE identifiers to instruct
 * enbox_populate_host() and / or enbox_enter_jail() to create a character
 * or a block device node entry respectively.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_CHRDEV_ENTRY_TYPE
 * @see #ENBOX_BLKDEV_ENTRY_TYPE
 * @see #enbox_entry
 * @see enbox_populate_host()
 * @see enbox_enter_jail()
 * @see enbox_make_chrdev()
 * @see enbox_make_blkdev()
 * @see [makedev(3)]
 *
 * [makedev(3)]: https://man7.org/linux/man-pages/man3/makedev.3.html
 */
struct enbox_dev_entry {
	/**
	 * Mode, i.e., permission bits for the device node.
	 * MUST fit within the bitmask defined by the octal value `0666`.
	 */
	mode_t       mode;
	/** Device node major number. */
	unsigned int major;
	/** Device node minor number. */
	unsigned int minor;
};

/**
 * FIFO, i.e., (filesystem backed) named pipe, entry descriptor.
 *
 * Depicts how to create a named pipe entry when :
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_FIFO_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_enter_jail() to create a named pipe entry.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_FIFO_ENTRY_TYPE
 * @see #enbox_entry
 * @see enbox_populate_host()
 * @see enbox_enter_jail()
 * @see enbox_make_fifo()
 * @see [pipe(7)]
 *
 * [pipe(7)]: https://man7.org/linux/man-pages/man7/pipe.7.html
 */
struct enbox_fifo_entry {
	/**
	 * Mode, i.e., permission bits for the named pipe.
	 * MUST fit within the bitmask defined by the octal value `0666`.
	 */
	mode_t mode;
};

/**
 * Mount entry descriptor.
 *
 * Depicts how to initially mount a filesystem when populating jail
 * filesystem using enbox_enter_jail().
 *
 * The filesystem will be mounted from within the jail's own mount namespace
 * using unbindable propagation properties (see «SHARED SUBTREE» section of
 * [mount_namespaces(7)]).
 * Mount point directory will be implicitly created if not existing with
 * permissions, ownership and membership inherited from the original filesystem
 * root directory.
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_PROC_ENTRY_TYPE identifier to instruct enbox_enter_jail() to create a
 * mount entry.
 *
 * @warning Do not use if you want to bind mount a filesystem, use
 *          #enbox_bind_entry instead.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_PROC_ENTRY_TYPE
 * @see #enbox_entry
 * @see #enbox_bind_entry
 * @see enbox_enter_jail()
 * @see [mount(2)]
 * @see [mount_namespaces(7)]
 *
 * [mount(2)]: https://man7.org/linux/man-pages/man2/mount.2.html
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
struct enbox_mount_entry {
	/**
	 * Mounting flags passed as 4th argument to [mount(2)]
	 * (https://man7.org/linux/man-pages/man2/mount.2.html) when mounting
	 * filesystem.
	 *
	 * The set of supported mounting flags is listed below. Any other flags
	 * will generate unpredictable behavior :
	 * - `MS_DIRSYNC`
	 * - `MS_MANDLOCK`
	 * - `MS_NODEV`
	 * - `MS_NOEXEC`
	 * - `MS_NOSUID`
	 * - `MS_RDONLY`
	 * - `MS_SILENT`
	 * - `MS_SYNCHRONOUS`
	 * - `MS_NOSYMFOLLOW`
	 * - `MS_LAZYTIME`
	 * - `MS_NOATIME`
	 * - `MS_RELATIME`
	 * - `MS_STRICTATIME`
	 * - `MS_NODIRATIME`
	 */
	unsigned long flags;
	/**
	 * Mounting options passed as 5th argument to
	 * [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html) when
	 * mounting filesystem.
	 *
	 * This is a string of comma-separated options specific to the type of
	 * mounted filesystem.
	 */
	const char *  opts;
};

/**
 * Bind mount entry descriptor.
 *
 * Depicts how to bind mount a file or a filesystem (sub-)tree when populating
 * jail filesystem using enbox_enter_jail(). See «Creating a bind mount» section
 * of [mount(2)] for more informations about what a bind mount is.
 *
 * The bind mount will be performed from within the jail's own mount namespace
 * using unbindable propagation properties (see «SHARED SUBTREE» section of
 * [mount_namespaces(7)]).
 * Mount point directory will be implicitly created if not existing with
 * permissions, ownership and membership inherited from the source filesystem
 * mount point entry.
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_FILE_ENTRY_TYPE or #ENBOX_TREE_ENTRY_TYPE identifiers to instruct
 * enbox_enter_jail() to create file or (sub-)tree bind mount mount entry
 * respectively.
 *
 * @warning Do not use if you want to initially mount a filesystem, use
 *          #enbox_mount_entry instead.
 *
 * @see #enbox_entry_type
 * @see #ENBOX_FILE_ENTRY_TYPE
 * @see #ENBOX_TREE_ENTRY_TYPE
 * @see #enbox_entry
 * @see #enbox_bind_entry
 * @see enbox_enter_jail()
 * @see [mount(2)]
 * @see [mount_namespaces(7)]
 *
 * [mount(2)]: https://man7.org/linux/man-pages/man2/mount.2.html
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
struct enbox_bind_entry {
	/** Pathname to source filesystem entry to bind mount. */
	const char *  orig;
	/**
	 * Mounting flags passed as 4th argument to [mount(2)]
	 * (https://man7.org/linux/man-pages/man2/mount.2.html) when bind
	 * mounting a file or a filesystem (sub-)tree.
	 *
	 * The set of supported mounting flags to bind mount a source file using
	 * #ENBOX_FILE_ENTRY_TYPE is show below. Any other flags will generate
	 * unpredictable behavior :
	 * - `MS_MANDLOCK`
	 * - `MS_NODEV`
	 * - `MS_NOEXEC`
	 * - `MS_NOSUID`
	 * - `MS_RDONLY`
	 * - `MS_SILENT`
	 * - `MS_SYNCHRONOUS`
	 * - `MS_NOSYMFOLLOW`
	 * - `MS_LAZYTIME`
	 * - `MS_NOATIME`
	 * - `MS_RELATIME`
	 * - `MS_STRICTATIME`
	 *
	 * The set of supported mounting flags to bind mount a source filesystem
	 * tree using #ENBOX_TREE_ENTRY_TYPE is show below. Any other flags will
	 * generate unpredictable behavior :
	 * - `MS_DIRSYNC`
	 * - `MS_MANDLOCK`
	 * - `MS_NODEV`
	 * - `MS_NOEXEC`
	 * - `MS_NOSUID`
	 * - `MS_RDONLY`
	 * - `MS_SILENT`
	 * - `MS_SYNCHRONOUS`
	 * - `MS_NOSYMFOLLOW`
	 * - `MS_LAZYTIME`
	 * - `MS_NOATIME`
	 * - `MS_RELATIME`
	 * - `MS_STRICTATIME`
	 * - `MS_NODIRATIME`
	 */
	unsigned long flags;
	/**
	 * Mounting options passed as 5th argument to
	 * [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html) when
	 * bind mounting a file or a filesystem (sub-)tree.
	 *
	 * This is a string of comma-separated options specific to the type of
	 * the mounted source filesystem.
	 */
	const char *  opts;
};

/**
 * Filesystem entry descriptor.
 *
 * This depicts how to ensure the filesystem entry identified by @p path is
 * properly created when:
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of [mount_namespaces(7)]).
 *
 * @see enbox_populate_host()
 * @see enbox_enter_jail()
 * @see [mount_namespaces(7)]
 *
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
struct enbox_entry {
	/**
	 * Pathname to entry.
	 *
	 * Enbox uses this field as the entry's primary identifier.
	 */
	const char *                     path;
	/** Type of entry. */
	enum enbox_entry_type            type;
	/** UID of entry owner. */
	uid_t                            uid;
	/** GID of entry group. */
	gid_t                            gid;
	/** Per entry type specific settings. */
	union {
		/**
		 * Directory entry specific settings.
		 *
		 * @see #ENBOX_DIR_ENTRY_TYPE
		 */
		struct enbox_dir_entry   dir;
		/**
		 * Symbolic link entry specific settings.
		 *
		 * @see #ENBOX_SLINK_ENTRY_TYPE
		 */
		struct enbox_slink_entry slink;
		/**
		 * Device node entry specific settings.
		 *
		 * @see #ENBOX_CHRDEV_ENTRY_TYPE
		 * @see #ENBOX_BLKDEV_ENTRY_TYPE
		 */
		struct enbox_dev_entry   dev;
		/**
		 * FIFO, i.e., named pipe entry specific settings.
		 *
		 * @see #ENBOX_FILE_ENTRY_TYPE
		 */
		struct enbox_fifo_entry  fifo;
		/**
		 * Initial mount point entry specific settings.
		 *
		 * @see #ENBOX_PROC_ENTRY_TYPE
		 */
		struct enbox_mount_entry mount;
		/**
		 * Bind mount point entry specific settings.
		 *
		 * @see #ENBOX_FILE_ENTRY_TYPE
		 * @see #ENBOX_TREE_ENTRY_TYPE
		 */
		struct enbox_bind_entry  bind;
	};
};

/**
 * Document me !!
 */
struct enbox_fsset {
	unsigned int               nr;
	const struct enbox_entry * entries;
};

/**
 * Document me !!
 */
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

/**
 * Document me!
 */
struct enbox_jail {
	int                namespaces;
	const char *       root_path;
	struct enbox_fsset fsset;
};

/**
 * Document me !!
 */
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
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see enbox_setup_dump()
 */
extern int
enbox_setup(struct elog * __restrict logger)
	__enbox_nonull(1) __nothrow;

#endif /* _ENBOX_H */
