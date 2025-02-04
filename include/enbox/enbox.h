/**
 * @file enbox.h
 * Enbox API interface.
 */

/**
 * @mainpage Enbox API
 *
 * What follows here provides a thorough description of how to use Enbox's
 * library.
 *
 * About {#about-sec}
 * ==================
 *
 * Basically, Enbox library is a C framework meant to instantiate a Linux
 * process from within a «runtime container», providing the ability to control
 * the process accesses to system resources according to a predefined
 * configuration.
 * The container logic implementation is based upon Linux's namespaces. As
 * stated into [namespaces(7)] man page :
 * > A namespace wraps a global system resource in an abstraction that makes it
 * > appear to the processes within the namespace that they have their own
 * > isolated instance of the global resource. Changes to the global resource
 * > are visible to other processes that are members of the namespace, but are
 * > invisible to other processes.
 *
 * The library also comes with additional utility functions allowing to
 * manipulate Linux system objects in a limited way. These are :
 * - [capabilities(7)],
 * - [namespaces(7)],
 * - filesystem objects,
 * - process [credentials(7)].
 *
 * Usage {#usage-sec}
 * ==================
 *
 * Enbox library API is organized around the following functional areas which
 * you can refer to for further details :
 * - [initialization](@ref init),
 * - [configuration](@ref conf),
 * - [instantiation](@ref instance),
 * - and [utilities](@ref utils).
 *
 * The typical sequence of operations involves using the first 3 functional
 * areas mentioned above. Most of the time, you use Enbox library in one of the
 * 2 following ways :
 * - [run an Enbox configuration from filesystem](#run-from-fs)
 * - or [run an Enbox configuration from pre-defined hard-coded values](#run-from-struct).
 *
 * Run a configuration from filesystem {#run-from-fs}
 * --------------------------------------------------
 *
 * This mode of operation is meant to apply and execute an Enbox configuration
 * stored into a file. This file must be formatted according to the
 * configuration syntax detailed into the [configuration syntax section](#conf-syntax).
 *
 * Additional usage details may be found into section @ref conf. This is the
 * most straightforward way to use the Enbox library.
 *
 * Run a configuration from hard-coded values {#run-from-struct}
 * -------------------------------------------------------------
 *
 * This mode of operation is meant to apply and execute an Enbox configuration
 * from pre-defined hard-coded values found into multiple binary structures
 * built at compile-time.
 *
 * Additional usage details may be found into section @ref instance. This is the
 * most complex way to use the Enbox library.
 *
 * Configuration syntax {#conf-syntax} 
 * ===================================
 *
 * Enbox parses configuration using the [libconfig library]. Configuration
 * follows syntax rules described in the [libconfig manual]. Please take a look
 * at the [libconfig manual] for an explanation of basic types.
 *
 * COMPLETE ME !!!
 *
 * [namespaces(7)]:     https://man7.org/linux/man-pages/man7/namespaces.7.html
 * [capabilities(7)]:   https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [credentials(7)]:    https://man7.org/linux/man-pages/man7/credentials.7.html
 * [execve(2)]:         https://man7.org/linux/man-pages/man2/execve.2.html
 * [libconfig library]: https://hyperrealm.github.io/libconfig
 * [libconfig manual]:  http://www.hyperrealm.com/libconfig/libconfig_manual.html
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

/**
 * @def __enbox_nonull(_arg_index, ...)
 *
 * Declare function arguments as non-null pointers.
 *
 * When applied to a function, tell compiler that the specified arguments must
 * be non-null pointers.
 * @param[in] _arg_index index of first non-null pointer argument
 * @param[in] ...        subsequent non-null pointer argument indices
 *
 * @see [GCC common function attributes]
 *      (https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes)
 */
#if defined(CONFIG_ENBOX_ASSERT)

#include <stroll/assert.h>

#define enbox_assert(_expr) \
	stroll_assert("enbox", _expr)

#define enbox_assert_setup() \
	enbox_assert(enbox_uid != (uid_t)-1); \
	enbox_assert(enbox_gid != (gid_t)-1); \
	enbox_assert(!(enbox_umask & ~((mode_t)ALLPERMS)))

#define __enbox_nonull(_arg_index, ...)
#define __enbox_const
#define __enbox_pure
#define __enbox_nothrow

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define __enbox_nonull(_arg_index, ...) __nonull(_arg_index, ## __VA_ARGS__)
#define __enbox_const                   __const
#define __enbox_pure                    __pure
#define __enbox_nothrow                 __nothrow

#define enbox_assert(_expr)

#define enbox_assert_setup()

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/**
 * @defgroup utils Utilities
 */

/**
 * @internal
 *
 * Current process file creation mode mask.
 *
 * @warning Do not reference this directly ! This is for internal use only. Use
 *          enbox_get_umask() and / or enbox_set_umask() instead.
 *
 * @see
 * - [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * - enbox_get_umask()
 * - enbox_set_umask()
 *
 * @ingroup utils
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
 * @see
 * - [getuid(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
 * - [setuid(2)](https://man7.org/linux/man-pages/man2/setuid.2.html)
 * - enbox_get_uid()
 *
 * @ingroup utils
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
 * @see
 * - [getgid(2)](https://man7.org/linux/man-pages/man2/getgid.2.html)
 * - [setgid(2)](https://man7.org/linux/man-pages/man2/setgid.2.html)
 * - enbox_get_gid()
 *
 * @ingroup utils
 */
extern gid_t enbox_gid;

/**
 * Retreive current process file creation mode mask.
 *
 * @return file creation mode mask.
 *
 * @see
 * - [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * - enbox_set_umask().
 *
 * @ingroup utils
 */
static inline mode_t __enbox_pure __enbox_nothrow
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
 * @see
 * - [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
 * - enbox_get_umask()
 *
 * @ingroup utils
 */
static inline mode_t __enbox_nothrow
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
 * @see
 * - [getuid(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
 * - [geteuid(2)](https://man7.org/linux/man-pages/man2/geteuid.2.html)
 * - enbox_get_gid().
 *
 * @ingroup utils
 */
static inline uid_t __enbox_pure __enbox_nothrow
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
 * @see
 * - [getgid(2)](https://man7.org/linux/man-pages/man2/getgid.2.html)
 * - [getegid(2)](https://man7.org/linux/man-pages/man2/getegid.2.html)
 * - enbox_get_uid().
 *
 * @ingroup utils
 */
static inline gid_t __enbox_pure __enbox_nothrow
enbox_get_gid(void)
{
	enbox_assert_setup();

	return enbox_gid;
}

/**
 * Keep filesystem entry owner UID unchanged.
 *
 * @see enbox_change_perms()
 *
 * @ingroup utils
 */
#define ENBOX_KEEP_UID  ((uid_t)-1)

/**
 * Keep filesystem entry group GID unchanged.
 *
 * @see enbox_change_perms()
 *
 * @ingroup utils
 */
#define ENBOX_KEEP_GID  ((gid_t)-1)

/**
 * Keep filesystem entry permissions unchanged.
 *
 * @see enbox_change_perms()
 *
 * @ingroup utils
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
 * @see
 * - #ENBOX_KEEP_UID
 * - #ENBOX_KEEP_GID
 * - #ENBOX_KEEP_MODE
 * - [chown(2)]
 * - [chmod(2)]
 *
 * @ingroup utils
 *
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 */
extern int
enbox_change_perms(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __enbox_nothrow;

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
 * @see
 * - [mkdir(2)]
 * - [chown(2)]
 * - [chmod(2)]
 * - [rmdir(2)]
 *
 * @ingroup utils
 *
 * [mkdir(2)]: https://man7.org/linux/man-pages/man2/mkdir.2.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [rmdir(2)]: https://man7.org/linux/man-pages/man2/rmdir.2.html
 */
extern int
enbox_make_dir(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __enbox_nothrow;

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
 * @see
 * - [symlink(2)]
 * - [readlink(2)]
 * - [chown(2)]
 * - [unlink(2)]
 *
 * @ingroup utils
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
	__enbox_nonull(1, 2) __enbox_nothrow;

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
 * @see
 * - [mknod(2)]
 * - [makedev(3)]
 * - [chown(2)]
 * - [chmod(2)]
 * - [unlink(2)]
 *
 * @ingroup utils
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
	__enbox_nonull(1) __enbox_nothrow;

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
 * @see
 * - [mknod(2)]
 * - [makedev(3)]
 * - [chown(2)]
 * - [chmod(2)]
 * - [unlink(2)]
 *
 * @ingroup utils
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
	__enbox_nonull(1) __enbox_nothrow;

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
 * @see
 * - [mkfifo(3)]
 * - [pipe(7)]
 * - [chown(2)]
 * - [chmod(2)]
 * - [unlink(2)]
 *
 * @ingroup utils
 *
 * [mkfifo(3)]: https://man7.org/linux/man-pages/man3/mkfifo.3.html
 * [chown(2)]: https://man7.org/linux/man-pages/man2/chown.2.html
 * [chmod(2)]: https://man7.org/linux/man-pages/man2/chmod.2.html
 * [unlink(2)]: https://man7.org/linux/man-pages/man2/unlink.2.html
 * [pipe(7)]: https://man7.org/linux/man-pages/man7/pipe.7.html
 */
extern int
enbox_make_fifo(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __enbox_nothrow;

/**
 * Clear effective, permitted and inheritable capability sets.
 *
 * Remove all capabilities from current thread's effective, permitted and
 * inheritable sets.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of [capabilities(7)].
 *
 * No particular privileges is required to perform this operation.
 *
 * @see
 * - sections `Thread capability sets` of [capabilities(7)]
 * - [capget(2)]
 *
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [capget(2)]:       https://man7.org/linux/man-pages/man2/capset.2.html
 */
extern int
enbox_clear_epi_caps(void) __enbox_nothrow;

/**
 * Clear ambient capability set.
 *
 * Remove all capabilities from current thread's ambient set.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of [capabilities(7)].
 *
 * No particular privileges is required to perform this operation.
 *
 * @see
 * - sections `Thread capability sets` of [capabilities(7)]
 * - section `PR_CAP_AMBIENT_CLEAR_ALL` of [prctl(2)]
 * - [PR_CAP_AMBIENT_CLEAR_ALL(2const)]
 * - [PR_CAP_AMBIENT(2const)]
 *
 * [capabilities(7)]:                  https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [prctl(2)]:                         https://man7.org/linux/man-pages/man2/prctl.2.html
 * [PR_CAP_AMBIENT_CLEAR_ALL(2const)]: https://man7.org/linux/man-pages/man2/PR_CAP_AMBIENT_CLEAR_ALL.2const.html
 * [PR_CAP_AMBIENT(2const)]:           https://man7.org/linux/man-pages/man2/PR_CAP_AMBIENT.2const.html
 */
extern void
enbox_clear_amb_caps(void) __enbox_nothrow;

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
 * @see
 * - sections `Thread capability sets` and `CAP_SETPCAP` of [capabilities(7)]
 * - section `PR_CAPBSET_DROP` of [prctl(2)]
 * - [PR_CAPBSET_DROP(2const)]
 *
 * @ingroup utils
 *
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 * [prctl(2)]:        https://man7.org/linux/man-pages/man2/prctl.2.html
 * [PR_CAPBSET_DROP(2const)]: https://man7.org/linux/man-pages/man2/pr_capbset_drop.2const.html
 */
extern int
enbox_clear_bound_caps(void)
	__enbox_nothrow __warn_result;

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
 * @see
 * - sections `PR_SET_NO_NEW_PRIVS` and `PR_SET_SECUREBITS` of [prctl(2)]
 * - sections `Thread capability sets` and `The securebits flags` of
 *   [capabilities(7)]
 *
 * @ingroup utils
 *
 * [no_new_privs]:    https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html
 * [execve(2)]:       https://man7.org/linux/man-pages/man2/execve.2.html
 * [prctl(2)]:        https://man7.org/linux/man-pages/man2/prctl.2.html
 * [capabilities(7)]: https://man7.org/linux/man-pages/man7/capabilities.7.html
 */
extern int
enbox_lock_caps(void) __enbox_nothrow;

/**
 * Request to setup current process's list of supplementary group IDs.
 *
 * @see
 * - enbox_change_ids()
 * - enbox_switch_ids()
 *
 * @ingroup utils
 */
#define ENBOX_RAISE_SUPP_GROUPS (false)

/**
 * Request to clear current process's list of supplementary group IDs.
 *
 * @see
 * - enbox_change_ids()
 * - enbox_switch_ids()
 *
 * @ingroup utils
 */
#define ENBOX_DROP_SUPP_GROUPS (true)

/**
 * Switch to user / group IDs.
 *
 * Change current process's real, effective and saved user ID to UID matching
 * @p pwd_entry entry passed in argument. This pointer may be retrieved using
 * one of the system primitives documented into getpwent(2).
 *
 * In addition, change current process's real, effective and saved group ID to
 * primary GID of @p user and setup current process's list of supplementary
 * group IDs according to the following :
 * - when @p drop_supp argument equals #ENBOX_RAISE_SUPP_GROUPS, setup
 *   supplementary group IDs from system group database in addition to primary
 *   group ID,
 * - when @p drop_supp argument equals #ENBOX_DROP_SUPP_GROUPS, clear
 *   supplementary group list.
 *
 * @warning
 * Requires the ability to enable the CAP_SETUID and CAP_SETUID capabilities.
 *
 * @param[in] pwd_entry A password file entry pointer to the user to change to
 * @param[in] drop_supp Load or clear supplementary groups list (see
 *                      #ENBOX_RAISE_SUPP_GROUPS and #ENBOX_DROP_SUPP_GROUPS)
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - #ENBOX_DROP_SUPP_GROUPS
 * - enbox_change_ids()
 * - [getpwent(2)]
 * - [setresuid(2)]
 * - [initgroups(3)]
 * - [setgroups(2)]
 * - [capabilities(7)]
 *
 * @ingroup utils
 *
 * [getpwent(2)]:     https://man7.org/linux/man-pages/man2/getpwent.2.html
 * [setresuid(2)]:    https://man7.org/linux/man-pages/man2/setresuid.2.html
 * [initgroups(3)]:   https://man7.org/linux/man-pages/man3/initgroups.3.html
 * [setgroups(2)]:    https://man7.org/linux/man-pages/man2/setgroups.2.html
 * [capabilities(7)]: https://man7.org/linux/man-pages/man2/capabilities.7.html
 */
extern int
enbox_switch_ids(const struct passwd * __restrict pwd, bool drop_supp)
	__enbox_nonull(1) __enbox_nothrow __leaf __warn_result;

/**
 * Switch to user / group IDs and setup capabilities.
 *
 * Change current process's real, effective and saved user ID to UID matching
 * @p pwd_entry entry passed in argument. This pointer may be retrieved using
 * one of the system primitives documented into getpwent(2).
 *
 * In addition, change current process's real, effective and saved group ID to
 * primary GID of @p user and setup current process's list of supplementary
 * group IDs according to the following :
 * - when @p drop_supp argument equals #ENBOX_RAISE_SUPP_GROUPS, setup
 *   supplementary group IDs from system group database in addition to primary
 *   group ID,
 * - when @p drop_supp argument equals #ENBOX_DROP_SUPP_GROUPS, clear
 *   supplementary group list.
 *
 * Finally, after return from this function, current thread permitted and
 * effective capability sets reflect the mask given by @p kept_caps.
 * Securebits are also modified and locked to the following value:
 * `SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
 *  SECBIT_NO_SETUID_FIXUP_LOCKED |
 *  SECBIT_KEEP_CAPS_LOCKED |
 *  SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * @warning
 * Requires the ability to enable the CAP_SETPCAP, CAP_SETUID and CAP_SETUID
 * capabilities.
 *
 * @param[in] pwd_entry A password file entry pointer to the user to change to
 * @param[in] kept_caps Mask of capabilities to keep in the permitted and
 *                      effective sets after the change operation
 * @param[in] drop_supp Load or clear supplementary groups list (see
 *                      #ENBOX_RAISE_SUPP_GROUPS and #ENBOX_DROP_SUPP_GROUPS)
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - #ENBOX_DROP_SUPP_GROUPS
 * - enbox_switch_ids()
 * - [getpwent(2)]
 * - [setresuid(2)]
 * - [initgroups(3)]
 * - [setgroups(2)]
 * - [capabilities(7)]
 *
 * @ingroup utils
 *
 * [getpwent(2)]:     https://man7.org/linux/man-pages/man2/getpwent.2.html
 * [setresuid(2)]:    https://man7.org/linux/man-pages/man2/setresuid.2.html
 * [initgroups(3)]:   https://man7.org/linux/man-pages/man3/initgroups.3.html
 * [setgroups(2)]:    https://man7.org/linux/man-pages/man2/setgroups.2.html
 * [capabilities(7)]: https://man7.org/linux/man-pages/man2/capabilities.7.html
 */
extern int
enbox_change_ids(const struct passwd * __restrict pwd_entry,
                 bool                             drop_supp,
                 uint64_t                         kept_caps)
	__enbox_nonull(1) __warn_result;

/**
 * Prepare system privilege runtime for later change IDs operation.
 *
 * Prepare the current thread's system privileges context to perform a change
 * IDs using enbox_change_ids().
 *
 * This will basically setup the following Linux kernel's security and
 * capability related features:
 * - set the [no_new_privs] attribute to 1, instructing next [execve(2)] call
 *   not to grant privileges to do anything that could not have been done
 *   without the [execve(2)] call ;
 * - set and lock the `SECBIT_NOROOT` securebits flag to 1 to disable the
 *   granting of capabilities when a SUID root program is executed or when a
 *   process with an effective or real UID of 0 calls [execve(2)] ;
 * - set and lock the `SECBIT_NO_CAP_AMBIENT_RAISE` securebits flag to 1 to
 *   disallow raising ambient capabilities ;
 * - clear all other available securebits flags ;
 * - enable capabilities required to perform a successful call to
 *   enbox_change_ids(), i.e. `CAP_SETPCAP`, `CAP_SETUID` and `CAP_SETGID`
 *   capabilities ;
 * - clear all bounding set capabilities to restrict all capabilities that may
 *   be gained through an [execve(2)].
 *
 * @warning Requires CAP_SETPCAP capability.
 *
 * @warning
 * Requires the ability to enable the CAP_SETPCAP, CAP_SETUID and CAP_SETUID
 * capabilities.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - enbox_change_ids()
 * - [execve(2)]
 * - [capabilities(7)]
 *
 * @ingroup utils
 *
 * [exeve(2)]:        https://man7.org/linux/man-pages/man2/execve.2.html
 * [setresuid(2)]:    https://man7.org/linux/man-pages/man2/setresuid.2.html
 * [capabilities(7)]: https://man7.org/linux/man-pages/man2/capabilities.7.html
 */
extern int
enbox_secure_change_ids(void)
	__warn_result;

#if defined(CONFIG_ENBOX_VERBOSE)

extern void
enbox_print_status(FILE * __restrict stdio)
	__enbox_nonull(1);

#else  /* !defined(CONFIG_ENBOX_VERBOSE) */

static inline __enbox_nonull(1)
void
enbox_print_status(FILE * __restrict stdio __unused)
{
}

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

/**
 * @defgroup instance Instantiation
 *
 * This involves the following sequence of operations :
 * -# initialize Enbox library using enbox_setup(),
 * -# optionally populate the «host» filesystem using enbox_populate_host(),
 * -# optionally load user and group membership informations required for later
 *  processing using enbox_load_ids_byid() or enbox_load_ids_byname(),
 * -# optionally run either of the following sequence of operations :
 *    - run a command onto the «host» system using enbox_run_cmd(),
 *    - or run a «jail'ed» command :
 *      -# instantiate a runtime container, i.e. the so-called jail, using
 *      enbox_enter_jail()
 *      -# run a command from within this jail using enbox_run_cmd().
 *
 */

/**
 * File system entry type identifier.
 *
 * Identifies types of filesystem entries that Enbox may create when populating
 * jail and / or host filesystems.
 *
 * @ingroup instance
 */
enum enbox_entry_type {
	/** Directory entry. @see enbox_dir_entry */
	ENBOX_DIR_ENTRY_TYPE,
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_DIR_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - enbox_make_dir()
 * - section «The file type and mode» of [inode(7)]
 *
 * @ingroup instance
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_SLINK_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - enbox_make_slink()
 *
 * @ingroup instance
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_CHRDEV_ENTRY_TYPE
 * - #ENBOX_BLKDEV_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - enbox_make_chrdev()
 * - enbox_make_blkdev()
 * - [makedev(3)]
 *
 * @ingroup instance
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_FIFO_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - enbox_make_fifo()
 * - [pipe(7)]
 *
 * @ingroup instance
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_PROC_ENTRY_TYPE
 * - #enbox_entry
 * - #enbox_bind_entry
 * - enbox_enter_jail()
 * - [mount(2)]
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
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
 * jail filesystem using enbox_enter_jail(). See section «Bind mounts» of
 * [mount(8)] and section «Creating a bind mount» of [mount(2)] for more
 * informations about what a bind mount is.
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
 * @see
 * - #enbox_entry_type
 * - #ENBOX_FILE_ENTRY_TYPE
 * - #ENBOX_TREE_ENTRY_TYPE
 * - #enbox_entry
 * - #enbox_bind_entry
 * - enbox_enter_jail()
 * - [mount(2)]
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
 *
 * [mount(2)]: https://man7.org/linux/man-pages/man2/mount.2.html
 * [mount(8)]: https://man7.org/linux/man-pages/man8/mount.8.html
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
 * @see
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
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
		 * @see
		 * - #ENBOX_CHRDEV_ENTRY_TYPE
		 * - #ENBOX_BLKDEV_ENTRY_TYPE
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
		 * @see
		 * - #ENBOX_FILE_ENTRY_TYPE
		 * - #ENBOX_TREE_ENTRY_TYPE
		 */
		struct enbox_bind_entry  bind;
	};
};

/**
 * Filesystem entry descriptor set.
 *
 * Aggregate multiple #enbox_entry filesystem entry descriptors. This is used
 * to ensure that the contained filesystem entries are properly created when:
 * - populating jail filesystem using enbox_enter_jail(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of [mount_namespaces(7)]).
 *
 * @see
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
 *
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
struct enbox_fsset {
	/**
	 * Number of #enbox_entry entries contained into
	 * #enbox_fsset::entries.
	 */
	unsigned int               nr;
	/** Array of #enbox_entry entries. */
	const struct enbox_entry * entries;
};

/**
 * Populate host filesystem.
 *
 * Ensure that filesystem entries found into #enbox_fsset set given in argument
 * are properly created from within the «host» mount namespace, i.e., the
 * initial system-wide mount namespace.
 *
 * Entries will be created in the order they appear into the #enbox_fsset set.
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of [mount_namespaces(7)]).
 *
 * @param[in] fsset Set of filesystem entries to create
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
 *
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
extern int
enbox_populate_host(const struct enbox_fsset * __restrict fsset)
	__enbox_nonull(1);

/**
 * @struct enbox_ids
 *
 * User / group identifiers.
 *
 * Opaque structure storing user and group membership informations.
 *
 * @see
 * - enbox_load_ids_byid()
 * - enbox_load_ids_byname()
 * - enbox_enter_jail()
 * - enbox_run_cmd()
 *
 * @ingroup instance
 */
struct enbox_ids;

/**
 * Load user and group membership identifiers by UID.
 *
 * Given the UID @p id argument, load the related ownership and group membership
 * informations and store them into @p ids. It may then be used as input to
 * enbox_enter_jail() and / or enbox_run_cmd() to switch to the stored user and
 * group(s).
 *
 * Depending on @p drop_supp argument, group membership informations will be set
 * to the following :
 * - user's primary group only when @p drop_supp set to #ENBOX_DROP_SUPP_GROUPS,
 * - user's primary group and all groups it is a member of when @p drop_supp set
 *   to #ENBOX_RAISE_SUPP_GROUPS.
 *
 * @param[out] ids       Ownership and group membership informations store
 * @param[in]  id        User UID to load informations for
 * @param[in]  drop_supp Drop supplementary group membership
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_DROP_SUPP_GROUPS
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - enbox_enter_jail()
 * - enbox_run_cmd()
 * - enbox_change_ids()
 * - enbox_load_ids_byname()
 *
 * @ingroup instance
 */
extern int
enbox_load_ids_byid(struct enbox_ids * __restrict ids,
                    uid_t                         id,
                    bool                          drop_supp) __enbox_nonull(1);

/**
 * Load user and group membership identifiers by user name.
 *
 * Given the user name @p name argument, load the related ownership and group
 * membership informations and store them into @p ids. It may then be used as
 * input to enbox_enter_jail() and / or enbox_run_cmd() to switch to the stored
 * user and group(s).
 *
 * Depending on @p drop_supp argument, group membership informations will be set
 * to the following :
 * - user's primary group only when @p drop_supp set to #ENBOX_DROP_SUPP_GROUPS,
 * - user's primary group and all groups it is a member of when @p drop_supp set
 *   to #ENBOX_RAISE_SUPP_GROUPS.
 *
 * @param[out] ids       Ownership and group membership informations store
 * @param[in]  user      User name to load informations for
 * @param[in]  drop_supp Drop supplementary group membership
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_DROP_SUPP_GROUPS
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - enbox_enter_jail()
 * - enbox_run_cmd()
 * - enbox_change_ids()
 * - enbox_load_ids_byid()
 *
 * @ingroup instance
 */
extern int
enbox_load_ids_byname(struct enbox_ids * __restrict ids,
                      const char * __restrict       user,
                      bool                          drop_supp)
	__enbox_nonull(1, 2);

/**
 * Default list of new namespaces a jail is made a member of.
 *
 * The list is set to:
 * - mount namespace,
 * - Cgroup namespace,
 * - UTS namespace,
 * - IPC namespace,
 * - and network namespace.
 *
 * @see
 * - #enbox_jail::namespaces
 * - enbox_enter_jail()
 * - [mount_namespaces(7)]
 *
 * @ingroup instance
 *
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 */
#define ENBOX_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

/**
 * Jail descriptor.
 *
 * This structure holds properties used to create a jail using
 * enbox_enter_jail().
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of [mount_namespaces(7)]).
 *
 * [mount_namespaces(7)]: https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
 *
 * @see enbox_enter_jail()
 *
 * @ingroup instance
 */
struct enbox_jail {
	/**
	 * List of namespaces this jail will be a member of.
	 *
	 * @see #ENBOX_NAMESPACE_FLAGS
	 */
	int                namespaces;
	/**
	 * Pathname to this jail's root filesystem.
	 *
	 * Pathname to directory under which this jail's root (TMPFS) filesystem
	 * will be mounted.
	 */
	const char *       root_path;
	/** Set of filesystem entries to create for this jail. */
	struct enbox_fsset fsset;
};

/**
 * Create and enter a jailed runtime context.
 *
 * Allows to create and enter a jail. This jail may be used to further
 * [execve(2)] a program from within a runtime context isolated from the main
 * system-wide runtime using enbox_run_cmd().
 * Jail will be created according to properties passed as @p jail argument.
 * In addition, @p ids argument must point to user and group membership
 * identifiers that will be passed to the next enbox_run_cmd() call.
 *
 * enbox_enter_jail() carries out the following sequence of actions:
 * 1. clear the whole environment using [clearenv(3)] ;
 * 2. lock capability sets using enbox_lock_caps() ;
 * 3. clear the capability *bounding* set using enbox_clear_bounding_caps() ;
 *    note that *effective*, *permitted*, *inheritable* and *ambient* sets will
 *    be cleared at [execve(2)] time ;
 * 4. isolate from global system namespaces using [unshare(2)] and
 *    #enbox_jail::namespaces value;
 * 5. create jail's futur root filesystem (TMPFS) and populate it using
 *    #enbox_jail::root_path and #enbox_jail::fsset content;
 * 6. switch the new jail's root filesystem.
 *
 * Isolation from global system resources is provided through the Linux kernel
 * [namespaces(7)] / [unshare(2)] machinery. More specifically, the following
 * types of namespaces may be created:
 * - mount namespace (`CLONE_NEWNS`),
 * - cgroup namespace (`CLONE_NEWCGROUP`),
 * - UTS namespace (`CLONE_NEWUTS`),
 * - IPC namespace (`CLONE_NEWIPC`)
 * - network namespace (`CLONE_NEWNET`).
 *
 * In addition, the jail will be implicitly isolated from the global system-wide
 * filesystem attributes by giving [unshare(2)] the `CLONE_FS` flag in order to
 * prevent from sharing with any other process :
 * - the root directory ([chroot(2)]),
 * - the current working directory ([chdir(2)]),
 * - and [umask(2)] attributes.
 *
 * Finally, the jail will be implicitly isolated from the global system-wide
 * System V semaphore adjustment values by giving [unshare(2)] the
 * `CLONE_SYSVSEM` flag (see [semop(2)]).
 *
 * @warning
 * Should an error occur, current program state will be left as-is, i.e. in an
 * unpredictable state. Caller should exit(3) as soon as possible.
 *
 * @note
 * Enbox is meant to run onto embedded systems, i.e., from within a controlled
 * software runtime. That is the reason why Enbox is a [execve(2)] based
 * containment system to keep things simple. As a consequence, this comes with a
 * few limitations with respect to namespace isolation handling:
 * 1. don't support CLONE_NEWPID since we don't want to handle fork / init
 *    process machinery ; instead, we may rely upon secure procfs operations to
 *    provide some sort of PID space isolation (see procfs hidepid / gid /
 *    subset mount options).
 * 2. don't support CLONE_NEWUSER since we don't really need it for now (we have
 *    no use case for emulating a complete virtualized OS while running onto an
 *    embedded system) ;
 *    we may however need to investigate possible implications related to kernel
 *    keyrings isolation...
 *
 * @param[in] jail Properties of jail to create
 * @param[in] ids  User and group membership identifiers used to [execve(2)] as
 *                 when calling enbox_run_cmd()
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - enbox_load_ids_byid()
 * - enbox_load_ids_byname()
 * - enbox_run_cmd()
 * - enbox_lock_caps()
 * - enbox_clear_bounding_caps()
 * - [clearenv(3)]
 * - [namespaces(7)]
 * - [unshare(2)]
 * - [execve(2)]
 * - [chroot(2)]
 * - [pivot_root(2)]
 * - [chdir(2)]
 * - [umask(2)]
 * - [semop(2)]
 *
 * @ingroup instance
 *
 * [clearenv(3)]:   https://man7.org/linux/man-pages/man3/clearenv.3.html
 * [namespaces(7)]: https://man7.org/linux/man-pages/man7/namespaces.7.html
 * [unshare(2)]:    https://man7.org/linux/man-pages/man2/unshare.2.html
 * [execve(2)]:     https://man7.org/linux/man-pages/man2/execve.2.html
 * [chroot(2)]:     https://man7.org/linux/man-pages/man2/chroot.2.html
 * [pivot_root(2)]: https://man7.org/linux/man-pages/man2/pivot_root.2.html
 * [chdir(2)]:      https://man7.org/linux/man-pages/man2/chdir.2.html
 * [umask(2)]:      https://man7.org/linux/man-pages/man2/umask.2.html
 * [semop(2)]:      https://man7.org/linux/man-pages/man2/semop.2.html
 * [exit(3)]:       https://man7.org/linux/man-pages/man3/exit.3.html
 */
extern int
enbox_enter_jail(const struct enbox_jail * __restrict jail,
                 const struct enbox_ids * __restrict  ids)
	__enbox_nonull(1, 2) __enbox_nothrow;

/**
 * Command descriptor.
 *
 * This structure holds properties used to [execve(2)] a program using
 * enbox_run_cmd().
 *
 * @see
 * - enbox_run_cmd()
 * - enbox_enter_jail()
 * - enbox_populate_host()
 * - [execve(2)]
 *
 * @ingroup instance
 *
 * [execve(2)]:     https://man7.org/linux/man-pages/man2/execve.2.html
 */
struct enbox_cmd {
	/**
	 * File creation mode mask of process running this command.
	 *
	 * @see [umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)
	 */
	mode_t               umask;
	/**
	 * Optional current working directory of process running this command.
	 *
	 * @see [chdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html)
	 */
	const char *         cwd;
	/**
	 * Array of arguments used to execute this command.
	 *
	 * First array entry will be passed to [execve(2)] as first argument.
	 * The whole array will be passed to [execve(2)] as second argument.
	 * This array must be `NULL` terminated.
	 *
	 * Command will be executed with an empty environment.
	 *
	 * @warning The maximum number of array entries is restricted to 1024
	 *          excluding the terminating `NULL` entry.
	 *
	 * @see [execve(2)]
	 *
	 * [execve(2)]: https://man7.org/linux/man-pages/man2/execve.2.html
	 */
	const char * const * exec;
};

/**
 * Run a command.
 *
 * [execve(2)] a program according to properties stored into @p exec and @p ids
 * arguments.
 *
 * enbox_run_cmd() carries out the following sequence of actions:
 * 1. setup current process file creation mode mask according to
 *    #enbox_cmd::umask value ;
 * 2. change current process's real, effective and saved user ID and setup
 *    current process's list of supplementary group IDs according to @p ids
 *    content ;
 * 3. optionally change to directory pointed to by #enbox_cmd::cwd if not
 *    `NULL`;
 * 4. finally call [execve(2)] using arguments found into #enbox_cmd::exec
 *    array.
 *
 * @p ids argument must point to user and group membership identifiers that will
 * be switched to before calling [execve(2)]. You may use enbox_load_ids_byid()
 * or enbox_load_ids_byname() to initialize @p ids.
 *
 * See #enbox_cmd::exec for details about how this command is [execve(2)]'ed.
 *
 * enbox_populate_host() and / or enbox_enter_jail() may be called prior to
 * enbox_run_cmd() to setup the «host» mount namespace or the jail container
 * respectively.
 *
 * @warning
 * Should an error occur, current program state will be left as-is, i.e. in an
 * unpredictable state. Caller should exit(3) as soon as possible.
 *
 * @param[in] cmd Properties used to [execve(2)] this command
 * @param[in] ids User and group membership identifiers to switch to before
 *                calling [execve(2)]
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_cmd
 * - enbox_set_umask()
 * - enbox_load_ids_byid()
 * - enbox_load_ids_byname()
 * - enbox_change_ids()
 * - enbox_populate_host()
 * - enbox_enter_jail()
 * - [execve(2)]
 * - [chdir(2)]
 * - [umask(2)]
 * - [exit(2)]
 *
 * @ingroup instance
 *
 * [execve(2)]:     https://man7.org/linux/man-pages/man2/execve.2.html
 * [chdir(2)]:      https://man7.org/linux/man-pages/man2/chdir.2.html
 * [umask(2)]:      https://man7.org/linux/man-pages/man2/umask.2.html
 * [exit(3)]:       https://man7.org/linux/man-pages/man3/exit.3.html
 */
extern int
enbox_run_cmd(const struct enbox_cmd * __restrict cmd,
              const struct enbox_ids * __restrict ids)
	__enbox_nonull(1, 2) __enbox_nothrow;

/**
 * @defgroup conf Configuration
 *
 * This involves the following sequence of operations :
 * -# initialize Enbox library using enbox_setup(),
 * -# load and parse an Enbox configuration from the content of a file using
 *  enbox_create_conf_from_file(),
 * -# apply and execute the configuration loaded above using enbox_run_conf().
 *
 */

/**
 * @struct enbox_conf
 *
 * Enbox configuration.
 *
 * Opaque structure storing an Enbox configuration.
 *
 * @see
 * - enbox_create_conf_from_file()
 * - enbox_run_conf()
 * - enbox_destroy_conf()
 *
 * @ingroup conf
 */
struct enbox_conf;

/**
 * Apply an Enbox configuration.
 *
 * Run / apply an Enbox configuration instantiated by
 * enbox_create_conf_from_file().
 *
 * @warning
 * Should an error occur, current program state will be left as-is, i.e. in an
 * unpredictable state. Caller should call [exit(3)] as soon as possible.
 *
 * @note
 * In case of error, for debugging purpose and to ensure all resources allocated
 * by enbox_create_conf_from_file() are properly released, caller may
 * additionally call enbox_destroy_conf() prior to running [exit(3)].
 *
 * @param[in] conf Pointer to configuration to apply
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_conf
 * - enbox_create_conf_from_file()
 * - enbox_destroy_conf()
 * - [exit(3)]
 *
 * @ingroup conf
 *
 * [exit(3)]: https://man7.org/linux/man-pages/man3/exit.3.html
 */
extern int
enbox_run_conf(const struct enbox_conf * __restrict conf) __enbox_nonull(1);

/**
 * Load and instantiate an Enbox configuration from file content.
 *
 * Open, read and parse content of the file pointed to by @p path, then return a
 * pointer to an allocated Enbox configuration which may be later given to
 * enbox_run_conf() to apply the loaded configuration.
 *
 * File content syntax is detailed into FINISH ME!!
 *
 * Resources allocated for the instantiated Enbox configuration should be
 * released using enbox_destroy_conf() and / or [exit(3)].
 *
 * @param[in] path Pathname to configuration file
 *
 * @return A pointer to an allocated #enbox_conf structure or `NULL` in case of
 *         error in which case `errno` will be set accordingly.
 *
 * @see
 * - #enbox_conf
 * - enbox_run_conf()
 * - enbox_destroy_conf()
 * - [exit(3)]
 *
 * @ingroup conf
 *
 * [exit(3)]: https://man7.org/linux/man-pages/man3/exit.3.html
 */
extern struct enbox_conf *
enbox_create_conf_from_file(const char * __restrict path) __enbox_nonull(1);

/**
 * Release configuration resources.
 *
 * Release Enbox configuration resources allocated by
 * enbox_create_conf_from_file().
 *
 * @note
 * May safely be called just before [exit(3)] in case a previous call to
 * enbox_run_conf() has failed.
 *
 * @param[in] conf Pointer to configuration to destroy.
 *
 * @see
 * - #enbox_conf
 * - enbox_create_conf_from_file()
 * - enbox_run_conf()
 * - [exit(3)]
 *
 * @ingroup conf
 *
 * [exit(3)]: https://man7.org/linux/man-pages/man3/exit.3.html
 */
void
enbox_destroy_conf(struct enbox_conf * __restrict conf) __enbox_nonull(1);

/**
 * @defgroup init Initialization
 *
 * This module gather all definitions required to initialize the Enbox library.
 */

struct elog;

/**
 * Initialize Enbox library.
 *
 * May alter calling process *dumpable* attribute according to
 * #CONFIG_ENBOX_DISABLE_DUMP build option.
 * 
 * When @p logger is passed as a `NULL` pointer, Enbox disables the logging of
 * all diagnostic messages.
 *
 *
 * @warning
 * MUST be called prior to every other Enbox library function calls.
 *
 * @param[inout] logger an optional initialized Elog logger instance.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @ingroup init
 */
extern void
enbox_setup(struct elog * __restrict logger)
	__enbox_nothrow;

#endif /* _ENBOX_H */
