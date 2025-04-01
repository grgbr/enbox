/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Enbox interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      02 Feb 2022
 * @copyright Copyright (C) 2022-2025 Grégor Boirie.
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _ENBOX_H
#define _ENBOX_H

#include <enbox/config.h>
#include <utils/pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/capability.h>

/*
 * Depending on glibc version, this definition may be missing although handled
 * by kernel...
 */
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW (1UL << 8)
#endif

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

#define enbox_assert(_expr) \
	do {} while (0)

#define enbox_assert_setup() \
	do {} while (0)

#define __enbox_nonull(_arg_index, ...) __nonull(_arg_index, ## __VA_ARGS__)
#define __enbox_const                   __const
#define __enbox_pure                    __pure
#define __enbox_nothrow                 __nothrow

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/**
 * @internal
 *
 * Current process file creation mode mask.
 *
 * @warning Do not reference this directly ! This is for internal use only. Use
 *          enbox_get_umask() and / or enbox_set_umask() instead.
 *
 * @see
 * - @man{umask(2)}
 * - enbox_get_umask()
 * - enbox_set_umask()
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
 * - @man{getuid(2)}
 * - @man{setuid(2)}
 * - enbox_get_uid()
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
 * - @man{getgid(2)}
 * - @man{setgid(2)}
 * - enbox_get_gid()
 */
extern gid_t enbox_gid;

/**
 * Retreive current process file creation mode mask.
 *
 * @return file creation mode mask.
 *
 * @see
 * - @man{umask(2)}
 * - enbox_set_umask().
 */
static inline mode_t __enbox_pure __enbox_nothrow __warn_result
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
 * - @man{umask(2)}
 * - enbox_get_umask()
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
 * - @man{getuid(2)}
 * - @man{geteuid(2)}
 * - enbox_get_gid().
 */
static inline uid_t __enbox_pure __enbox_nothrow __warn_result
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
 * - @man{getgid(2)}
 * - @man{getegid(2)}
 * - enbox_get_uid().
 */
static inline gid_t __enbox_pure __enbox_nothrow __warn_result
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
 * Basically calls @man{chown(2)} then @man{chmod(2)} onto filesystem entry
 * pointed to by @p path.
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
 * - @man{chown(2)}
 * - @man{chmod(2)}
 */
extern int
enbox_change_perms(const char * __restrict path,
                   uid_t                   uid,
                   gid_t                   gid,
                   mode_t                  mode)
	__enbox_nonull(1) __enbox_nothrow __warn_result;

/**
 * Ensure a filesystem directory is properly created.
 *
 * Basically calls @man{mkdir(2)} to create a directory pointed to by @p path
 * according to @p uid user ID, @p gid group ID and @p mode permissions.
 * In case the directory already exists, ensure it is consistent with @p uid
 * user ID, @p gid group ID and @p mode permissions passed in arguments.
 *
 * Should an error occur:
 * - an entry matching @p path pathname existing prior to this call and not
 *   being a directory will be left untouched ;
 * - a directory matching @p path pathname existing prior to this call will be
 *   left in an unpredictable state ;
 * - otherwise, the new directory just created will be deleted using
 *   @man{rmdir(2)}
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
 * - @man{mkdir(2)}
 * - @man{chown(2)}
 * - @man{chmod(2)}
 * - @man{rmdir(2)}
 */
extern int
enbox_make_dir(const char * __restrict path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __enbox_nothrow __warn_result;

/**
 * Ensure a filesystem symbolic link is properly created.
 *
 * Basically calls @man{symlink(2)} to create a symbolic link @p path targeting
 * @p target according to @p uid user ID and @p gid group ID.
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
 * - otherwise, the new symbolic link will be deleted using @man{unlink(2)}
 *   before returning to the caller.
 *
 * @param[in] path   Pathname to filesystem symbolic link
 * @param[in] target Target pathname which @p path will point to
 * @param[in] uid    Symbolic link owner UID
 * @param[in] gid    Symbolic link group GID
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - @man{symlink(2)}
 * - @man{readlink(2)}
 * - @man{chown(2)}
 * - @man{unlink(2)}
 */
extern int
enbox_make_slink(const char * __restrict path,
                 const char * __restrict target,
                 uid_t                   uid,
                 gid_t                   gid)
	__enbox_nonull(1, 2) __enbox_nothrow __warn_result;

/**
 * Ensure a filesystem character devide node is properly created.
 *
 * Basically calls @man{mknod(2)} to create a character device node pointed to
 * by @p path according to @p uid user ID, @p gid group ID, @p mode permissions,
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
 * - otherwise, the new character device node will be deleted using
 *   @man{unlink(2)} before returning to the caller.
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
 * - @man{mknod(2)}
 * - @man{makedev(3)}
 * - @man{chown(2)}
 * - @man{chmod(2)}
 * - @man{unlink(2)}
 */
extern int
enbox_make_chrdev(const char * __restrict path,
                  uid_t                   uid,
                  gid_t                   gid,
                  mode_t                  mode,
                  unsigned int            major,
                  unsigned int            minor)
	__enbox_nonull(1) __enbox_nothrow __warn_result;

/**
 * Ensure a filesystem block devide node is properly created.
 *
 * Basically calls @man{mknod(2)} to create a block device node pointed to by
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
 * - otherwise, the new block device node will be deleted using @man{unlink(2)}
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
 * - @man{mknod(2)}
 * - @man{makedev(3)}
 * - @man{chown(2)}
 * - @man{chmod(2)}
 * - @man{unlink(2)}
 */
extern int
enbox_make_blkdev(const char * __restrict path,
                  uid_t                   uid,
                  gid_t                   gid,
                  mode_t                  mode,
                  unsigned int            major,
                  unsigned int            minor)
	__enbox_nonull(1) __enbox_nothrow __warn_result;

/**
 * Ensure a filesystem named pipe is properly created.
 *
 * Basically calls @man{mkfifo(3)} to create a named pipe (FIFO) pointed to by
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
 * - otherwise, the new named pipe will be deleted using @man{unlink(2)} before
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
 * - @man{mkfifo(3)}
 * - @man{pipe(7)}
 * - @man{chown(2)}
 * - @man{chmod(2)}
 * - @man{unlink(2)}
 */
extern int
enbox_make_fifo(const char * __restrict path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __enbox_nothrow __warn_result;

/**
 * Make a capability mask out of a constant capability index.
 *
 * Build a capability bitmask out of the given constant @p _cap capability index.
 *
 * Capability index definitions may be found into the `<linux/capability.h>`
 * header file shipped with your Linux kernel / C library install.
 *
 * @param[in] _cap A system capability index
 *
 * @return A system capability bitmask.
 *
 * @see
 * - enbox_cap()
 * - @man{capabilities(7)}
 */
#define ENBOX_CAP(_cap) \
	({ \
		compile_assert(cap_valid(_cap)); \
		UINT64_C(1) << (_cap); \
	 })

/**
 * Make a capability mask out of a capability index.
 *
 * Build a capability bitmask out of the given @p cap capability index.
 *
 * Capability index definitions may be found into the `<linux/capability.h>`
 * header file shipped with your Linux kernel / C library install.
 *
 * @param[in] cap A system capability index
 *
 * @return A system capability bitmask.
 *
 * @see
 * - ENBOX_CAP
 * - @man{capabilities(7)}
 */
static inline __enbox_const __enbox_nothrow __warn_result
uint64_t
enbox_cap(int cap)
{
	enbox_assert(cap_valid(cap));

	return UINT64_C(1) << cap;
}

/**
 * Clear effective, permitted and inheritable capability sets.
 *
 * Remove all capabilities from current thread's effective, permitted and
 * inheritable sets.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of @man{capabilities(7)}.
 *
 * No particular privileges is required to perform this operation.
 *
 * @see
 * - sections `Thread capability sets` of @man{capabilities(7)}
 * - @man{capget(2)}
 */
extern void
enbox_clear_epi_caps(void) __enbox_nothrow;

/**
 * Clear ambient capability set.
 *
 * Remove all capabilities from current thread's ambient set.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of @man{capabilities(7)}.
 *
 * No particular privileges is required to perform this operation.
 *
 * @see
 * - sections `Thread capability sets` of @man{capabilities(7)}
 * - section `PR_CAP_AMBIENT_CLEAR_ALL` of @man{prctl(2)}
 * - @man{PR_CAP_AMBIENT_CLEAR_ALL(2const)}
 * - @man{PR_CAP_AMBIENT(2const)}
 */
extern void
enbox_clear_amb_caps(void) __enbox_nothrow;

/**
 * Clear bounding capability set.
 *
 * Remove all capabilities from current thread's bounding set.
 *
 * For more informations about Linux capability sets, refer to section `Thread
 * capability sets` of @man{capabilities(7)}.
 *
 * @warning Requires CAP_SETPCAP capability.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - sections `Thread capability sets` and `CAP_SETPCAP` of
 *   @man{capabilities(7)}
 * - section `PR_CAPBSET_DROP` of @man{prctl(2)}
 * - @man{PR_CAPBSET_DROP(2const)}
 */
extern int
enbox_clear_bound_caps(void)
	__enbox_nothrow __warn_result;

/**
 * Request to setup current process's list of supplementary group IDs.
 *
 * @see
 * - enbox_change_ids()
 * - enbox_switch_ids()
 */
#define ENBOX_RAISE_SUPP_GROUPS (false)

/**
 * Request to clear current process's list of supplementary group IDs.
 *
 * @see
 * - enbox_change_ids()
 * - enbox_switch_ids()
 */
#define ENBOX_DROP_SUPP_GROUPS (true)

/**
 * Switch to user / group IDs.
 *
 * Change current process's real, effective and saved user ID to UID matching
 * @p pwd_entry entry passed in argument. This pointer may be retrieved using
 * one of the system primitives documented into @man{getpwent(3)}.
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
 * - @man{getpwent(3)}
 * - @man{setresuid(2)}
 * - @man{initgroups(3)}
 * - @man{setgroups(2)}
 * - @man{capabilities(7)}
 */
extern int
enbox_switch_ids(const struct passwd * __restrict pwd_entry, bool drop_supp)
	__enbox_nonull(1) __enbox_nothrow __leaf __warn_result;

/**
 * Switch to user / group IDs and setup capabilities.
 *
 * Change current process's real, effective and saved user ID to UID matching
 * @p pwd_entry entry passed in argument. This pointer may be retrieved using
 * one of the system primitives documented into @man{getpwent(3)}.
 *
 * In addition, change current process's real, effective and saved group ID to
 * primary GID matching the @p pwd_entry and setup current process's list of
 * supplementary group IDs according to the following :
 * - when @p drop_supp argument equals #ENBOX_RAISE_SUPP_GROUPS, setup
 *   supplementary group IDs from system group database in addition to primary
 *   group ID,
 * - when @p drop_supp argument equals #ENBOX_DROP_SUPP_GROUPS, clear
 *   supplementary group list.
 *
 * The @p kept_caps argument configures the mask of capabilities to keep enabled
 * when returning from call to enbox_change_ids().
 *
 * Upon return, current thread permitted and effective capability sets reflect
 * the mask given by @p kept_caps. Bounding and ambient capabilitiy sets are
 * cleared. The @rstterm{no_new_privs} attribute is set to 1 and securebits are
 * also modified and locked so that the following bits are set:
 * - `SECBIT_NOROOT`,
 * - `SECBIT_NOROOT_LOCKED`,
 * - `SECBIT_NO_SETUID_FIXUP_LOCKED`,
 * - `SECBIT_KEEP_CAPS_LOCKED`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * @warning
 * - Requires the ability to enable the CAP_SETPCAP, CAP_SETUID and CAP_SETUID
 *   capabilities.
 * - Trying to change to the same UID as the current process effective UID will
 *   lead to unpredictable result.
 * - Trying to change to a zero UID will lead to unpredictable result.
 * - Does not preserve `CAP_SYS_ADMIN`, `CAP_SETPCAP`, `CAP_SETUID`, and
 *   `CAP_SETGID` capabilities across change IDs operation. Trying to do so
 *   will lead to unpredictable results.
 *
 * @param[in]    pwd_entry A password file entry pointer to the user to change
 *                         to
 * @param[in]    drop_supp Load or clear supplementary groups list (see
 *                         #ENBOX_RAISE_SUPP_GROUPS and #ENBOX_DROP_SUPP_GROUPS)
 * @param[in]    kept_caps Capabilities to preserve after change IDs
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - #ENBOX_DROP_SUPP_GROUPS
 * - enbox_switch_ids()
 * - enbox_change_idsn_execve()
 * - @man{getpwent(3)}
 * - @man{setresuid(2)}
 * - @man{initgroups(3)}
 * - @man{setgroups(2)}
 * - @man{capabilities(7)}
 */
extern int
enbox_change_ids(const struct passwd * __restrict pwd_entry,
                 bool                             drop_supp,
                 uint64_t                         kept_caps)
	__enbox_nonull(1) __warn_result;

/**
 * Execute the program given in arguments and preserve capabilities.
 *
 * Executes the program  referred to by @p path. This causes the program that is
 * currently being run by the calling process to be replaced with a new program,
 * with newly initialized stack, heap, and (initialized and uninitialized) data
 * segments.
 *
 * The @p kept_caps argument configures the mask of capabilities to keep enabled
 * when returning from call to enbox_execve().
 * Capabilities referred to by @p kept_caps *MUST* also be enabled within the
 * bounding capability set. An error is returned otherwise.
 *
 * Upon return, current thread permitted, effective, inheritable and ambient
 * capability sets reflect the mask given by @p kept_caps. Bounding capabilitiy
 * set is cleared. The @rstterm{no_new_privs} attribute is set to 1 and
 * securebits are also modified and locked so that the following bits are set:
 * - `SECBIT_NOROOT`,
 * - `SECBIT_NOROOT_LOCKED`,
 * - `SECBIT_NO_SETUID_FIXUP_LOCKED`,
 * - `SECBIT_KEEP_CAPS_LOCKED`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * @p argv is a `NULL` terminated array of pointers to strings passed to the new
 * program as its command-line arguments. By convention, the first of these
 * strings (i.e., argv[0]) should contain the filename associated with
 * the file being executed.
 *
 * @p envp is an optional `NULL` terminated array of pointers to strings,
 * conventionally of the form *key=value*, which are passed as the environment
 * of the new program.
 *
 * @warning
 * - Requires the ability to enable the CAP_SETPCAP capabilities.
 * - @p argv *MUST* contain an arbitrary program name as first argument. Failing
 *   to do will lead to unpredictable results.
 * - Does not preserve `CAP_SYS_ADMIN` and `CAP_SETPCAP` capabilities across
 *   @man{execve(2)} operation. Trying to do so will lead to unpredictable
 *   results.
 *
 * @param[in] path      Pathname to program to @man{execve(2)}
 * @param[in] argv      Program command-line arguments
 * @param[in] envp      Optional program environment variable set
 * @param[in] kept_caps Capabilities to preserve after @man{execve(2)}
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - enbox_change_idsn_execve()
 * - @man{execve(2)}
 * - @man{capabilities(7)}
 */
extern int
enbox_execve(const char * __restrict path,
             char * const            argv[__restrict_arr],
             char * const            envp[__restrict_arr],
             uint64_t                kept_caps)
	__enbox_nonull(1, 2) __enbox_nothrow __leaf;

/**
 * Switch to user / group IDs, execute the program given in arguments and
 * preserve capabilities.
 *
 * Change current process's real, effective and saved user and group IDs to UID
 * and GIDs matching the @p pwd_entry entry and @p drop_supp arguments, then
 * execute the program specified as the @p path, @p argv and @p envp arguments
 * while preserving capabilities passed as @p kept_caps argument.
 *
 * While changing user IDs, current process's real, effective and saved group
 * IDs are switched to primary GID matching the @p pwd_entry and current
 * process's list of supplementary group IDs is setup according to the
 * following :
 * - when @p drop_supp argument equals #ENBOX_RAISE_SUPP_GROUPS, setup
 *   supplementary group IDs from system group database in addition to primary
 *   group ID,
 * - when @p drop_supp argument equals #ENBOX_DROP_SUPP_GROUPS, clear
 *   supplementary group list.
 *
 * The program to execute is referred to by @p path. This causes the program
 * that is currently being run by the calling process to be replaced with a new
 * program, with newly initialized stack, heap, and (initialized and
 * uninitialized) data segments.
 *
 * The @p kept_caps argument configures the mask of capabilities to keep enabled
 * when returning from call to enbox_change_idsn_execve().
 * Capabilities referred to by @p kept_caps *MUST* also be enabled within the
 * bounding capability set. An error is returned otherwise.
 *
 * Upon return, current thread permitted, effective, inheritable and ambient
 * capability sets reflect the mask given by @p kept_caps. Bounding capabilitiy
 * set is cleared. The @rstterm{no_new_privs} attribute is set to 1 and
 * securebits are also modified and locked so that the following bits are set:
 * - `SECBIT_NOROOT`,
 * - `SECBIT_NOROOT_LOCKED`,
 * - `SECBIT_NO_SETUID_FIXUP_LOCKED`,
 * - `SECBIT_KEEP_CAPS_LOCKED`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * The @p pwd_entry should point to a `struct passwd` entry retrieved using one
 * of the system primitives documented into @man{getpwent(3)}.
 *
 * The @p argv is a `NULL` terminated array of pointers to strings passed to the
 * new program as its command-line arguments. By convention, the first of these
 * strings (i.e., argv[0]) should contain the filename associated with the file
 * being executed.
 *
 * @p envp is an optional `NULL` terminated array of pointers to strings,
 * conventionally of the form *key=value*, which are passed as the environment
 * of the new program.
 *
 * @note
 * When @p pwd_entry points to an entry matching the current thread's effective
 * UID, the change IDs operations are skipped entirely.
 *
 * @warning
 * - Requires the ability to enable the CAP_SETPCAP, CAP_SETUID and CAP_SETUID
 *   capabilities.
 * - @p argv *MUST* contain an arbitrary program name as first argument. Failing
 *   to do will lead to unpredictable results.
 * - Does not preserve `CAP_SYS_ADMIN` and `CAP_SETPCAP` capabilities across
 *   operations. Trying to do so will lead to unpredictable results.
 *
 * @param[in]    pwd_entry A password file entry pointer to the user to change
 *                         to
 * @param[in]    drop_supp Load or clear supplementary groups list (see
 *                         #ENBOX_RAISE_SUPP_GROUPS and #ENBOX_DROP_SUPP_GROUPS)
 * @param[in]    path      Pathname to program to @man{execve(2)}
 * @param[in]    argv      Program command-line arguments
 * @param[in]    envp      Optional program environment variable set
 * @param[in]    kept_caps Capabilities to preserve after change IDs and
 *                         program execution
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #ENBOX_RAISE_SUPP_GROUPS
 * - #ENBOX_DROP_SUPP_GROUPS
 * - enbox_change_ids()
 * - enbox_execve()
 * - @man{getpwent(3)}
 * - @man{setresuid(2)}
 * - @man{initgroups(3)}
 * - @man{setgroups(2)}
 * - @man{execve(2)}
 * - @man{capabilities(7)}
 */
extern int
enbox_change_idsn_execve(const struct passwd * __restrict pwd_entry,
                         bool                             drop_supp,
                         const char * __restrict          path,
                         char * const                     argv[__restrict_arr],
                         char * const                     envp[__restrict_arr],
                         uint64_t                         kept_caps)
	__enbox_nonull(1, 3, 4);

/**
 * Enforce the safest security context possible.
 *
 * Given the current system privilege context, this function enforces the
 * most restricted environment possible for the current thread.
 *
 * Basically, it sets @rstterm{no_new_privs} attribute to 1.
 *
 * It clears all bounding set capabilities. In addition, securebits are modified
 * and locked to so that the following bits are set:
 * - `SECBIT_NOROOT`,
 * - `SECBIT_NOROOT_LOCKED`,
 * - `SECBIT_NO_SETUID_FIXUP_LOCKED`,
 * - `SECBIT_KEEP_CAPS_LOCKED`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * All ambient set and inheritable capabilities are cleared.
 *
 * Finally, capabilities given as @p kept_caps argument are left enabled into
 * the permitted and effective sets while all other ones are cleared.
 *
 * Requires CAP_SETPCAP capability.
 *
 * @param[in] kept_caps Capabilities to preserve into permitted and effective
 *                      sets.
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - @man{capabilities(7)}
 * - @rstterm{no_new_privs}
 */
extern int
enbox_enforce_safe(uint64_t kept_caps);

/**
 * Enable the safest security context possible.
 *
 * Given the current system privilege context, this function enables the
 * most restricted environment possible for the current thread.
 *
 * Basically, it sets @rstterm{no_new_privs} attribute to 1.
 *
 * If the CAP_SETPCAP capabilitiy is enabled into the permitted set, it clears
 * all bounding set capabilities. In addition, securebits are modified and
 * locked to so that the following bits are set:
 * - `SECBIT_NOROOT`,
 * - `SECBIT_NOROOT_LOCKED`,
 * - `SECBIT_NO_SETUID_FIXUP_LOCKED`,
 * - `SECBIT_KEEP_CAPS_LOCKED`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE`,
 * - `SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED`.
 *
 * All ambient set and inheritable capabilities are cleared.
 *
 * Finally, capabilities given as @p kept_caps argument are left enabled into
 * the permitted and effective sets while all other ones are cleared.
 *
 * No particular privileges are required to run this function.
 *
 * @param[in] kept_caps Capabilities to preserve into permitted and effective
 *                      sets.
 *
 * @see
 * - @man{capabilities(7)}
 * - @rstterm{no_new_privs}
 */
extern void
enbox_ensure_safe(uint64_t kept_caps);

/**
 * Show current thread's privileges.
 *
 * This function prints a detailed report of current thread's privileges, i.e.:
 * - system capability sets,
 * - securebits
 * - real, effective and saved UIDs and GIDs,
 * - as well as supplementary GIDs.
 *
 * No particular privileges are required to run this function.
 *
 * @param[in] stdio The standard I/O stream onto which to print the report.
 *
 * @see
 * - @man{capabilities(7)}
 * - @rstterm{no_new_privs}
 * - @man{credentials(7)}
 */
#if defined(CONFIG_ENBOX_SHOW)

extern void
enbox_show_status(FILE * __restrict stdio)
	__enbox_nonull(1);

#else  /* !defined(CONFIG_ENBOX_SHOW) */

static inline __enbox_nonull(1)
void
enbox_show_status(FILE * __restrict stdio __unused)
{
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

/**
 * File system entry type identifier.
 *
 * Identifies types of filesystem entries that Enbox may create when populating
 * jail and / or host filesystems.
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
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_DIR_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_prep_proc() to create a directory entry.
 *
 * @see
 * - #enbox_entry_type
 * - #ENBOX_DIR_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - enbox_make_dir()
 * - section «The file type and mode» of @man{inode(7)}
 */
struct enbox_dir_entry {
	/** Mode, i.e., permission bits for the directory. */
	mode_t mode;
};

/**
 * Symbolic link entry descriptor.
 *
 * Depicts how to create a symbolic link entry when :
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_SLINK_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_prep_proc() to create a symbolic link entry.
 *
 * @see
 * - #enbox_entry_type
 * - #ENBOX_SLINK_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - enbox_make_slink()
 */
struct enbox_slink_entry {
	/** Symbolic link target, i.e., pathname this symlink will point to. */
	const char * target;
};

/**
 * Device node entry descriptor.
 *
 * Depicts how to create a device node entry (wether character or block) when :
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_CHRDEV_ENTRY_TYPE or #ENBOX_BLKDEV_ENTRY_TYPE identifiers to instruct
 * enbox_populate_host() and / or enbox_prep_proc() to create a character
 * or a block device node entry respectively.
 *
 * @see
 * - #enbox_entry_type
 * - #ENBOX_CHRDEV_ENTRY_TYPE
 * - #ENBOX_BLKDEV_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - enbox_make_chrdev()
 * - enbox_make_blkdev()
 * - @man{makedev(3)}
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
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_FIFO_ENTRY_TYPE identifier to instruct enbox_populate_host() and / or
 * enbox_prep_proc() to create a named pipe entry.
 *
 * @see
 * - #enbox_entry_type
 * - #ENBOX_FIFO_ENTRY_TYPE
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - enbox_make_fifo()
 * - @man{pipe(7)}
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
 * filesystem using enbox_prep_proc().
 *
 * The filesystem will be mounted from within the jail's own mount namespace
 * using unbindable propagation properties (see «SHARED SUBTREE» section of
 * @man{mount_namespaces(7)}).
 * Mount point directory will be implicitly created if not existing with
 * permissions, ownership and membership inherited from the original filesystem
 * root directory.
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_PROC_ENTRY_TYPE identifier to instruct enbox_prep_proc() to create a
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
 * - enbox_prep_proc()
 * - @man{mount(2)}
 * - @man{mount_namespaces(7)}
 */
struct enbox_mount_entry {
	/**
	 * Mounting flags passed as 4th argument to @man{mount(2)}
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
	 * Mounting options passed as 5th argument to @man{mount(2)} when
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
 * jail filesystem using enbox_prep_proc(). See section «Bind mounts» of
 * @man{mount(8)} and section «Creating a bind mount» of @man{mount(2)} for more
 * informations about what a bind mount is.
 *
 * The bind mount will be performed from within the jail's own mount namespace
 * using unbindable propagation properties (see «SHARED SUBTREE» section of
 * @man{mount_namespaces(7)}).
 * Mount point directory will be implicitly created if not existing with
 * permissions, ownership and membership inherited from the source filesystem
 * mount point entry.
 *
 * Embedded within a #enbox_entry structure and used in combination with
 * #ENBOX_FILE_ENTRY_TYPE or #ENBOX_TREE_ENTRY_TYPE identifiers to instruct
 * enbox_prep_proc() to create file or (sub-)tree bind mount mount entry
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
 * - enbox_prep_proc()
 * - @man{mount(2)}
 * - @man{mount_namespaces(7)}
 */
struct enbox_bind_entry {
	/** Pathname to source filesystem entry to bind mount. */
	const char *  orig;
	/**
	 * Mounting flags passed as 4th argument to @man{mount(2)}
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
	 * Mounting options passed as 5th argument to @man{mount(2)} when bind
	 * mounting a file or a filesystem (sub-)tree.
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
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of @man{mount_namespaces(7)}).
 *
 * @see
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - @man{mount_namespaces(7)}
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
 * - populating jail filesystem using enbox_prep_proc(),
 * - or populating host filesystem using enbox_populate_host().
 *
 * @note Populating jail's filesystem(s) will be performed from within the
 *       jail's own mount namespace using unbindable propagation properties (see
 *       «SHARED SUBTREE» section of @man{mount_namespaces(7)}).
 *
 * @see
 * - #enbox_entry
 * - enbox_populate_host()
 * - enbox_prep_proc()
 * - @man{mount_namespaces(7)}
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
 *       «SHARED SUBTREE» section of @man{mount_namespaces(7)}).
 *
 * @param[in] fsset Set of filesystem entries to create
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_entry
 * - enbox_populate_host()
 * - @man{mount_namespaces(7)}
 */
extern int
enbox_populate_host(const struct enbox_fsset * __restrict fsset)
	__enbox_nonull(1) __warn_result;

/**
 * @struct enbox_ids
 *
 * User / group identifiers.
 *
 * Opaque structure storing user and group membership informations. It should be
 * initialized using one of the enbox_load_ids_byid() or enbox_load_ids_byname()
 * functions.
 *
 * @see
 * - enbox_load_ids_byid()
 * - enbox_load_ids_byname()
 * - enbox_prep_proc()
 * - enbox_run_cmd()
 * - @man{getpwent(3)}
 * - @man{credentials(7)}
 */
struct enbox_ids {
	/**
	 * @internal
	 *
	 * A pointer to a password database entry.
	 */
	const struct passwd * pwd;
	/**
	 * @internal
	 *
	 * Wether to request the loading of supplementary groups or not.
	 */
	bool                  drop_supp;
};

/**
 * Load user and group membership identifiers by UID.
 *
 * Given the UID @p id argument, load the related ownership and group membership
 * informations and store them into @p ids. It may then be used as input to
 * enbox_prep_proc(), enbox_change_proc_ids(), enbox_run_proc_cmd() or
 * enbox_change_ids() to switch to the stored user and group(s).
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
 * - enbox_load_ids_byname()
 * - #enbox_proc::ids
 * - enbox_prep_proc()
 * - enbox_run_proc_cmd()
 * - enbox_change_proc_ids()
 * - enbox_change_ids()
 * - @man{getpwent(3)}
 * - @man{credentials(7)}
 */
extern int
enbox_load_ids_byid(struct enbox_ids * __restrict ids,
                    uid_t                         id,
                    bool                          drop_supp)
	__enbox_nonull(1) __warn_result;

/**
 * Load user and group membership identifiers by user name.
 *
 * Given the user name @p name argument, load the related ownership and group
 * membership informations and store them into @p ids. It may then be used as
 * input to enbox_prep_proc(), enbox_change_proc_ids(), enbox_run_proc_cmd() or
 * enbox_change_ids() to switch to the stored user and group(s).
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
 * - enbox_load_ids_byid()
 * - #enbox_proc::ids
 * - enbox_prep_proc()
 * - enbox_run_proc_cmd()
 * - enbox_change_proc_ids()
 * - enbox_change_ids()
 * - @man{getpwent(3)}
 * - @man{credentials(7)}
 */
extern int
enbox_load_ids_byname(struct enbox_ids * __restrict ids,
                      const char * __restrict       user,
                      bool                          drop_supp)
	__enbox_nonull(1, 2) __warn_result;

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
 * - enbox_prep_proc()
 * - @man{mount_namespaces(7)}
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
 * enbox_prep_proc().
 *
 * @note
 * Populating jail's filesystem(s) will be performed from within the jail's own
 * mount namespace using unbindable propagation properties (see «SHARED SUBTREE»
 * section of @man{mount_namespaces(7)}).
 *
 * @see enbox_prep_proc()
 */
struct enbox_jail {
	/**
	 * List of @rstsubst{namespaces} this jail will be a member of.
	 *
	 * @see
	 * - #ENBOX_NAMESPACE_FLAGS
	 * - @man{namespaces(7)}
	 */
	int                namespaces;
	/**
	 * Pathname to this jail's root filesystem.
	 *
	 * Pathname to directory under which this jail's root (TMPFS) filesystem
	 * will be mounted.
	 */
	const char *       root_path;
	/**
	 * Set of filesystem entries to create for this jail.
	 *
	 * This field may be empty, i.e., thanks to a zero #enbox_fsset::nr
	 * field. In this case, the @rstsubst{jail} will be created with an
	 * empty root filesystem.
	 */
	struct enbox_fsset fsset;
};

/**
 * Process context descriptor.
 *
 * This structure holds properties used to prepare runtime context for further
 * secure operations such as enbox_run_proc_cmd() or enbox_change_proc_ids().
 *
 * You are encouraged to use enbox_load_ids_byid() or enbox_load_ids_byname() to
 * setup user / group @rstsubst{credentials} pointed to by the #enbox_proc::ids
 * field of this structure.
 *
 * @see
 * - enbox_prep_proc()
 * - enbox_run_proc_cmd()
 * - enbox_change_proc_ids()
 * - enbox_load_ids_byid()
 * - enbox_load_ids_byname()
 */
struct enbox_proc {
	/**
	 * File creation mode mask of current process.
	 *
	 * @see @man{umask(2)}
	 */
	mode_t               umask;
	/**
	 * Optional pointer to a structure holding user and group membership
	 * identifiers to change to for current process.
	 *
	 * @see
	 * - enbox_load_ids_byid()
	 * - enbox_load_ids_byname()
	 * - @man{credentials(7)}
	 */
	struct enbox_ids *   ids;
	/**
	 * Optional mask of system capabilities enabled for current process.
	 *
	 * @see @man{capabilities(7)}
	 */
	uint64_t             caps;
	/**
	 * Optional current working directory of current process.
	 *
	 * When unspecified, current working directory is set to the root of the
	 * @rstsubst{jail} if any. It is left untouched otherwise.
	 *
	 * @see
	 * - @man{chdir(2)}
	 * - @man{getcwd(2)}
	 */
	const char *         cwd;
	/**
	 * Number of file descriptors to keep opened before running the final
	 * program.
	 *
	 * @see #enbox_proc::fds
	 */
	unsigned int         fds_nr;
	/**
	 * Optional list of file descriptors to keep opened before running the
	 * final program.
	 *
	 * @see #enbox_proc::fds_nr
	 */
	int *                fds;
};

/**
 * Secure current process runtime context.
 *
 * Enforce system runtime properties for the current process according to the @p
 * proc argument.
 * Optionally, when the @p jail is given as a non `NULL' argument, current
 * process is made to enter a @rstsubst{jail} created according to @p jail
 * argument.
 *
 * When returning from this function, current process may be considered secure
 * enough and ready to perform further call to enbox_run_proc_cmd(),
 * enbox_change_proc_ids(), or eventually hand-crafted @man{setresuid(2)} /
 * @man{execve(2)} to run an arbitrary program isolated from the main
 * system-wide runtime.
 *
 * @note
 * This function does not configure system @rstsubst{capabilities} at all. For
 * additional restricted system privileges, a subsequent call to
 * enbox_run_proc_cmd() or enbox_change_proc_ids() *should* be performed.
 *
 * Basically, the following sequence of actions are carried out:
 * -# clear the whole environment using @man{clearenv(3)} ;
 * -# if @p jail is given as a non `NULL` argument, setup and enter the jail ;
 * -# otherwise, close all unwanted file descriptors according to
 *    #enbox_proc::fds_nr and #enbox_proc::fds content ;
 * -# setup the requested @man{umask(2)} attribute according to
 *    #enbox_proc::umask ;
 * -# change to the requested current working directory according to
 *    #enbox_proc::cwd.
 *
 * Optionally, when the @p jail argument is non `NULL`, step *b.* above performs
 * the following actions:
 * -# isolate from global system namespaces using @man{unshare(2)} according to
 *    #enbox_jail::namespaces value;
 * -# populate jail's root filesystem (TMPFS) according to
 *    #enbox_jail::root_path and #enbox_jail::fsset content;
 * -# close all unwanted file descriptors according to #enbox_proc::fds_nr and
 *    #enbox_proc::fds content ;
 * -# @man{chroot(2)} / @man{pivot_root(2)} to the new jail's root filesystem
 *    mounted as read-only.
 *
 * Isolation from global system resources is provided through the Linux kernel
 * @man{namespaces(7)} / @man{unshare(2)} machinery. More specifically, the
 * following types of namespaces may be created:
 * - mount namespace (`CLONE_NEWNS`),
 * - cgroup namespace (`CLONE_NEWCGROUP`),
 * - UTS namespace (`CLONE_NEWUTS`),
 * - IPC namespace (`CLONE_NEWIPC`)
 * - network namespace (`CLONE_NEWNET`).
 *
 * In addition, the jail will be implicitly isolated from the global system-wide
 * filesystem attributes by giving @man{unshare(2)} the `CLONE_FS` flag in order
 * to prevent from sharing with any other process :
 * - the root directory (@man{chroot(2)}),
 * - the current working directory (@man{chdir(2)}),
 * - and @man{umask(2)} attributes.
 *
 * Finally, the jail will be implicitly isolated from the global system-wide
 * System V semaphore adjustment values by giving @man{unshare(2)} the
 * `CLONE_SYSVSEM` flag (see @man{semop(2)}).
 *
 * @warning
 * Should an error occur, current program state will be left as-is, i.e. in an
 * unpredictable state. Caller should exit(3) as soon as possible.
 *
 * @note
 * Enbox is meant to run onto embedded systems, i.e., from within a controlled
 * software runtime. That is the reason why Enbox is a @man{execve(2)} based
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
 * @param[in] proc Process runtime properties to enforce
 * @param[in] jail Properties of jail to create
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - enbox_run_proc_cmd()
 * - enbox_change_proc_ids()
 * - @man{clearenv(3)}
 * - @man{namespaces(7)}
 * - @man{unshare(2)}
 * - @man{execve(2)}
 * - @man{chroot(2)}
 * - @man{pivot_root(2)}
 * - @man{chdir(2)}
 * - @man{umask(2)}
 * - @man{semop(2)}
 */
extern int
enbox_prep_proc(const struct enbox_proc * __restrict proc,
                const struct enbox_jail * __restrict jail)
	__enbox_nonull(1) __warn_result;

/**
 * Change user / group IDs according to a process runtime context.
 *
 * Perform a change of user / group @rstsubst{credentials} for the current
 * process according to the @p proc argument.
 * This function is typically called after enbox_prep_proc() to complete the
 * process of securing the current runtime context for further operations.
 *
 * The @p proc argument *should* have been previously given to enbox_prep_proc()
 * and is used to perform the user / group IDs change for the current process
 * according to the #enbox_proc::ids field.
 *
 * Basically, this function performs the following:
 * * configures system @rstsubst{capabilities} to further restrict system
 *   privileges according to #enbox_proc::caps content ;
 * * optionally switch to user / group IDs according to #enbox_proc::ids.
 *
 * When returning from this function, current process may be considered ready to
 * perform operations on a completly secure and isolated basis.
 *
 * @warning
 * Should an error occur, current program state will be left as-is, i.e. in an
 * unpredictable state. Caller should exit(3) as soon as possible.
 *
 * @param[in] proc Process runtime properties to enforce
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - enbox_run_proc_cmd()
 * - enbox_prep_proc()
 * - @man{capabilities(7)}
 * - @man{setresuid(2)}
 */
extern int
enbox_change_proc_ids(const struct enbox_proc * __restrict proc)
	__enbox_nonull(1) __warn_result;

/**
 * Change user / group IDs and execute arbitrary program according to a process
 * runtime context.
 *
 * Perform an optional change of user / group @rstsubst{credentials} for the
 * current process according to the @p proc argument, then @man{exeve(2)} the
 * program given as @p cmd argument.
 * This function is typically called after enbox_prep_proc() to complete the
 * process of securing the current runtime context in order to run the program
 * given as argument.
 *
 * The @p proc argument *should* have been previously given to enbox_prep_proc()
 * and is used to perform a change of user / group @rstsubst{credentials} for
 * the current process according to the #enbox_proc::ids field.
 *
 * @p cmd is an array of arguments that specifies the program to be executed by
 * the current process.
 * First @p cmd array entry will be passed to @man{execve(2)} as first argument.
 * The whole array will be passed to @man{execve(2)} as second argument.
 * This array must be `NULL` terminated.
 *
 * This function basically performs the following operations:
 * - optionally change user / group IDs according to #enbox_proc::ids if
 *   present ;
 * - restrict system @man{capabilities(7)} according to #enbox_proc::caps ;
 * - and finally @man{exeve(2)} the program passed as @p cmd.
 *
 * See #enbox_proc for further details about properties used to setup
 * runtime context and optional program of current process.
 *
 * @warning
 * - The maximum number of @p cmd array entries is restricted to 1024 excluding
 *   the terminating `NULL` entry.
 * - Should an error occur, current program state will be left as-is, i.e. in an
 *   unpredictable state. Caller should exit(3) as soon as possible.
 *
 * @param[in] proc Process runtime properties to enforce
 * @param[in] cmd  Program and arguments used to @man{execve(2)} this command
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_proc
 * - enbox_prep_proc()
 * - enbox_change_proc_ids()
 * - enbox_change_idsn_execve()
 * - @man{setresuid(2)}
 * - @man{execve(2)}
 * - @man{exit(3)}
 * - @man{capabilities(7)}
 * - @man{credentials(7)}
 */
extern int
enbox_run_proc_cmd(const struct enbox_proc * __restrict proc,
                   const char * const                   cmd[__restrict_arr])
	__enbox_nonull(1, 2) __warn_result;

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
 * unpredictable state. Caller should call @man{exit(3)} as soon as possible.
 *
 * @note
 * In case of error, for debugging purpose and to ensure all resources allocated
 * by enbox_create_conf_from_file() are properly released, caller may
 * additionally call enbox_destroy_conf() prior to running @man{exit(3)}.
 *
 * @param[in] conf Pointer to configuration to apply
 *
 * @return 0 if successful, an errno-like error code otherwise.
 *
 * @see
 * - #enbox_conf
 * - enbox_create_conf_from_file()
 * - enbox_destroy_conf()
 * - @man{exit(3)}
 */
extern int
enbox_run_conf(const struct enbox_conf * __restrict conf)
	__enbox_nonull(1) __warn_result;

/**
 * Load and instantiate an Enbox configuration from file content.
 *
 * Open, read and parse content of the file pointed to by @p path, then return a
 * pointer to an allocated Enbox configuration which may be later given to
 * enbox_run_conf() to apply the loaded configuration.
 *
 * Refer to @rstsubst{configuration} section for detailed informations about
 * configuration file syntax.
 *
 * Resources allocated for the instantiated Enbox configuration should be
 * released using enbox_destroy_conf() and / or @man{exit(3)}.
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
 * - @man{exit(3)}
 */
extern struct enbox_conf *
enbox_create_conf_from_file(const char * __restrict path)
	__enbox_nonull(1) __warn_result;

/**
 * Release configuration resources.
 *
 * Release Enbox configuration resources allocated by
 * enbox_create_conf_from_file().
 *
 * @note
 * May safely be called just before @man{exit(3)} in case a previous call to
 * enbox_run_conf() has failed.
 *
 * @param[in] conf Pointer to configuration to destroy.
 *
 * @see
 * - #enbox_conf
 * - enbox_create_conf_from_file()
 * - enbox_run_conf()
 * - @man{exit(3)}
 */
void
enbox_destroy_conf(struct enbox_conf * __restrict conf) __enbox_nonull(1);

struct elog;

/**
 * Initialize Enbox library.
 *
 * May alter calling process *dumpable* attribute according to
 * CONFIG_ENBOX_DISABLE_DUMP build option.
 *
 * When @p logger is passed as a `NULL` pointer, Enbox disables the logging of
 * all diagnostic messages.
 *
 *
 * @warning
 * MUST be called prior to every other Enbox library function calls.
 *
 * @param[in] logger an optional initialized Elog logger instance.
 */
extern void
enbox_setup(struct elog * __restrict logger)
	__enbox_nothrow;

#endif /* _ENBOX_H */
