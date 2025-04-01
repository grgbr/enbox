/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "priv.h"
#include "caps.h"
#include <unistd.h>
#include <sys/prctl.h>

#if defined(CONFIG_ENBOX_SHOW)

/*
 * Get the "dumpable" attribute for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_DUMPABLE(2const) and capabilities(7).
 */
bool
enbox_load_dump(void)
{
	int ret;

	ret = prctl(PR_GET_DUMPABLE);
	enbox_assert(ret >= 0);

	return !!ret;
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

#if defined(CONFIG_ENBOX_DISABLE_DUMP)

/**
 * @internal
 *
 * Setup current process *dumpable* attribute.
 *
 * Enable or disable generation of coredumps for current process.
 * In addition, attaching to the process via @man{ptrace(2)} PTRACE_ATTACH is
 * restricted according to multiple logics introduced below.
 *
 * As stated into section «PR_SET_DUMPABLE» of @man{prctl(2)}, the *dumpable*
 * attribute is normally set to 1. However, it is reset to the current value
 * contained in the file `/proc/sys/fs/suid_dumpable` (which defaults to value
 * 0), in the following circumstances:
 * - current process EUID or EGID is changed ;
 * - current process FSUID or FSGID is changed ;
 * - current process @man{execve(2)} a SUID / SGID program incurring a EUID /
 *   EGID change ;
 * - current process @man{execve(2)} a program that has file capabilities
 *   exceeding those already permitted.
 * The `/proc/sys/fs/suid_dumpable` file is documented into @man{proc(5)}.
 *
 * As stated in @man{ptrace(2)}, Linux kernel performs so-called "ptrace access
 * mode" checks whose outcome determines whether @man{ptrace(2)} operations are
 * permitted in addition to `CAP_SYS_PTRACE` capability and Linux Security
 * Module ptrace access checks.
 * See section «Ptrace access mode checking» of @man{ptrace(2)} for more
 * informations.
 *
 * Finally, the [Yama] Linux Security Module may further restrict
 * @man{ptrace(2)} operations thanks to the runtime controllable sysctl
 * `/proc/sys/kernel/yama`.
 * See «PR_SET_PTRACER» section in @man{prctl(2)} and [Yama] section in
 * [The Linux kernel user’s and administrator’s guide].
 *
 * @param[in] on Enable coredumps generation if `true`, disable it otherwise.
 *
 * @see
 * - #ENBOX_ENABLE_DUMP
 * - #ENBOX_DISABLE_DUMP
 * - enbox_setup()
 *
 * [The Linux kernel user’s and administrator’s guide]: https://www.kernel.org/doc/html/latest/admin-guide/index.html
 * [Yama]:                                              https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html
 */
void
enbox_setup_dump(bool on)
{
	enbox_assert_setup();

	int err __unused;

	err = prctl(PR_SET_DUMPABLE, (int)on, 0, 0, 0);
	enbox_assert(!err);
}

#endif /* defined(CONFIG_ENBOX_DISABLE_DUMP) */

/*
 * Require the CAP_SETUID capability.
 */
static __nothrow __warn_result
int
enbox_change_uid(uid_t uid)
{
	if (!setresuid(uid, uid, uid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static __nothrow __warn_result
int
enbox_change_gid(gid_t gid)
{
	if (!setresgid(gid, gid, gid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static __enbox_nothrow __warn_result
int
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
static __enbox_nonull(1)
int
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

	err = (int)upwd_validate_user_name(pwd->pw_name);
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

int
enbox_switch_ids(const struct passwd * __restrict pwd_entry, bool drop_supp)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, false));

	int err;

	err = enbox_change_gid(pwd_entry->pw_gid);
	if (err) {
		enbox_info("cannot switch to GID %hu(%s): %s (%d)",
		           pwd_entry->pw_gid,
		           enbox_get_group_name(pwd_entry->pw_gid),
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_gid = pwd_entry->pw_gid;

	if (drop_supp)
		err = enbox_drop_supp_groups();
	else
		err = enbox_raise_supp_groups(pwd_entry->pw_name,
		                              pwd_entry->pw_gid);
	if (err) {
		enbox_info("cannot setup %d(%s) users's supplementary groups: "
		           "%s (%d)",
		           pwd_entry->pw_uid,
		           pwd_entry->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	err = enbox_change_uid(pwd_entry->pw_uid);
	if (err) {
		enbox_info("cannot switch to UID %d(%s): %s (%d)",
		           pwd_entry->pw_uid,
		           pwd_entry->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_uid = pwd_entry->pw_uid;

	return 0;
}

/* The set of capabilities required to perform a change of UIDs / * GIDs... */
#define ENBOX_CAPS_CHIDS_MASK \
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SETUID) | ENBOX_CAP(CAP_SETGID))

/* Securebits used to perform a change of UIDs / GIDs... */
#define ENBOX_CAPS_SECBITS \
	(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | \
	 SECBIT_KEEP_CAPS_LOCKED | \
	 SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

int
enbox_change_ids(const struct passwd * __restrict pwd_entry,
                 bool                             drop_supp,
                 uint64_t                         kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, false));
	enbox_assert(pwd_entry->pw_uid != enbox_uid);
	enbox_assert(kept_caps & (ENBOX_CAPS_VALID | ENBOX_CAPS_CHIDS_MASK));

	struct enbox_caps caps;
	int               err;

	enbox_enable_nonewprivs();

	/*
	 * Make sure we can modify :
	 * - capabilities (at least, to clear the bounding set),
	 * - and change UIDs / GIDs.
	 * Also make sure `kept_caps' are added to the permitted set so that we
	 * may enable them after the change IDs operation.
	 */
	enbox_set_eff_caps(&caps, ENBOX_CAPS_CHIDS_MASK);
	enbox_set_perm_caps(&caps, ENBOX_CAPS_CHIDS_MASK | kept_caps);
	enbox_set_inh_caps(&caps, 0);
	err = enbox_save_epi_caps(&caps);
	if (err)
		goto err;

	/*
	 * Clear entire capability bounding set: we do require none of them
	 * since the targeted use case is not meant calling execve(2) and we
	 * want to inhibit file capabilities.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	if (kept_caps) {
		/*
		 * When capability preservation is required, enable the
		 * SECBIT_KEEP_CAPS flag to preserve capabilities set into the
		 * permitted set after the IDs switch.
		 */
		err = enbox_enable_keep_caps(true);
		if (err)
			goto err;

		/*
		 * Do the actual change IDs: the effective capability set will
		 * have been cleared on return from enbox_switch_ids().
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;

		/*
		 * Re-enable the CAP_SETPCAP capability into the effective set
		 * to complete secure bits configuration below.
		 */
		enbox_set_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
		err = enbox_save_epi_caps(&caps);
		if (err)
			goto err;

		/* Lock securebits in a fully restrictive state. */
		err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
		if (err)
			goto err;
	}
	else {
		/*
		 * Short path when there is no need to keep capabilities across
		 * change IDs.
		 */

		/* Lock securebits in a fully restrictive state. */
		err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
		if (err)
			goto err;

		/*
		 * Do the actual change IDs: the effective capability set will
		 * have been cleared on return from enbox_switch_ids().
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;
	}

	/*
	 * Finally, set final requested capabilities.
	 *
	 * Note that event when `kept_caps' is zero, this step should always be
	 * done. Indeed, when swiching from non zero UID(s), there is no
	 * guarantee that effective and permitted sets are properly cleared on
	 * return from enbox_switch_ids().
	 *
	 * See section `Effect of user ID changes on capabilities' of
	 * capabilities(7).
	 */
	enbox_set_eff_caps(&caps, kept_caps);
	enbox_set_perm_caps(&caps, kept_caps);
	err = enbox_save_epi_caps(&caps);
	if (err)
		goto err;

	/*
	 * Just to be sure, clear all ambient capabilities: we do require none
	 * of them since the targeted use case is not meant to call execve(2).
	 */
	enbox_clear_amb_caps();

	return 0;

err:
	enbox_info("failed to change IDs: %s (%d)", strerror(-err), -err);

	return err;
}

static
int
enbox_execve_with_caps(struct enbox_caps * __restrict caps,
                       const char * __restrict        path,
                       char * const                   argv[__restrict_arr],
                       char * const                   envp[__restrict_arr],
                       uint64_t                       kept_caps)
{
	enbox_assert_setup();
	enbox_assert(caps);
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(kept_caps & (ENBOX_CAPS_VALID | ENBOX_CAPS_CHIDS_MASK));

	int err;

	/*
	 * Load capabilities to preserve across execve(2) into the inheritable
	 * set so that they may also be enabled into the ambient set.
	 * Indeed, as stated into capabilities(7):
	 *   -- The ambient capability set obeys the invariant that no
	 *      capability can ever be ambient if it is not both permitted and
	 *      inheritable.
	 * Note that to enable inheritable capabilities, these MUST also be
	 * enabled into bounding sets. Call to enbox_save_epi_caps() will return
	 * -EPERM otherwise...
	 */
	enbox_set_inh_caps(caps, kept_caps);
	err = enbox_save_epi_caps(caps);
	if (err)
		return err;

	/*
	 * Now setup ambient capabilities: these are preserved across execve(2)
	 * for non privileged processes.
	 * Ambient capabilities will be added to the permitted set and assigned
	 * to the effective set when execve(2) is called below.
	 */
	err = enbox_save_amb_caps(kept_caps);
	if (err)
		return err;

	/* Lock securebits in a fully restrictive state. */
	err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
	if (err)
		return err;

	/*
	 * Clear entire capability bounding set to inhibit file capabilities.
	 * As stated into capabilities(7):
	 *   -- Removing a capability from the bounding set does not remove it
	 *      from the thread's inheritable set. However it does prevent the
	 *      capability from being added back into the thread's inheritable
	 *      set in the future.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		return err;

	/*
	 * Finally jump into program given by arguments. Returning from
	 * execve(2) means failure...
	 */
	execve(path, argv, envp);
	err = -errno;
	enbox_assert(err);

	return err;
}

int
enbox_execve(const char * __restrict path,
             char * const            argv[__restrict_arr],
             char * const            envp[__restrict_arr],
             uint64_t                kept_caps)
{
	enbox_assert_setup();
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(kept_caps & ENBOX_CAPS_VALID);

	struct enbox_caps caps;
	int               err;

	enbox_enable_nonewprivs();

	/*
	 * Prepare capability sets for preservation across next execve(2).
	 * Basically, this means we must:
	 * - enable CAP_SETPCAP into the effective set for later bounding set
	 *   and securebits configuration ;
	 * - enable `kept_caps' capabilities into the permitted set for later
	 *   configuration of the ambient set.
	 * See enbox_execve_with_caps() for more details.
	 */
	enbox_load_epi_caps(&caps);
	enbox_raise_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
	enbox_raise_perm_caps(&caps, ENBOX_CAP(CAP_SETPCAP) | kept_caps);

	/* Complete capability configuration and call execve(2). */
	err = enbox_execve_with_caps(&caps, path, argv, envp, kept_caps);
	enbox_assert(err);

	enbox_info("failed to execute: %s (%d)", strerror(-err), -err);

	return err;
}

int
enbox_change_idsn_execve(const struct passwd * __restrict pwd_entry,
                         bool                             drop_supp,
                         const char * __restrict          path,
                         char * const                     argv[__restrict_arr],
                         char * const                     envp[__restrict_arr],
                         uint64_t                         kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, true));
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(kept_caps & ENBOX_CAPS_VALID);

	struct enbox_caps caps;
	uint64_t          eff;
	int               err;

	enbox_enable_nonewprivs();

	enbox_load_epi_caps(&caps);
	eff = enbox_get_eff_caps(&caps);

	if (pwd_entry->pw_uid != enbox_uid) {
		/*
		 * A change IDs is required before execve(2).
		 *
		 * Make sure we can modify :
		 * - capabilities (at least, to clear the bounding set),
		 * - and change UIDs / GIDs.
		 * Also make sure `kept_caps' are added to the permitted set so
		 * that we may enable them after the change IDs operation.
		 *
		 * Prepare capability sets for preservation across next change
		 * IDs and execve(2). Basically, this means we must:
		 * - enable CAP_SETUID and CAP_SETGID into the effective set to
		 *   perform successful change IDs operation ;
		 * - enable CAP_SETPCAP into the effective set for later
		 *   bounding set and securebits configuration ;
		 * - make sure `kept_caps' are added to the permitted set so
		 *   that we may enable them after the change IDs operation.
		 * - cleanup inheritable set to make things deterministic (this
		 *   is not really required though).
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAPS_CHIDS_MASK);
		enbox_raise_perm_caps(&caps,
		                      ENBOX_CAPS_CHIDS_MASK | kept_caps);
		enbox_set_inh_caps(&caps, 0);
		err = enbox_save_epi_caps(&caps);
		if (err)
			goto err;

		/*
		 * Request system to preserve capabilities (into the permitted
		 * set) across change IDs operation.
		 */
		err = enbox_enable_keep_caps(true);
		if (err)
			goto err;

		/*
		 * Change user and group IDs.
		 * On return from enbox_switch_ids() / setresuid(2), effective
		 * and ambients sets will be cleared.
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;

		/*
		 * Re-enable CAP_SETPCAP into the effective set for later
		 * bounding set and securebits configuration.
		 * `kept_caps' capabilities have already been enabled into the
		 * permitted set above, allowing later configuration of the
		 * ambient set.
		 * See enbox_execve_with_caps() for more details.
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAP(CAP_SETPCAP));
	}
	else {
		/*
		 * No change IDs is required. Just prepare capability set for
		 * preservation across next execve(2). Basically, this means we
		 * must:
		 * - enable CAP_SETPCAP into the effective set for later
		 *   bounding set and securebits configuration ;
		 * - enable `kept_caps' capabilities into the permitted set for
		 *   later configuration of the ambient set.
		 * See enbox_execve_with_caps() for more details.
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAP(CAP_SETPCAP));
		enbox_raise_perm_caps(&caps,
		                      ENBOX_CAP(CAP_SETPCAP) | kept_caps);
	}

	/* Complete capability configuration and call execve(2). */
	err = enbox_execve_with_caps(&caps, path, argv, envp, kept_caps);
	enbox_assert(err);

err:
	enbox_info("failed to change IDs and execute: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_enforce_safe(uint64_t kept_caps)
{
	int               err;
	struct enbox_caps caps;

	enbox_enable_nonewprivs();

	err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
	if (err)
		goto err;

	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	enbox_clear_amb_caps();

	enbox_set_eff_caps(&caps, kept_caps);
	enbox_set_perm_caps(&caps, kept_caps);
	enbox_set_inh_caps(&caps, 0);
	err = enbox_save_epi_caps(&caps);
	if (err)
		goto err;

	return 0;

err:
	enbox_info("failed to enforce safe operations: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

void
enbox_ensure_safe(uint64_t kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	struct enbox_caps caps;
	int               err __unused;

	enbox_enable_nonewprivs();

	enbox_load_epi_caps(&caps);
	if (enbox_have_perm_caps(&caps, CAP_SETPCAP)) {

		/*
		 * Enable CAP_SETPCAP to clear bounding set and setup securebits
		 * below.
		 */
		if (!enbox_have_eff_caps(&caps, CAP_SETPCAP)) {
			enbox_raise_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
			err = _enbox_save_epi_caps(&caps);
			enbox_assert(!err);
		}

		/*
		 * This may fail when trying to modify a locked bit.
		 * However, since we just want to provide the caller with the
		 * safest environment we can, ignore errors.
		 */
		enbox_save_secbits(SECBIT_NOROOT |
		                   SECBIT_NO_CAP_AMBIENT_RAISE |
		                   SECURE_ALL_LOCKS);

		/*
		 * This should never fail thanks to the enabled SETPCAP
		 * capability...
		 */
		err = enbox_clear_bound_caps();
		enbox_assert(!err);
	}

	/*
	 * We would no want our children to acquire capabilities from the actual
	 * ambient set...
	 */
	enbox_clear_amb_caps();

	/* This should never fail since we only drop capabilities... */
	enbox_set_eff_caps(&caps, enbox_get_eff_caps(&caps) & kept_caps);
	enbox_set_perm_caps(&caps, enbox_get_perm_caps(&caps) & kept_caps);
	enbox_set_inh_caps(&caps, 0);
	err = _enbox_save_epi_caps(&caps);
	enbox_assert(!err);
}
