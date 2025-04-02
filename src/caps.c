/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "caps.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

const struct enbox_flag_desc enbox_caps_descs[] = {
	/* Include generated capability descriptor definitions. */
#include "capabilities.i"
	{ NULL, }
};

#if defined(CONFIG_ENBOX_SHOW)

/*
 * Load and return secure bits for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_SECUREBITS(2const) and capabilities(7).
 */
int
enbox_load_secbits(void)
{
	int ret;

	ret = prctl(PR_GET_SECUREBITS);
	enbox_assert(!(ret & ~(SECURE_ALL_BITS | SECURE_ALL_LOCKS)));

	return ret;
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

/*
 * Modify and save secure bits for the current thread.
 *
 * Requires CAP_SETPCAP capability.
 *
 * Warning:
 * This function always clears the SECBIT_NO_SETUID_FIXUP bit and locks it !
 *
 * See PR_SET_SECUREBITS(2const) and capabilities(7).
 */
int
enbox_save_secbits(int secbits)
{
	enbox_assert(!(secbits & ~(SECURE_ALL_BITS | SECURE_ALL_LOCKS)));

	secbits = (secbits & ~SECBIT_NO_SETUID_FIXUP) |
	          SECBIT_NO_SETUID_FIXUP_LOCKED;

	if (prctl(PR_SET_SECUREBITS, (unsigned long)secbits)) {
		int err = errno;

		enbox_assert(err != EINVAL);

		enbox_info("cannot save secure bits: %s (%d)",
		           strerror(err),
		           err);

		return -err;
	}

	return 0;
}

/*
 * Set "keep capabilities" flag for the current thread.
 *
 * No particular capability is required for this operation. However, the
 * SECBIT_KEEP_CAPS_LOCKED secbit must not be set.
 *
 * See PR_SET_KEEPCAPS(2const) and capabilities(7).
 */
int
enbox_enable_keep_caps(bool on)
{
	if (prctl(PR_SET_KEEPCAPS, (long)on)) {
		int err = errno;

		enbox_assert(err != EINVAL);

		enbox_info("cannot setup keep capability flag: %s (%d)",
		           strerror(err),
		           err);

		return -err;
	}

	return 0;
}

#if defined(CONFIG_ENBOX_SHOW)

/*
 * Get the no_new_privs attribute for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_NO_NEW_PRIVS(2const) and capabilities(7).
 */
bool
enbox_load_nonewprivs(void)
{
	int ret;

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L);
	enbox_assert(ret >= 0);

	return !!ret;
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

/*
 * Set the no_new_privs attribute for the calling thread.
 *
 * With no_new_privs set to 1, execve(2) promises not to grant privileges to do
 * anything that could not have been done without the execve(2) call (for
 * example, rendering the set-user-ID and set- group-ID mode bits, and file
 * capabilities non-functional).
 *
 * No particular privileges is required to set this bit. Once set, it cannot be
 * unset.
 * The setting of this attribute is inherited by children created by fork(2) and
 * clone(2), and preserved across execve(2).
 *
 * See <linux>/Documentation/userspace-api/no_new_privs.rst
 */
void
enbox_enable_nonewprivs(void)
{
	int err __unused;

	err = prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
	enbox_assert(!err);
}

#if defined(CONFIG_ENBOX_SHOW)

/*
 * Get the ambient capability set for the current thread.
 *
 * No particular capability required to load this set.
 *
 * See PR_CAP_AMBIENT_IS_SET(2const), PR_CAP_AMBIENT(2const) and
 * capabilities(7).
 */
uint64_t
enbox_load_amb_caps(void)
{
	int      c;
	uint64_t caps = 0;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int ret;

		ret = prctl(PR_CAP_AMBIENT,
		            PR_CAP_AMBIENT_IS_SET,
		            (long)c,
		            0L,
		            0L);
		enbox_assert(ret >= 0);

		caps |= (uint64_t)(!!ret) << c;
	}

	return caps;
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

int
enbox_save_amb_caps(uint64_t ambient)
{
	enbox_assert(!(ambient & ~ENBOX_CAPS_VALID));

	int c;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int cmd = (ambient & enbox_cap(c)) ? PR_CAP_AMBIENT_RAISE
		                                   : PR_CAP_AMBIENT_LOWER;

		if (prctl(PR_CAP_AMBIENT, cmd, (long)c, 0L, 0L)) {
			int err = errno;

			enbox_info("cannot save ambient set capabilities: "
			           "%s (%d)",
			           strerror(err),
			           err);
			return -err;
		}
	}

	return 0;
}

/*
 * Clear the ambient capability set for the current thread.
 *
 * No particular privileges is required to perform this operation.
 *
 * See PR_CAP_AMBIENT_CLEAR_ALL(2const), PR_CAP_AMBIENT(2const) and
 * capabilities(7).
 */
void
enbox_clear_amb_caps(void)
{
	int ret __unused;

	ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	enbox_assert(!ret);
}

#if defined(CONFIG_ENBOX_SHOW)

/*
 * Get the bounding capability set for the current thread.
 *
 * No particular capability required to load this set.
 *
 * See PR_CAPBSET_READ(2const) and capabilities(7).
 */
uint64_t
enbox_load_bound_caps(void)
{
	int      c;
	uint64_t caps = 0;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int ret;

		ret = prctl(PR_CAPBSET_READ, (long)c);
		enbox_assert(ret >= 0);

		caps |= (uint64_t)(!!ret) << c;
	}

	return caps;
}

#endif /* defined(CONFIG_ENBOX_SHOW) */

int
enbox_clear_bound_caps(void)
{
	int c;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		if (prctl(PR_CAPBSET_DROP, (unsigned long)c, 0, 0, 0) < 0) {
			int err = errno;

			enbox_info("cannot clear bounding set capabilities: "
			           "%s (%d)",
			           strerror(err),
			           err);
			return -err;
		}
	}

	return 0;
}

/*
 * Get effective / permitted / inheritable capability sets for the current
 * thread.
 *
 * There is no glibc wrapper for this syscall...
 *
 * See capget(2) and syscall(2).
 */
static inline __enbox_nonull(1, 2) __warn_result
int
capget(cap_user_header_t header, cap_user_data_t data)
{
	return (int)syscall(SYS_capget, header, data);
}

void
enbox_load_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	/* Prepare capability sets header for the current thread. */
	int                             err __unused;
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid     = 0
	};

	err = capget(&hdr, caps->data);
	enbox_assert(!err);

	enbox_assert(hdr.version == _LINUX_CAPABILITY_VERSION_3);
}

/*
 * Set effective / permitted / inheritable capability sets for the current
 * thread.
 *
 * There is no glibc wrapper for this syscall...
 *
 * See capget(2) and syscall(2).
 */
static inline __enbox_nonull(1, 2) __warn_result
int
capset(cap_user_header_t header, const cap_user_data_t data)
{
	return (int)syscall(SYS_capset, header, data);
}

int
_enbox_save_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	/* Prepare capability sets header for the current thread. */
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid     = 0
	};

	if (capset(&hdr, caps->data)) {
		int err = errno;

		enbox_assert(err != EFAULT);
		enbox_assert(err != EINVAL);
		enbox_assert(err != ESRCH);

		return -err;
	}

	return 0;
}

int
enbox_save_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	int ret;

	ret = _enbox_save_epi_caps(caps);
	if (ret)
		enbox_info("cannot save capabilities: %s (%d)",
		           strerror(-ret),
		           -ret);

	return ret;
}

void
enbox_clear_epi_caps(void)
{
	struct enbox_caps caps;
	int               err __unused;

	memset(&caps, 0, sizeof(caps));

	/* This should never fail since we simply drop all capabilities... */
	err = _enbox_save_epi_caps(&caps);
	enbox_assert(!err);
}
