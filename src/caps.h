/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_CAPS_H
#define _ENBOX_CAPS_H

#include "common.h"
#include <linux/version.h>
#include <linux/securebits.h>

/* Support for Linux capability v3 only (Linux 2.6.26 and after). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#error No support for Linux kernel version below 2.6.26 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
#if VFS_CAP_U32 != VFS_CAP_U32_3
#error Unexpected VFS_CAP_U32 found into <linux/capability.h> header. \
       Check your Linux kernel revision is compatible with Enbox...
#endif /* VFS_CAP_U32 != VFS_CAP_U32_3 */

/*
 * Expect support for CAP_BLOCK_SUSPEND capability shipped with Linux
 * 3.5.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#error No support for Linux kernel version below 3.5 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,9) */
#if !defined(CAP_BLOCK_SUSPEND) || defined(CAP_EPOLLWAKEUP)
#error Unexpected deprecated CAP_EPOLLWAKEUP found into <linux/capability.h> \
       header. Check your Linux kernel revision is compatible with Enbox...
#endif

/*
 * Expect support for CAP_CHECKPOINT_RESTORE capability shipped with Linux
 * 5.9...
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
#error No support for Linux kernel version below 5.9 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,9) */
#if !defined(CAP_CHECKPOINT_RESTORE)
#error CAP_CHECKPOINT_RESTORE not found into <linux/capability.h> header. \
       Check your Linux kernel revision is compatible with Enbox...
#endif

/*
 * Ensure that the kernel does not define capabilities Enbox is not aware of.
 */
#if CAP_LAST_CAP != CAP_CHECKPOINT_RESTORE
#error Unexpected additional capability found into <linux/capability.h> \
       header. Check your Linux kernel revision is compatible with Enbox...
#endif /* CAP_LAST_CAP != CAP_CHECKPOINT_RESTORE */

/* Maximum number of supported system capabilities. */
#define ENBOX_CAPS_NR \
	(CAP_LAST_CAP + 1)

/*
 * Mask of capabilities that system supports.
 */
#define ENBOX_CAPS_VALID \
	((UINT64_C(1) << ENBOX_CAPS_NR) - 1)

/*
 * Mask of capabilities that Enbox refuses to propagate across setresuid(2) and
 * execve(2).
 */
#define ENBOX_CAPS_REJECTED \
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SYS_ADMIN))

/*
 * Mask of capabilities that Enbox allows to propagate across setresuid(2) and
 * execve(2).
 */
#define ENBOX_CAPS_ALLOWED \
	(ENBOX_CAPS_VALID & ~ENBOX_CAPS_REJECTED)

#if defined(CONFIG_ENBOX_SHOW)
#define __enbox_export_caps
#else  /* !defined(CONFIG_ENBOX_SHOW) */
#define __enbox_export_caps __export_intern
#endif /* defined(CONFIG_ENBOX_SHOW) */

extern const struct enbox_flag_desc enbox_caps_descs[] __enbox_export_caps;

/**
 * @internal
 *
 * An opaque structure holding internal capability state.
 */
struct enbox_caps {
	struct __user_cap_data_struct data[VFS_CAP_U32];
};

#if defined(CONFIG_ENBOX_SHOW)

extern int
enbox_load_secbits(void)
	__enbox_nothrow __leaf __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_SHOW) */

extern int
enbox_save_secbits(int secbits)
	__enbox_nothrow __leaf __export_intern;

#if defined(CONFIG_ENBOX_SHOW)

extern bool
enbox_load_nonewprivs(void)
	__enbox_nothrow __leaf __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_SHOW) */


extern void
enbox_enable_nonewprivs(void)
	__enbox_nothrow __leaf __export_intern;

extern int
enbox_enable_keep_caps(bool on)
	__enbox_nothrow __leaf __warn_result __export_intern;

#if defined(CONFIG_ENBOX_SHOW)

extern uint64_t
enbox_load_amb_caps(void)
	__enbox_nothrow __leaf __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_SHOW) */

extern int
enbox_save_amb_caps(uint64_t ambient)
	__enbox_nothrow __leaf __warn_result __export_intern;

/**
 * @internal
 *
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
enbox_clear_amb_caps(void) __enbox_nothrow __leaf __export_intern;

#if defined(CONFIG_ENBOX_SHOW)

extern uint64_t
enbox_load_bound_caps(void)
	__enbox_nothrow __leaf __warn_result __export_intern;

#endif /* defined(CONFIG_ENBOX_SHOW) */

/**
 * @internal
 *
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
	__enbox_nothrow  __leaf __warn_result __export_intern;

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
uint64_t
enbox_get_eff_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].effective) << 32) |
	       (uint64_t)caps->data[0].effective;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_have_eff_caps(const struct enbox_caps * __restrict caps,
                    int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_eff_caps(caps) & enbox_cap(id));
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
uint64_t
enbox_get_perm_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].permitted) << 32) |
	       (uint64_t)caps->data[0].permitted;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_have_perm_caps(const struct enbox_caps * __restrict caps,
                     int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_perm_caps(caps) & enbox_cap(id));
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
uint64_t
enbox_get_inh_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].inheritable) << 32) |
	       (uint64_t)caps->data[0].inheritable;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_have_inh_caps(const struct enbox_caps * __restrict caps,
                    int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_inh_caps(caps) & enbox_cap(id));
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_set_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].effective = (uint32_t)
	                          (effective & (UINT64_C(0xffffffff)));
	caps->data[1].effective = (uint32_t)(effective >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_eff_caps(caps, enbox_get_eff_caps(caps) | effective);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_eff_caps(caps, enbox_get_eff_caps(caps) & ~effective);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_set_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].permitted = (uint32_t)
	                          (permitted & (UINT64_C(0xffffffff)));
	caps->data[1].permitted = (uint32_t)(permitted >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_perm_caps(caps, enbox_get_perm_caps(caps) | permitted);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_perm_caps(caps, enbox_get_perm_caps(caps) & ~permitted);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_set_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].inheritable = (uint32_t)
	                            (inheritable & (UINT64_C(0xffffffff)));
	caps->data[1].inheritable = (uint32_t)(inheritable >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_inh_caps(caps, enbox_get_inh_caps(caps) | inheritable);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_inh_caps(caps, enbox_get_inh_caps(caps) & ~inheritable);
}

extern void
enbox_load_epi_caps(struct enbox_caps * __restrict caps)
	__enbox_nonull(1) __leaf __export_intern;

extern int
_enbox_save_epi_caps(struct enbox_caps * __restrict caps)
	__enbox_nonull(1) __leaf __warn_result __export_intern;

extern int
enbox_save_epi_caps(struct enbox_caps * __restrict caps)
	__enbox_nonull(1) __warn_result __export_intern;

/**
 * @internal
 *
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
enbox_clear_epi_caps(void) __export_intern;


#endif /* _ENBOX_CAPS_H */
