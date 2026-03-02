/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "caps.h"
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>

#if defined(CONFIG_ENBOX_VERBOSE)

struct elog * enbox_logger __unused;

__elog_nonull(1, 3) __printf(3, 4) __nothrow __unused
void
elog_log(struct elog * __restrict logger __unused,
         enum elog_severity       severity __unused,
         const char * __restrict  format __unused,
         ...)
{
}

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

#if defined(CONFIG_ENBOX_SECCOMP_AUDIT)
#include <linux/seccomp.h>  /* Definition of SECCOMP_* constants */
#include <linux/filter.h>   /* Definition of struct sock_fprog */
#include <linux/audit.h>    /* Definition of AUDIT_* constants */
#include <sys/ptrace.h>     /* Definition of PTRACE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>
#include <sys/prctl.h>

static const struct sock_filter preauth_insns[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_LOG),
};

static const struct sock_fprog preauth_program = {
	.len = (unsigned short)(sizeof(preauth_insns)/sizeof(preauth_insns[0])),
	.filter = (struct sock_filter *)preauth_insns,
};

static __ctor(65535)
void
enbox_seccomp_init(void)
{
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &preauth_program);
}
#endif /* defined(CONFIG_ENBOX_SECCOMP_AUDIT) */

#define ENBOX_KEEP_INH_CAPS_MAX (8U)

#define ENBOX_KEEP_INH_CAPS_STR_SIZE \
	(sizeof(STROLL_STRING(ENBOX_KEEP_INH_CAPS_MAX)) - 1)

static __ctor()
void
enbox_postproc_init(void)
{
	char * keep;
	int    ret;

	keep = secure_getenv("ENBOX_KEEP_INH_CAPS");
	if (keep && (keep[0] != '\0')) {
		unsigned long cnt;
		char *        err;

		cnt = strtoul(keep, &err, 0);
		if ((*err == '\0') && cnt && (cnt <= ENBOX_KEEP_INH_CAPS_MAX)) {
			char str[ENBOX_KEEP_INH_CAPS_STR_SIZE];

			if (!--cnt)
				goto unset;

			ret = snprintf(str, sizeof(str), "%lu", cnt);
			if ((ret > 0) && ((size_t)ret < sizeof(str))) {
				ret = setenv("ENBOX_KEEP_INH_CAPS", str, 1);
				if (!ret)
					return;
			}

			enbox_assert(errno != EINVAL);
			exit(EX_OSERR);
		}
	}

	enbox_clear_inh_caps();

unset:
	ret = unsetenv("ENBOX_KEEP_INH_CAPS");
	enbox_assert(!ret);
}
