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
