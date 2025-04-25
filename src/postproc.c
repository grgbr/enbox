/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"

extern void enbox_postproc_init(void);

#define ENBOX_CAPS_NR \
	(CAP_LAST_CAP + 1)
#define ENBOX_CAPS_VALID \
	((UINT64_C(1) << ENBOX_CAPS_NR) - 1)
#define ENBOX_CAPS_REJECTED \
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SYS_ADMIN))
#define ENBOX_CAPS_ALLOWED \
	(ENBOX_CAPS_VALID & ~ENBOX_CAPS_REJECTED)

void
enbox_postproc_init(void)
{
	enbox_setup(NULL);
	enbox_ensure_safe(ENBOX_CAPS_ALLOWED);
}
