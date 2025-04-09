/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_SHOW_H
#define _ENBOX_SHOW_H

#include "common.h"

#if defined(CONFIG_ENBOX_SHOW)

#define ENBOX_MODE_STRING_SIZE (10U)

const char *
enbox_build_mode_string(char str[ENBOX_MODE_STRING_SIZE], mode_t mode)
	__enbox_nonull(1) __enbox_nothrow __leaf __returns_nonull;

#endif /* defined(CONFIG_ENBOX_SHOW) */

#endif /* _ENBOX_SHOW_H */
