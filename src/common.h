/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ENBOX_COMMON_H
#define _ENBOX_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include "enbox/enbox.h"
#include <elog/elog.h>

extern struct elog * enbox_logger;

#define enbox_err(_format, ...) \
	do { \
		if (enbox_logger) \
			elog_err(enbox_logger, _format ".", ## __VA_ARGS__); \
	} while (0)

#if defined(CONFIG_ENBOX_VERBOSE)

#define enbox_info(_format, ...) \
	do { \
		if (enbox_logger) \
			elog_info(enbox_logger, _format ".", ## __VA_ARGS__); \
	} while (0)

#else /* !defined(CONFIG_ENBOX_VERBOSE) */

#define enbox_info(_format, ...) \
	do {} while (0)

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

struct enbox_flag_desc {
	const char *  kword;
	size_t        len;
	unsigned long value;
};

#define ENBOX_INIT_FLAG_DESC(_kword, _value) \
	{ \
		.kword = _kword, \
		.len =  sizeof(_kword) - 1, \
		.value = _value \
	}

#endif /* _ENBOX_COMMON_H */
