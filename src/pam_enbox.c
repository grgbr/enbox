/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of Enbox.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "conf.h"
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include <elog/elog.h>
#include <stdlib.h>
#include <sched.h>
#include <utils/path.h>

#define ENBOX_CONF_OPT "conf="

static struct elog_syslog      pam_enbox_log;
static struct elog_syslog_conf pam_elog_conf = {
	.super.severity = ELOG_WARNING_SEVERITY,
	.format         = ELOG_TAG_FMT | ELOG_PID_FMT,
	.facility       = LOG_AUTHPRIV
};

/* Make sure to honor the `no_warn' module option. */
#define pam_syslog_notice(_pamh, _format, ...) \
	({ \
		if (pam_elog_conf.super.severity >= ELOG_WARNING_SEVERITY) \
			pam_syslog(_pamh, \
			           LOG_NOTICE, \
			           _format, \
			           ## __VA_ARGS__); \
	 })

static
int
pam_parse_enbox(const pam_handle_t * pamh,
                int                  argc,
                const char **        argv,
                const char **        pathname)
{
	int          a;
	const char * path = NULL;

	for (a = 0; a < argc; a++) {
		if (!strncmp(argv[a],
		             ENBOX_CONF_OPT,
		             sizeof(ENBOX_CONF_OPT) - 1))
			path = argv[a] + sizeof(ENBOX_CONF_OPT) - 1;
		else if (!strcmp(argv[a], "no_warn"))
			pam_elog_conf.super.severity = ELOG_ERR_SEVERITY;
#if defined(CONFIG_ENBOX_DEBUG)
		else if (!strcmp(argv[a], "debug"))
			pam_elog_conf.super.severity = ELOG_DEBUG_SEVERITY;
#endif /* defined(CONFIG_ENBOX_DEBUG) */
		else if (strcmp(argv[a], "expose_account"))
			pam_syslog(pamh,
			           LOG_ERR,
			           "Unknown option '%s'",
			           argv[a]);
	}

	if (!path) {
		pam_syslog(pamh, LOG_ERR, "Missing configuration pathname");
		return PAM_ABORT;
	}
	else if (upath_validate_path_name(path) < 0) {
		pam_syslog(pamh, LOG_ERR, "Invalid configuration pathname");
		return PAM_ABORT;
	}

	*pathname = path;

	return PAM_SUCCESS;
}

static
int
pam_setup_enbox(const pam_handle_t * pamh)
{
	const char * svc;
	char *       tag;

	if (pam_get_item(pamh, PAM_SERVICE, (const void **)&svc) != PAM_SUCCESS)
		svc = "<unknown>";

	if (asprintf(&tag, "pam_enbox(%s:session)", svc) < 0) {
		pam_syslog(pamh, LOG_CRIT, "Cannot allocate memory");
		return PAM_BUF_ERR;
	}
	elog_setup(tag, ELOG_DFLT_PID);
	free(tag);

	elog_init_syslog(&pam_enbox_log, &pam_elog_conf);

	enbox_setup((struct elog *)&pam_enbox_log);

	return PAM_SUCCESS;
}

static
void
pam_fini_enbox(void)
{

	elog_fini_syslog(&pam_enbox_log);
}

static
int
pam_get_gid(pam_handle_t * pamh, gid_t * gid)
{
	int             err;
	const char *    user;
	struct passwd * pwd;

	err = pam_get_user(pamh, &user, NULL);
	if (err != PAM_SUCCESS) {
		pam_syslog_notice(pamh,
		                  "Cannot determine user name: %s",
		                  pam_strerror(pamh, err));
		return PAM_USER_UNKNOWN;
	}

	pwd = pam_modutil_getpwnam(pamh, user);
	if (!pwd) {
		pam_syslog_notice(pamh, "Unknown user %s", user);
		return PAM_USER_UNKNOWN;
	}

	*gid = pwd->pw_gid;

	return PAM_SUCCESS;
}

int
pam_sm_open_session(pam_handle_t * pamh,
                    int            flags __unused,
                    int            argc,
                    const char **  argv)
{
	int                   ret;
	const char *          path;
	struct enbox_pam_conf conf;
	gid_t                 gid;

	ret = pam_parse_enbox(pamh, argc, argv, &path);
	if (ret != PAM_SUCCESS)
		return PAM_SESSION_ERR;

	ret = pam_setup_enbox(pamh);
	if (ret != PAM_SUCCESS)
		return PAM_SESSION_ERR;

	ret = enbox_load_pam_conf_file(&conf, path);
	if (ret) {
		pam_syslog(pamh,
		           LOG_ALERT,
		           "Invalid configuration: %s",
		           strerror(-ret));
		ret = PAM_SESSION_ERR;
		goto fini;
	}

	ret = pam_get_gid(pamh, &gid);
	if (ret != PAM_SUCCESS) {
		ret = PAM_SESSION_ERR;
		goto unload;
	}

	ret = enbox_run_pam_conf(&conf, gid);
	if (ret) {
		pam_syslog(pamh,
		           LOG_CRIT,
		           "Cannot instantiate container: %s",
		           strerror(-ret));
		ret = PAM_SESSION_ERR;
		goto unload;
	}

	ret = PAM_SUCCESS;

unload:
	enbox_unload_pam_conf(&conf);
fini:
	pam_fini_enbox();

	return ret;
}

int
pam_sm_close_session(pam_handle_t * pamh __unused,
                     int            flags __unused,
                     int            argc __unused,
                     const char **  argv __unused)
{
	return PAM_SUCCESS;
}
