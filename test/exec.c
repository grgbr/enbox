#define _GNU_SOURCE
#include <stdio.h>
#include <enbox/enbox.h>
#include <elog/elog.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static struct elog_stdio log;

#define dolog(_format, ...) \
	elog_log(&log.super, \
	         ELOG_CURRENT_SEVERITY, \
	         _format "\n", \
	         ## __VA_ARGS__)

#define USAGE \
"Usage: %1$s [OPTIONS] <USER>\n" \
"Test Enbox execve logic.\n" \
"\n" \
"With OPTIONS:\n" \
"    --caps=CAPS -- tries to preserve the CAPS list of capabilities across execve()\n" \
"    -h|--help   -- this help message\n" \
"Where:\n" \
"    CAPS -- a comma separated list of system capabilities\n"

int main(int argc, char * const argv[], char * const envp[])
{
	assert(argc >= 1);

	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	int                                 ret = EXIT_FAILURE;
	int                                 err;
	char *                              args[argc];
	const struct passwd *               pwd;

	elog_init_stdio(&log, &cfg);

	enbox_setup((struct elog *)&log);

	if (argc <= 1) {
		enbox_print_status(stdout);
		ret = EXIT_SUCCESS;
		goto out;
	}

	args[0] = argv[0];
	if (argc > 2)
		memcpy(&args[1], &argv[2], (argc - 2) * sizeof(argv[0]));
	args[argc - 1] = NULL;

	if (!strcmp(argv[1], "exec")) {
		dolog("execv'ing '%s'...", argv[1]);
		err = enbox_execve(argv[0],
		                   args,
		                   envp,
		                   ENBOX_CAP(CAP_DAC_OVERRIDE) |
		                   ENBOX_CAP(CAP_SETUID) |
		                   ENBOX_CAP(CAP_SETGID) |
		                   ENBOX_CAP(CAP_SYSLOG));
		goto err;
	}

	pwd = upwd_get_user_byname(argv[1]);
	if (pwd) {
		dolog("change IDs and execv'ing '%s'...", argv[1]);
		err = enbox_switch_ids(pwd, ENBOX_RAISE_SUPP_GROUPS);
		if (err)
			goto out;
	}
	else
		dolog("execv'ing '%s'...", argv[1]);

	execv(argv[0], args);
	err = -errno;

err:
	dolog("execution failed: %s (%d).", strerror(-err), -err);
out:
	elog_fini_stdio(&log);

	return ret;
}
