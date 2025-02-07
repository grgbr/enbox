#define _GNU_SOURCE
#include <elog/elog.h>
#include <enbox/enbox.h>
#include <utils/pwd.h>
#include <stdlib.h>
#include <stdio.h>

static struct elog_stdio log;

#define dolog(_format, ...) \
	elog_log(&log.super, \
	         ELOG_CURRENT_SEVERITY, \
	         _format "\n", \
	         ## __VA_ARGS__)

#define USAGE \
"Usage: %1$s [OPTIONS] <USER>\n" \
"Test Enbox change IDs logic.\n" \
"\n" \
"With OPTIONS:\n" \
"    -h|--help -- this help message\n" \
"Where:\n" \
"    USER -- a login user name"

static
void
usage(void)
{
	fprintf(stderr, USAGE "\n", program_invocation_short_name);
}

int main(int argc, char * const argv[])
{
	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	int                                 ret = EXIT_FAILURE;
	const char *                        user;

	elog_init_stdio(&log, &cfg);

	if (argc != 2) {
		dolog("invalid number of argument.");
		usage();
		goto out;
	}

	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage();
		ret = EXIT_SUCCESS;
		goto out;
	}

	user = argv[1];
	if (upwd_validate_user_name(user) <= 0) {
	    dolog("invalid user name.");
	    goto out;
	}

	enbox_setup((struct elog *)&log);

	if (enbox_change_ids_byname(user,
	                            ENBOX_RAISE_SUPP_GROUPS,
	                            ENBOX_CAP(CAP_SYSLOG))) {
	    dolog("failed to change IDs.");
	    goto out;
	}

	enbox_print_status(stdout);

	ret = EXIT_SUCCESS;

out:
	elog_fini_stdio(&log);

	return ret;
}
