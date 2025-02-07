#define _GNU_SOURCE
#include <stdio.h>
#include <enbox/enbox.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, char * const argv[])
{
	int          err;
	unsigned int depth = 0;
	const char * msg;

	if (argc > 1) {
		err = 0 - ustr_parse_uint_range(argv[1], &depth, 0, 3);
		if (err) {
			msg = "invalid depth specified";
			goto err;
		}
	}

	enbox_setup(NULL);

	printf("#################### Security status for `%s %u' ####################\n",
	       program_invocation_short_name,
	       depth);
	enbox_print_status(stdout);

	if (depth > 0) {
		assert(depth > 0);
		assert(depth < 10);

		const char arg[2] = { '0' + depth - 1, '\0' };

		execl("/home/sigors/greg/devel/tidor/enbox-priv",
		      "/home/sigors/greg/devel/tidor/enbox-priv",
		      arg,
		      NULL);

		err = errno;
		msg = "failed to execute";
		goto err;
	}

	return EXIT_SUCCESS;

err:
	fprintf(stderr,
	        "%s: %s: %s (%d).\n",
	        program_invocation_short_name,
	        msg,
	        strerror(err),
	        err);

	return EXIT_FAILURE;
}


#if 0
int main(void)
{
	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	struct enbox_caps                   caps;

	elog_init_stdio(&log, &cfg);
	enbox_setup((struct elog *)&log);

	if (enbox_secure_execve(&caps,
	                        ENBOX_CAP(CAP_DAC_OVERRIDE) |
	                        ENBOX_CAP(CAP_SETUID) |
	                        ENBOX_CAP(CAP_SETGID) |
	                        ENBOX_CAP(CAP_SYSLOG)))
		return EXIT_FAILURE;

#define DEPTH 1
	printf("#################### Security status for `%s %u' ####################\n",
	       program_invocation_short_name,
	       DEPTH);
	enbox_print_status(stdout);

	execl("/home/sigors/greg/devel/tidor/enbox-priv",
	      "/home/sigors/greg/devel/tidor/enbox-priv",
	      STROLL_STRING(DEPTH),
	      NULL);
}
#endif
