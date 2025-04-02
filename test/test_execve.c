#define _GNU_SOURCE
#include <enbox/enbox.h>
#include <elog/elog.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#define error(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format "\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

static struct elog_stdio log;

#define dolog(_format, ...) \
	elog_log(&log.super, \
	         ELOG_CURRENT_SEVERITY, \
	         _format "\n", \
	         ## __VA_ARGS__)

static const char * capabilities[] = {
	"chown",             /*  0 */
	"dac_override",
	"dac_read_search",
	"fowner",
	"fsetid",
	"kill",              /*  5 */
	"setgid",
	"setuid",
	"setpcap",
	"linux_immutable",
	"net_bind_service",  /* 10 */
	"net_broadcast",
	"net_admin",
	"net_raw",
	"ipc_lock",
	"ipc_owner",         /* 15 */
	"sys_module",
	"sys_rawio",
	"sys_chroot",
	"sys_ptrace",
	"sys_pacct",         /* 20 */
	"sys_admin",
	"sys_boot",
	"sys_nice",
	"sys_resource",
	"sys_time",          /* 25 */
	"sys_tty_config",
	"mknod",
	"lease",
	"audit_write",
	"audit_control",     /* 30 */
	"setfcap",
	"mac_override",
	"mac_admin",
	"syslog",
	"wake_alarm",        /* 35 */
	"block_suspend",
	"audit_read",
	"perfmon",
	"bpf",
	"checkpoint_restore" /* 40 */
};

static
int
parse_one_cap(const char * arg, uint64_t * cap)
{
	unsigned int c;

	for (c = 0; c < stroll_array_nr(capabilities); c++) {
		if (!strcmp(arg, capabilities[c])) {
			*cap |= UINT64_C(1) << c;
			return 0;
		}
	}

	error("invalid '%s' capability.\n", arg);

	return -EINVAL;
}

static
int
parse_caps(char * arg, uint64_t * caps)
{
	char * comma;

	comma = index(arg, ',');
	while (comma) {
		*comma = '\0';
		if (parse_one_cap(arg, caps))
			return -EINVAL;

		arg = comma + 1;
		comma = index(arg, ',');
	}

	return parse_one_cap(arg, caps);
}

#define USAGE \
"Usage: %1$s [OPTIONS] <CMD>\n" \
"Test Enbox execve logic.\n" \
"\n" \
"With OPTIONS:\n" \
"    --caps=CAPS -- tries to preserve the CAPS list of capabilities across\n" \
"                   execve()\n" \
"    -h|--help   -- this help message\n" \
"Where:\n" \
"    CMD  -- a command to give to enbox_execve()\n" \
"    CAPS -- a comma separated list of system capabilities"

static
void
usage(void)
{
	fprintf(stderr, USAGE "\n", program_invocation_short_name);
}

int main(int argc, char * const argv[], char * const envp[])
{
	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	int                                 ret = EXIT_FAILURE;
	int                                 err;
	const struct passwd *               pwd;
	uint64_t                            caps = 0;

	while (true) {
		int                        opt;
		static const struct option opts[] = {
			{ "caps", required_argument, NULL, 'c' },
			{ "help", no_argument,       NULL, 'h' },
			{ NULL,   0,                 NULL, -1 }
		};

		opt = getopt_long(argc, argv, ":h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'c':
			if (parse_caps(optarg, &caps))
				goto usage;
			break;

		case 'h':
			ret = EXIT_SUCCESS;
			goto usage;

		case ':':
			error("option '%s' requires an argument.\n",
			      argv[optind - 1]);
			goto usage;

		case '?':
			error("unrecognized option '%s'.\n", argv[optind - 1]);
			goto usage;

		default:
			error("unexpected option parsing error.\n");
			goto usage;
		}
	}

	argc -= optind;
	if (argc < 1) {
		error("invalid number of arguments.\n");
		goto usage;
	}
	argv = &argv[optind];

	elog_init_stdio(&log, &cfg);
	enbox_setup((struct elog *)&log);

	dolog("execv'ing '%s' with 0x%" PRIx64
	      " capability preservation mask...",
	      argv[0],
	      caps);
	err = enbox_execve(argv[0], argv, envp, caps);
	dolog("enbox_execve() failed: %s (%d).", strerror(-err), -err);

	elog_fini_stdio(&log);

	return EXIT_FAILURE;

usage:
	usage();

	return ret;
}
