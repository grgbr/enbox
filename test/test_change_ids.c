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
"Usage: %1$s [OPTIONS] <USER> [CAPS...]\n" \
"Test Enbox change IDs logic.\n" \
"\n" \
"With OPTIONS:\n" \
"    -h|--help -- this help message\n" \
"Where:\n" \
"    USER -- a login user name\n" \
"    CAPS -- a whitspace separated list of system capabilities"

static
void
usage(void)
{
	fprintf(stderr, USAGE "\n", program_invocation_short_name);
}

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
enbox_parse_cap(const char * __restrict arg)
{
	unsigned int c;

	for (c = 0; c < stroll_array_nr(capabilities); c++)
		if (!strcmp(arg, capabilities[c]))
			return (int)c;

	return -ENOENT;
}

int main(int argc, char * const argv[])
{
	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	int                                 ret = EXIT_FAILURE;
	const char *                        user;
	const struct passwd *               pwd;
	unsigned int                        a;
	uint64_t                            caps = 0;

	elog_init_stdio(&log, &cfg);

	if (argc < 2) {
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

	pwd = upwd_get_user_byname(user);
	if (!pwd) {
		dolog("unknown '%s' user.", user);
		goto out;
	}

	for (a = 2; a < argc; a++) {
		int c;

		c = enbox_parse_cap(argv[a]);
		if (c < 0) {
			dolog("unknown '%s' capability.", argv[a]);
			goto out;
		}

		caps |= enbox_cap(c);
	}

	enbox_setup((struct elog *)&log);

	if (pwd->pw_uid != enbox_get_uid()) {
		if (enbox_change_ids(pwd, ENBOX_RAISE_SUPP_GROUPS, caps)) {
		    dolog("failed to change IDs.");
		    goto out;
		}
	}
	else
		enbox_ensure_safe(caps);

	enbox_print_priv(stdout);

	ret = EXIT_SUCCESS;

out:
	elog_fini_stdio(&log);

	return ret;
}
