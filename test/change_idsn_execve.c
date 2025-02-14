#define _GNU_SOURCE
#include <stdio.h>
#include <enbox/enbox.h>
#include <elog/elog.h>
#include <utils/pwd.h>
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
"Usage: %1$s [OPTIONS] <USER> [CAPS...]\n" \
"Test Enbox change_idsn_execve logic.\n" \
"\n" \
"With OPTIONS:\n" \
"    -h|--help   -- this help message\n" \
"Where:\n" \
"    CAPS -- a list of system capabilities\n"

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

int main(int argc, char * const argv[], char * const envp[])
{
	assert(argc >= 1);

	static const struct elog_stdio_conf cfg = {
		.super.severity = ELOG_DEBUG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};
	const struct passwd *               pwd;
	unsigned int                        a;
	uint64_t                            caps = 0;
	int                                 ret = EXIT_FAILURE;
	int                                 err;
	char * const                        args[] = { argv[0], NULL };

	elog_init_stdio(&log, &cfg);

	enbox_setup((struct elog *)&log);

	if (argc <= 1) {
		enbox_print_status(stdout);
		ret = EXIT_SUCCESS;
		goto out;
	}

	if (argc < 2) {
		dolog("invalid number of arguments.");
		goto out;
	}

	pwd = upwd_get_user_byname(argv[1]);
	if (!pwd) {
		dolog("invalid user '%s' name.", argv[1]);
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

	err = enbox_change_idsn_execve(pwd,
	                               ENBOX_RAISE_SUPP_GROUPS,
	                               argv[0],
	                               args,
	                               NULL,
	                               caps);
	dolog("change_idsn_execve failed: %s (%d).", strerror(-err), -err);

out:
	elog_fini_stdio(&log);

	return ret;
}
