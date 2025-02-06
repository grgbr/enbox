#include "common.h"
#include <linux/securebits.h>
#include <linux/version.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdlib.h>

/* Support for Linux capability v3 only (Linux 2.6.26 and after). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#error No support for Linux kernel version below 2.6.26 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
#if VFS_CAP_U32 != VFS_CAP_U32_3
#error Unexpected VFS_CAP_U32 found into <linux/capability.h> header. \
       Check your Linux kernel revision is compatible with Enbox...
#endif /* VFS_CAP_U32 != VFS_CAP_U32_3 */

/*
 * Expect support for CAP_BLOCK_SUSPEND capability shipped with Linux
 * 3.5.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#error No support for Linux kernel version below 3.5 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,9) */
#if !defined(CAP_BLOCK_SUSPEND) || defined(CAP_EPOLLWAKEUP)
#error Unexpected deprecated CAP_EPOLLWAKEUP found into <linux/capability.h> \
       header. Check your Linux kernel revision is compatible with Enbox...
#endif

/*
 * Expect support for CAP_CHECKPOINT_RESTORE capability shipped with Linux
 * 5.9...
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
#error No support for Linux kernel version below 5.9 !
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,9) */
#if !defined(CAP_CHECKPOINT_RESTORE)
#error CAP_CHECKPOINT_RESTORE not found into <linux/capability.h> header. \
       Check your Linux kernel revision is compatible with Enbox...
#endif

/*
 * Ensure that the kernel does not define capabilities Enbox is not aware of.
 */
#if CAP_LAST_CAP != CAP_CHECKPOINT_RESTORE
#error Unexpected additional capability found into <linux/capability.h> \
       header. Check your Linux kernel revision is compatible with Enbox...
#endif /* CAP_LAST_CAP != CAP_CHECKPOINT_RESTORE */

#define ENBOX_CAPS_NR \
	(CAP_LAST_CAP + 1)

static inline __enbox_const __enbox_nothrow __warn_result
uint64_t
enbox_cap(int capability)
{
	enbox_assert(cap_valid(capability));

	return UINT64_C(1) << capability;
}

/*
 * Load and return secure bits for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_SECUREBITS(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
int
enbox_load_secbits(void)
{
	int ret;

	ret = prctl(PR_GET_SECUREBITS);
	enbox_assert(!(ret & ~(SECURE_ALL_BITS | SECURE_ALL_LOCKS)));

	return ret;
}

/*
 * Modify and save secure bits for the current thread.
 *
 * Requires CAP_SETPCAP capability.
 *
 * Warning:
 * This function always clears the SECBIT_NO_SETUID_FIXUP bit and locks it !
 *
 * See PR_SET_SECUREBITS(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
int
enbox_save_secbits(int secbits)
{
	enbox_assert(!(secbits & ~(SECURE_ALL_BITS | SECURE_ALL_LOCKS)));

	secbits = (secbits & ~SECBIT_NO_SETUID_FIXUP) |
	          SECBIT_NO_SETUID_FIXUP_LOCKED;

	if (prctl(PR_SET_SECUREBITS, (unsigned long)secbits)) {
		int err = errno;

		enbox_assert(err != EINVAL);

		enbox_info("cannot save secure bits: %s (%d)",
		           strerror(err),
		           err);

		return -err;
	}

	return 0;
}

/*
 * Set "keep capabilities" flag for the current thread.
 *
 * No particular capability is required for this operation. However, the
 * SECBIT_KEEP_CAPS_LOCKED secbit must not be set.
 *
 * See PR_SET_KEEPCAPS(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
int
enbox_enable_keep_caps(bool on)
{
	if (prctl(PR_SET_KEEPCAPS, (long)on)) {
		int err = errno;

		enbox_assert(err != EINVAL);

		enbox_info("cannot setup keep capability flag: %s (%d)",
		           strerror(err),
		           err);

		return -err;
	}

	return 0;
}

/*
 * Get the no_new_privs attribute for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_NO_NEW_PRIVS(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
bool
enbox_load_nonewprivs(void)
{
	int ret;

	ret = prctl(PR_GET_NO_NEW_PRIVS, 0L, 0L, 0L, 0L);
	enbox_assert(ret >= 0);

	return !!ret;
}

/*
 * Set the no_new_privs attribute for the calling thread.
 *
 * With no_new_privs set to 1, execve(2) promises not to grant privileges to do
 * anything that could not have been done without the execve(2) call (for
 * example, rendering the set-user-ID and set- group-ID mode bits, and file
 * capabilities non-functional).
 *
 * No particular privileges is required to set this bit. Once set, it cannot be
 * unset.
 * The setting of this attribute is inherited by children created by fork(2) and
 * clone(2), and preserved across execve(2).
 */
static __enbox_nothrow
void
enbox_enable_nonewprivs(void)
{
	int err __unused;

	err = prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
	enbox_assert(!err);
}

/*
 * Get the "dumpable" attribute for the current thread.
 *
 * No particular capability is required for this operation.
 *
 * See PR_GET_DUMPABLE(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
bool
enbox_load_dump(void)
{
	int ret;

	ret = prctl(PR_GET_DUMPABLE);
	enbox_assert(ret >= 0);

	return !!ret;
}

/*
 * Get the ambient capability set for the current thread.
 *
 * No particular capability required to load this set.
 *
 * See PR_CAP_AMBIENT_IS_SET(2const), PR_CAP_AMBIENT(2const) and
 * capabilities(7).
 */
static __enbox_nothrow __warn_result
uint64_t
enbox_load_amb_caps(void)
{
	int      c;
	uint64_t caps = 0;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int ret;

		ret = prctl(PR_CAP_AMBIENT,
		            PR_CAP_AMBIENT_IS_SET,
		            (long)c,
		            0L,
		            0L);
		enbox_assert(ret >= 0);

		caps |= (uint64_t)(!!ret) << c;
	}

	return caps;
}

/*
 * Clear the ambient capability set for the current thread.
 *
 * No particular privileges is required to perform this operation.
 *
 * See PR_CAP_AMBIENT_CLEAR_ALL(2const), PR_CAP_AMBIENT(2const) and
 * capabilities(7).
 */
void
enbox_clear_amb_caps(void)
{
	int ret;

	ret = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	enbox_assert(!ret);
}

static
int
enbox_raise_amb_cap(int cap)
{
	enbox_assert(cap_valid(cap));

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, (long)cap, 0, 0)) {
		int err = errno;

		enbox_assert(err != EINVAL);

		enbox_info("cannot raise ambient capability: %s (%d)",
		           strerror(err),
		           err);

		return -err;
	}

	return 0;
}

#include <stroll/bmap.h>

int
enbox_raise_amb_caps(uint64_t caps)
{
	enbox_assert(caps);
	enbox_assert(!(caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	uint64_t     iter;
	unsigned int c;
	int          ret = 0;

	stroll_bmap_foreach_set64(&iter, caps, &c) {
		enbox_assert(cap_valid(c));

		ret = enbox_raise_amb_cap(c);
		if (ret)
			break;
	}

	return ret;
}

/*
 * Get the bounding capability set for the current thread.
 *
 * No particular capability required to load this set.
 *
 * See PR_CAPBSET_READ(2const) and capabilities(7).
 */
static __enbox_nothrow __warn_result
uint64_t
enbox_load_bound_caps(void)
{
	int      c;
	uint64_t caps = 0;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int ret;

		ret = prctl(PR_CAPBSET_READ, (long)c);
		enbox_assert(ret >= 0);

		caps |= (uint64_t)(!!ret) << c;
	}

	return caps;
}

int
enbox_clear_bound_caps(void)
{
	int c;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		if (prctl(PR_CAPBSET_DROP, (unsigned long)c, 0, 0, 0) < 0) {
			int err = errno;

			enbox_info("cannot drop bounding set capabilities: "
			           "%s (%d)",
			           strerror(err),
			           err);
			return -err;
		}
	}

	return 0;
}

/*
 * Get effective / permitted / inheritable capability sets for the current
 * thread.
 *
 * There is no glibc wrapper for this syscall...
 *
 * See capget(2) and syscall(2).
 */
static inline __enbox_nonull(1, 2) __warn_result
int
capget(cap_user_header_t header, cap_user_data_t data)
{
	return syscall(SYS_capget, header, data);
}

static inline __enbox_nonull(1) __warn_result
uint64_t
enbox_caps_get_eff(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].effective) << 32) |
	       (uint64_t)caps->data[0].effective;
}

static inline __enbox_nonull(1) __warn_result
uint64_t
enbox_caps_get_perm(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].permitted) << 32) |
	       (uint64_t)caps->data[0].permitted;
}

static inline __enbox_nonull(1) __warn_result
uint64_t
enbox_caps_get_inh(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].inheritable) << 32) |
	       (uint64_t)caps->data[0].inheritable;
}

static __enbox_nonull(1)
void
enbox_load_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	/* Prepare capability sets header for the current thread. */
	int                             err __unused;
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid     = 0
	};

	err = capget(&hdr, caps->data);
	enbox_assert(!err);

	enbox_assert(hdr.version == _LINUX_CAPABILITY_VERSION_3);
}

/*
 * Set effective / permitted / inheritable capability sets for the current
 * thread.
 *
 * There is no glibc wrapper for this syscall...
 *
 * See capget(2) and syscall(2).
 */
static inline __enbox_nonull(1, 2) __warn_result
int
capset(cap_user_header_t header, const cap_user_data_t data)
{
	return syscall(SYS_capset, header, data);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_caps_set_eff(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].effective = (uint32_t)
	                          (effective & (UINT64_C(0xffffffff)));
	caps->data[1].effective = (uint32_t)(effective >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_caps_set_perm(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].permitted = (uint32_t)
	                          (permitted & (UINT64_C(0xffffffff)));
	caps->data[1].permitted = (uint32_t)(permitted >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_caps_set_inh(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].inheritable = (uint32_t)
	                            (inheritable & (UINT64_C(0xffffffff)));
	caps->data[1].inheritable = (uint32_t)(inheritable >> 32);
}

static inline __enbox_nonull(1) __warn_result
int
_enbox_save_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	/* Prepare capability sets header for the current thread. */
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid     = 0
	};

	if (capset(&hdr, caps->data)) {
		int err = errno;

		enbox_assert(err != EFAULT);
		enbox_assert(err != EINVAL);
		enbox_assert(err != ESRCH);

		return -err;
	}

	return 0;
}

static __enbox_nonull(1) __warn_result
int
enbox_save_epi_caps(struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	int ret;

	ret = _enbox_save_epi_caps(caps);
	if (ret)
		enbox_info("cannot save capabilities: %s (%d)",
		           strerror(-ret),
		           -ret);

	return ret;
}

int
enbox_clear_epi_caps(void)
{
	struct enbox_caps caps;
	int               ret;

	memset(&caps, 0, sizeof(caps));

	ret = _enbox_save_epi_caps(&caps);
	if (ret)
		enbox_info("cannot clear capabilities: %s (%d)",
		           strerror(-ret),
		           -ret);

	return ret;
}

#if defined(CONFIG_ENBOX_VERBOSE)

static const char * const enbox_caps_names[] = {
	[CAP_CHOWN]              = "chown",             /*  0 */
	[CAP_DAC_OVERRIDE]       = "dac_override",
	[CAP_DAC_READ_SEARCH]    = "dac_read_search",
	[CAP_FOWNER]             = "fowner",
	[CAP_FSETID]             = "fsetid",
	[CAP_KILL]               = "kill",              /*  5 */
	[CAP_SETGID]             = "setgid",
	[CAP_SETUID]             = "setuid",
	[CAP_SETPCAP]            = "setpcap",
	[CAP_LINUX_IMMUTABLE]    = "linux_immutable",
	[CAP_NET_BIND_SERVICE]   = "net_bind_service",  /* 10 */
	[CAP_NET_BROADCAST]      = "net_broadcast",
	[CAP_NET_ADMIN]          = "net_admin",
	[CAP_NET_RAW]            = "net_raw",
	[CAP_IPC_LOCK]           = "ipc_lock",
	[CAP_IPC_OWNER]          = "ipc_owner",         /* 15 */
	[CAP_SYS_MODULE]         = "sys_module",
	[CAP_SYS_RAWIO]          = "sys_rawio",
	[CAP_SYS_CHROOT]         = "sys_chroot",
	[CAP_SYS_PTRACE]         = "sys_ptrace",
	[CAP_SYS_PACCT]          = "sys_pacct",         /* 20 */
	[CAP_SYS_ADMIN]          = "sys_admin",
	[CAP_SYS_BOOT]           = "sys_boot",
	[CAP_SYS_NICE]           = "sys_nice",
	[CAP_SYS_RESOURCE]       = "sys_resource",
	[CAP_SYS_TIME]           = "sys_time",          /* 25 */
	[CAP_SYS_TTY_CONFIG]     = "sys_tty_config",
	[CAP_MKNOD]              = "mknod",
	[CAP_LEASE]              = "lease",
	[CAP_AUDIT_WRITE]        = "audit_write",
	[CAP_AUDIT_CONTROL]      = "audit_control",     /* 30 */
	[CAP_SETFCAP]            = "setfcap",
	[CAP_MAC_OVERRIDE]       = "mac_override",
	[CAP_MAC_ADMIN]          = "mac_admin",
	[CAP_SYSLOG]             = "syslog",
	[CAP_WAKE_ALARM]         = "wake_alarm",        /* 35 */
	[CAP_BLOCK_SUSPEND]      = "block_suspend",
	[CAP_AUDIT_READ]         = "audit_read",
	[CAP_PERFMON]            = "perfmon",
	[CAP_BPF]                = "bpf",
	[CAP_CHECKPOINT_RESTORE] = "checkpoint_restore" /* 40 */
};

static __enbox_nonull(1)
void
enbox_print_caps(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	struct enbox_caps caps;
	uint64_t          eff;
	uint64_t          perm;
	uint64_t          inh;
	uint64_t          amb;
	uint64_t          bound;
	unsigned int      c;

	enbox_load_epi_caps(&caps);
	eff = enbox_caps_get_eff(&caps);
	perm = enbox_caps_get_perm(&caps);
	inh = enbox_caps_get_inh(&caps);
	amb = enbox_load_amb_caps();
	bound = enbox_load_bound_caps();

	fprintf(stdio,
	        "CAPABILITY          PERMITTED  EFFECTIVE  INHERITABLE  AMBIENT  BOUNDING\n");

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		fprintf(stdio,
		        "%-18.18s         %s         %s           %s       %s        %s\n",
		        enbox_caps_names[c],
		        (perm & enbox_cap(c)) ? "on" : " .",
		        (eff & enbox_cap(c)) ? "on" : " .",
		        (inh & enbox_cap(c)) ? "on" : " .",
		        (amb & enbox_cap(c)) ? "on" : " .",
		        (bound & enbox_cap(c)) ? "on" : " .");
	}
}

static __enbox_nonull(1)
void
enbox_print_secbits(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	int bits;

	bits = enbox_load_secbits();

	fputs("SECUREBITS  NOROOT  NO_SETUID_FIXUP  KEEP_CAPS  NO_CAP_AMBIENT_RAISE  NO_NEW_PRIVS  DUMPABLE\n",
	      stdio);
	fprintf(stdio,
	        "state           %s               %s         %s                    %s            %s        %s\n",
	        (bits & SECBIT_NOROOT) ? "on" : " .",
	        (bits & SECBIT_NO_SETUID_FIXUP) ? "on" : " .",
	        (bits & SECBIT_KEEP_CAPS) ? "on" : " .",
	        (bits & SECBIT_NO_CAP_AMBIENT_RAISE) ? "on" : " .",
	        enbox_load_nonewprivs() ? "on" : " .",
	        enbox_load_dump() ? "on" : " .");
	fprintf(stdio,
	        "lock            %s               %s         %s                    %s            NA        NA\n",
	        (bits & SECBIT_NOROOT_LOCKED) ? "on" : " .",
	        (bits & SECBIT_NO_SETUID_FIXUP_LOCKED) ? "on" : " .",
	        (bits & SECBIT_KEEP_CAPS_LOCKED) ? "on" : " .",
	        (bits & SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED) ? "on" : " .");
}

static __enbox_nonull(1)
void
enbox_print_creds(FILE * __restrict stdio)
{
	enbox_assert(stdio);

	uid_t   ruid;
	uid_t   euid;
	uid_t   suid;
	gid_t   rgid;
	gid_t   egid;
	gid_t   sgid;
	gid_t * supp;
	int     g;
	int     ret;

	ret = getresuid(&ruid, &euid, &suid);
	enbox_assert(!ret);
	ret = getresgid(&rgid, &egid, &sgid);
	enbox_assert(!ret);

	fputs("CREDENTIALS         Real   Effective       Saved\n",
	      stdio);
	fprintf(stdio, "uid           %10d  %10d  %10d\n", ruid, euid, suid);
	fprintf(stdio, "gid           %10d  %10d  %10d\n", rgid, egid, sgid);

	supp = malloc(NGROUPS_MAX * sizeof(supp[0]));
	if (!supp)
		return;

	ret = getgroups(NGROUPS_MAX, supp);
	enbox_assert(ret >= 0);

	if (ret) {
		fputs(         "Supp. groups  ", stdio);
		fprintf(stdio, "%d", supp[0]);
		for (g = 1; g < ret; g++)
			fprintf(stdio, ", %d", supp[g]);
		putc('\n', stdio);
	}
	else
		fputs(         "Supp. groups  none\n", stdio);

	free(supp);
}

void
enbox_print_status(FILE * __restrict stdio)
{
	enbox_assert_setup();
	enbox_assert(stdio);

	enbox_print_caps(stdio);
	putc('\n', stdio);
	enbox_print_secbits(stdio);
	putc('\n', stdio);
	enbox_print_creds(stdio);
}

#endif /* defined(CONFIG_ENBOX_VERBOSE) */

/*
 * Require the CAP_SETUID capability.
 */
static __nothrow __warn_result
int
enbox_change_uid(uid_t uid)
{
	if (!setresuid(uid, uid, uid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static __nothrow __warn_result
int
enbox_change_gid(gid_t gid)
{
	if (!setresgid(gid, gid, gid))
		return 0;

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static __enbox_nothrow __warn_result
int
enbox_drop_supp_groups(void)
{
	if (!setgroups(0, NULL))
		return 0;

	enbox_assert(errno != EFAULT);
	enbox_assert(errno != EINVAL);

	return -errno;
}

/*
 * Require the CAP_SETGID capability.
 */
static __enbox_nonull(1)
int
enbox_raise_supp_groups(const char * user, gid_t gid)
{
	enbox_assert(upwd_validate_user_name(user) > 0);

	if (!initgroups(user, gid))
		return 0;

	return -errno;
}

int
enbox_validate_pwd(const struct passwd * __restrict pwd, bool allow_root)
{
	enbox_assert(pwd);

	int err;

	if ((pwd->pw_uid == (uid_t)-1) || (pwd->pw_gid == (gid_t)-1))
		return -ERANGE;

	if (!pwd->pw_name)
		return -EINVAL;

	err = upwd_validate_user_name(pwd->pw_name);
	if (err < 0)
		return err;

	if (!allow_root) {
		if (!strcmp(pwd->pw_name, "root") ||
		    !pwd->pw_uid ||
		    !pwd->pw_gid)
			return -EPERM;
	}

	return 0;
}

int
enbox_switch_ids(const struct passwd * __restrict pwd_entry, bool drop_supp)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, false));

	int err;

	err = enbox_change_gid(pwd_entry->pw_gid);
	if (err) {
		enbox_info("cannot switch to GID %hu(%s): %s (%d)",
		           pwd_entry->pw_gid,
		           enbox_get_group_name(pwd_entry->pw_gid),
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_gid = pwd_entry->pw_gid;

	if (drop_supp)
		err = enbox_drop_supp_groups();
	else
		err = enbox_raise_supp_groups(pwd_entry->pw_name,
		                              pwd_entry->pw_gid);
	if (err) {
		enbox_info("cannot setup %d(%s) users's supplementary groups: "
		           "%s (%d)",
		           pwd_entry->pw_uid,
		           pwd_entry->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	err = enbox_change_uid(pwd_entry->pw_uid);
	if (err) {
		enbox_info("cannot switch to UID %d(%s): %s (%d)",
		           pwd_entry->pw_uid,
		           pwd_entry->pw_name,
		           strerror(-err),
		           -err);
		return err;
	}

	enbox_uid = pwd_entry->pw_uid;

	return 0;
}

/* The set of capabilities required to perform a change of UIDs / * GIDs... */
#define ENBOX_CAPS_CHIDS_MASK \
	(ENBOX_CAP(CAP_SETUID) | ENBOX_CAP(CAP_SETGID))

/* Securebits used to perform a change of UIDs / * GIDs... */
#define ENBOX_CAPS_CHIDS_SECBITS \
	(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | \
	 SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

int
enbox_change_ids(const struct passwd * __restrict pwd_entry,
                 bool                             drop_supp,
                 struct enbox_caps * __restrict   caps)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, false));
	enbox_assert(pwd_entry->pw_uid);
	enbox_assert(pwd_entry->pw_uid != enbox_uid);
	enbox_assert(caps);
	enbox_assert(enbox_caps_get_perm(caps) & ENBOX_CAPS_CHIDS_MASK);

	int      err;
	uint64_t kept;

	/*
	 * Derive the set of capabilities to preserve across a change IDs
	 * operation from the permitted set configured by
	 * enbox_secure_change_ids().
	 */
	kept = enbox_caps_get_perm(caps) &
	       ~(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAPS_CHIDS_MASK);

	/*
	 * Prepare for ID switch: setup capabilities required to switch to new
	 * IDs ...
	 */
	enbox_caps_set_eff(caps, ENBOX_CAPS_CHIDS_MASK);
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	if (!kept) {
		/*
		 * No capability preservation required: just change IDs since
		 * KEEP_CAPS securebits flags is meant to be disabled by a
		 * previous call to enbox_secure_change_ids() at that point.
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;

		return 0;
	}

	/*
	 * When capability preservation is required, enable the SECBIT_KEEP_CAPS
	 * flag to preserve capabilities set into the permitted set after the
	 * IDs switch.
	 */
	err = enbox_enable_keep_caps(true);
	if (err)
		goto err;

	/* Do the actual change IDs. */
	err = enbox_switch_ids(pwd_entry, drop_supp);
	if (err)
		goto err;

	/*
	 * Re-enable the CAP_SETPCAP capability into the effective set to
	 * complete secure bits configuration below.
	 */
	enbox_caps_set_eff(caps, ENBOX_CAP(CAP_SETPCAP));
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	err = enbox_save_secbits(ENBOX_CAPS_CHIDS_SECBITS |
	                         SECBIT_KEEP_CAPS_LOCKED);
	if (err)
		goto err;

	/* Finally, set final requested capabilities. */
	enbox_caps_set_eff(caps, kept);
	enbox_caps_set_perm(caps, kept);
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	return 0;

err:
	enbox_info("failed to change IDs: %s (%d)", strerror(-err), -err);

	return err;
}

int
enbox_change_ids_byid(uid_t                          uid,
                      bool                           drop_supp,
                      struct enbox_caps * __restrict caps)
{
	enbox_assert_setup();
	enbox_assert(uid);
	enbox_assert(uid != enbox_uid);
	enbox_assert(caps);

	const struct passwd * pwd;

	pwd = upwd_get_user_byid(uid);
	if (!pwd) {
		int err = errno;

		enbox_assert(err > 0);
		enbox_assert(err != ENODATA);
		enbox_assert(err != ENAMETOOLONG);

		switch (err) {
		case ENOENT:
			enbox_info("'%d': no such UID", uid);
			break;
		default:
			enbox_info("'%d': unexpected UID: %s (%d)",
				   uid,
				   strerror(err),
				   err);
		}

		return -err;
	}

	return enbox_change_ids(pwd, drop_supp, caps);
}

int
enbox_change_ids_byname(const char * __restrict        user,
                        bool                           drop_supp,
                        struct enbox_caps * __restrict caps)
{
	enbox_assert_setup();
	enbox_assert(upwd_validate_user_name(user) > 0);
	enbox_assert(caps);

	const struct passwd * pwd;

	pwd = upwd_get_user_byname(user);
	if (!pwd) {
		int err = errno;

		enbox_assert(err > 0);
		enbox_assert(err != ENODATA);
		enbox_assert(err != ENAMETOOLONG);

		switch (err) {
		case ENOENT:
			enbox_info("'%s': no such user", user);
			break;
		default:
			enbox_info("'%s': unexpected user name: %s (%d)",
				   user,
				   strerror(err),
				   err);
		}

		return -err;
	}

	return enbox_change_ids(pwd, drop_supp, caps);
}

int
enbox_secure_change_ids(struct enbox_caps * __restrict caps,
                        uint64_t                       kept_caps)
{
	enbox_assert_setup();
	enbox_assert(caps);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!(kept_caps &
	               (ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAPS_CHIDS_MASK)));

	int      err;
	int      secbits = ENBOX_CAPS_CHIDS_SECBITS;
	uint64_t perm = ENBOX_CAPS_CHIDS_MASK;

	if (!kept_caps)
		/*
		 * As `kept_caps' equals to zero, enbox_change_ids() is not
		 * required to preserve capabilities across change IDs
		 * operation: disable and lock the KEEP_CAPS securebits flag.
		 */
		secbits |= SECBIT_KEEP_CAPS_LOCKED;
	else
		/*
		 * Required to preserve capabilities across change IDs
		 * operations.
		 */
		perm |= ENBOX_CAP(CAP_SETPCAP) | kept_caps;

	enbox_enable_nonewprivs();

	err = enbox_save_secbits(secbits);
	if (err)
		goto err;

	/*
	 * Clear all capability bounding set: we do require none of them since
	 * the targeted use case is not meant calling execve(2).
	 */
	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	/*
	 * Setup the minimum capability set required to perform a change IDs
	 * with `kept_caps' capabilities preserved.
	 */
	enbox_caps_set_eff(caps, 0);
	enbox_caps_set_perm(caps, perm);
	enbox_caps_set_inh(caps, 0);
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	/*
	 * Just to be sure, clear all ambient capabilities: we do require none
	 * of them since the targeted use case is not meant to call execve(2).
	 */
	enbox_clear_amb_caps();

	return 0;

err:
	enbox_info("failed to prepare for change IDs: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

int
enbox_secure_execve(struct enbox_caps * __restrict caps,
                    uint64_t                       kept_caps)
{
	enbox_assert_setup();
	enbox_assert(caps);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	int err;

	enbox_enable_nonewprivs();

	/*
	 * Do not set the SECBIT_NOROOT as it would require us to use ambient
	 * capabilities to ensure inherited capabilities loading into permitted
	 * and effective sets.
	 * Ambient capabilities would otherwise be inherited and automatically
	 * loaded into permitted and effective sets at exeve(2) time by all
	 * unprivileged (grand)children processes...
	 */
	err = enbox_save_secbits(SECBIT_KEEP_CAPS_LOCKED |
	                         SECBIT_NO_CAP_AMBIENT_RAISE |
	                         SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED);
	if (err)
		goto err;

	/*
	 * Add the requested capabilities to be kept enabled after next
	 * execve(2) into the inheritable set.
	 * Note that an inheritable capability MUST also be enabled into the
	 * permitted set.
	 */
	enbox_load_epi_caps(caps);
	enbox_caps_set_perm(caps, enbox_caps_get_perm(caps) | kept_caps);
	enbox_caps_set_inh(caps, kept_caps);
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	/*
	 * Clear bounding capabilities after setting up inheritable set since
	 * the capability bounding set acts as a limiting superset for the
	 * capabilities that current thread can add to its inheritable set using
	 * capset(2).
	 * However, once a capability has been enabled into the inheritable set,
	 * disabling it from the bounding set does not remove it from the
	 * inheritable set.
	 * It just prevents the capability from being added back into the
	 * thread's inheritable set in the future.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	/*
	 * Clear all ambient capabilities: we would not want a non-root process
	 * inheriting capabilities from the ambient set if the process were to
	 * change IDs...
	 */
	enbox_clear_amb_caps();

	return 0;

err:
	enbox_info("failed to prepare for program execution: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

/* For non root / non zero user ids... */
#if 0
int
enbox_secure_execve(struct enbox_caps * __restrict caps,
                    uint64_t                       kept_caps)
{
	enbox_assert_setup();
	enbox_assert(caps);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	int err;

	enbox_enable_nonewprivs();

	enbox_load_epi_caps(caps);
	enbox_caps_set_perm(caps, enbox_caps_get_perm(caps) | kept_caps);
	enbox_caps_set_inh(caps, kept_caps);
	err = enbox_save_epi_caps(caps);
	if (err)
		goto err;

	/*
	 * Setup ambient capabilities after inheritable set since the ambient
	 * capability set obeys the invariant that no capability can ever be
	 * ambient if it is not both permitted and inheritable.
	 */
	enbox_clear_amb_caps();
	err = enbox_raise_amb_caps(kept_caps);
	if (err)
		goto err;

	err = enbox_save_secbits(SECBIT_KEEP_CAPS_LOCKED |
	                         SECBIT_NO_CAP_AMBIENT_RAISE |
	                         SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED);
	if (err)
		goto err;

	/*
	 * Clear bounding capabilities after setting up inheritable set since
	 * the capability bounding set acts as a limiting superset for the
	 * capabilities that current thread can add to its inheritable set using
	 * capset(2).
	 * However, once a capability has been enabled into the inheritable set,
	 * disabling it from the bounding set does not remove it from the
	 * inheritable set.
	 * It just prevents the capability from being added back into the
	 * thread's inheritable set in the future.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	return 0;

err:
	enbox_info("failed to prepare for program execution: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}
#endif
