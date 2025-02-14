#include "common.h"
#include <stroll/bmap.h>
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

/**
 * @internal
 *
 * An opaque structure holding internal capability state.
 */
struct enbox_caps {
	struct __user_cap_data_struct data[VFS_CAP_U32];
};

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
 *
 * See <linux>/Documentation/userspace-api/no_new_privs.rst
 */
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

static __enbox_nothrow
int
enbox_save_amb_caps(uint64_t ambient)
{
	enbox_assert(!(ambient & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	int c;

	for (c = 0; c < ENBOX_CAPS_NR; c++) {
		enbox_assert(cap_valid(c));

		int cmd = (ambient & enbox_cap(c)) ? PR_CAP_AMBIENT_RAISE
		                                   : PR_CAP_AMBIENT_LOWER;

		if (prctl(PR_CAP_AMBIENT, cmd, (long)c, 0L, 0L)) {
			int err = errno;

			enbox_info("cannot save ambient set capabilities: "
			           "%s (%d)",
			           strerror(err),
			           err);
			return -err;
		}
	}

	return 0;
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

			enbox_info("cannot clear bounding set capabilities: "
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
enbox_get_eff_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].effective) << 32) |
	       (uint64_t)caps->data[0].effective;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_eff_caps_have(const struct enbox_caps * __restrict caps,
                    int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_eff_caps(caps) & enbox_cap(id));
}

static inline __enbox_nonull(1) __warn_result
uint64_t
enbox_get_perm_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].permitted) << 32) |
	       (uint64_t)caps->data[0].permitted;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_perm_caps_have(const struct enbox_caps * __restrict caps,
                     int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_perm_caps(caps) & enbox_cap(id));
}

static inline __enbox_nonull(1) __warn_result
uint64_t
enbox_get_inh_caps(const struct enbox_caps * __restrict caps)
{
	enbox_assert(caps);

	return (((uint64_t)caps->data[1].inheritable) << 32) |
	       (uint64_t)caps->data[0].inheritable;
}

static inline __enbox_nonull(1) __enbox_pure __enbox_nothrow __warn_result
bool
enbox_inh_caps_have(const struct enbox_caps * __restrict caps,
                    int                                  id)
{
	enbox_assert(caps);
	enbox_assert(cap_valid(id));

	return !!(enbox_get_inh_caps(caps) & enbox_cap(id));
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
enbox_set_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].effective = (uint32_t)
	                          (effective & (UINT64_C(0xffffffff)));
	caps->data[1].effective = (uint32_t)(effective >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_eff_caps(caps, enbox_get_eff_caps(caps) | effective);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_eff_caps(struct enbox_caps * __restrict caps, uint64_t effective)
{
	enbox_assert(caps);
	enbox_assert(!(effective & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_eff_caps(caps, enbox_get_eff_caps(caps) & ~effective);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_set_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].permitted = (uint32_t)
	                          (permitted & (UINT64_C(0xffffffff)));
	caps->data[1].permitted = (uint32_t)(permitted >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_perm_caps(caps, enbox_get_perm_caps(caps) | permitted);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_perm_caps(struct enbox_caps * __restrict caps, uint64_t permitted)
{
	enbox_assert(caps);
	enbox_assert(!(permitted & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_perm_caps(caps, enbox_get_perm_caps(caps) & ~permitted);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_set_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	caps->data[0].inheritable = (uint32_t)
	                            (inheritable & (UINT64_C(0xffffffff)));
	caps->data[1].inheritable = (uint32_t)(inheritable >> 32);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_raise_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_inh_caps(caps, enbox_get_inh_caps(caps) | inheritable);
}

static inline __enbox_nonull(1) __enbox_nothrow
void
enbox_drop_inh_caps(struct enbox_caps * __restrict caps, uint64_t inheritable)
{
	enbox_assert(caps);
	enbox_assert(!(inheritable & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	enbox_set_inh_caps(caps, enbox_get_inh_caps(caps) & ~inheritable);
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

void
enbox_clear_epi_caps(void)
{
	struct enbox_caps caps;
	int               err __unused;

	memset(&caps, 0, sizeof(caps));

	/* This should never fail since we simply drop all capabilities... */
	err = _enbox_save_epi_caps(&caps);
	enbox_assert(!err);
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
	eff = enbox_get_eff_caps(&caps);
	perm = enbox_get_perm_caps(&caps);
	inh = enbox_get_inh_caps(&caps);
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
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SETUID) | ENBOX_CAP(CAP_SETGID))

/* Securebits used to perform a change of UIDs / GIDs... */
#define ENBOX_CAPS_SECBITS \
	(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | \
	 SECBIT_KEEP_CAPS_LOCKED | \
	 SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

/*
 * Do not allow propagation of these capabilities across execve(2) or
 * enbox_switch_ids() operations.
 */
#define ENBOX_CAPS_INVAL \
	(ENBOX_CAP(CAP_SETPCAP) | ENBOX_CAP(CAP_SYS_ADMIN))

int
enbox_change_ids(const struct passwd * __restrict pwd_entry,
                 bool                             drop_supp,
                 uint64_t                         kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, false));
	enbox_assert(pwd_entry->pw_uid != enbox_uid);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!(kept_caps & (ENBOX_CAPS_INVAL | ENBOX_CAPS_CHIDS_MASK)));

	struct enbox_caps caps;
	int               err;

	enbox_enable_nonewprivs();

	/*
	 * Make sure we can modify :
	 * - capabilities (at least, to clear the bounding set),
	 * - and change UIDs / GIDs.
	 * Also make sure `kept_caps' are added to the permitted set so that we
	 * may enable them after the change IDs operation.
	 */
	enbox_set_eff_caps(&caps, ENBOX_CAPS_CHIDS_MASK);
	enbox_set_perm_caps(&caps, ENBOX_CAPS_CHIDS_MASK | kept_caps);
	enbox_set_inh_caps(&caps, 0);
	err = enbox_save_epi_caps(&caps);
	if (err)
		goto err;

	/*
	 * Clear entire capability bounding set: we do require none of them
	 * since the targeted use case is not meant calling execve(2) and we
	 * want to inhibit file capabilities.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		goto err;

	if (kept_caps) {
		/*
		 * When capability preservation is required, enable the
		 * SECBIT_KEEP_CAPS flag to preserve capabilities set into the
		 * permitted set after the IDs switch.
		 */
		err = enbox_enable_keep_caps(true);
		if (err)
			goto err;

		/*
		 * Do the actual change IDs: the effective capability set will
		 * have been cleared on return from enbox_switch_ids().
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;

		/*
		 * Re-enable the CAP_SETPCAP capability into the effective set
		 * to complete secure bits configuration below.
		 */
		enbox_set_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
		err = enbox_save_epi_caps(&caps);
		if (err)
			goto err;

		/* Lock securebits in a fully restrictive state. */
		err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
		if (err)
			goto err;
	}
	else {
		/*
		 * Short path when there is no need to keep capabilities across
		 * change IDs.
		 */

		/* Lock securebits in a fully restrictive state. */
		err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
		if (err)
			goto err;

		/*
		 * Do the actual change IDs: the effective capability set will
		 * have been cleared on return from enbox_switch_ids().
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;
	}

	/*
	 * Finally, set final requested capabilities.
	 *
	 * Note that event when `kept_caps' is zero, this step should always be
	 * done. Indeed, when swiching from non zero UID(s), there is no
	 * guarantee that effective and permitted sets are properly cleared on
	 * return from enbox_switch_ids().
	 *
	 * See section `Effect of user ID changes on capabilities' of
	 * capabilities(7).
	 */
	enbox_set_eff_caps(&caps, kept_caps);
	enbox_set_perm_caps(&caps, kept_caps);
	err = enbox_save_epi_caps(&caps);
	if (err)
		goto err;

	/*
	 * Just to be sure, clear all ambient capabilities: we do require none
	 * of them since the targeted use case is not meant to call execve(2).
	 */
	enbox_clear_amb_caps();

	return 0;

err:
	enbox_info("failed to change IDs: %s (%d)", strerror(-err), -err);

	return err;
}

static
int
enbox_execve_with_caps(struct enbox_caps * __restrict caps,
                       const char * __restrict        path,
                       char * const                   argv[__restrict_arr],
                       char * const                   envp[__restrict_arr],
                       uint64_t                       kept_caps)
{
	enbox_assert_setup();
	enbox_assert(caps);
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!(kept_caps & ENBOX_CAPS_INVAL));

	int err;

	/*
	 * Load capabilities to preserve across execve(2) into the inheritable
	 * set so that they may also be enabled into the ambient set.
	 * Indeed, as stated into capabilities(7):
	 *   -- The ambient capability set obeys the invariant that no
	 *      capability can ever be ambient if it is not both permitted and
	 *      inheritable.
	 * Note that to enable inheritable capabilities, these MUST also be
	 * enabled into bounding sets. Call to enbox_save_epi_caps() will return
	 * -EPERM otherwise...
	 */
	enbox_set_inh_caps(caps, kept_caps);
	err = enbox_save_epi_caps(caps);
	if (err)
		return err;

	/*
	 * Now setup ambient capabilities: these are preserved across execve(2)
	 * for non privileged processes.
	 * Ambient capabilities will be added to the permitted set and assigned
	 * to the effective set when execve(2) is called below.
	 */
	err = enbox_save_amb_caps(kept_caps);
	if (err)
		return err;

	/* Lock securebits in a fully restrictive state. */
	err = enbox_save_secbits(ENBOX_CAPS_SECBITS);
	if (err)
		return err;

	/*
	 * Clear entire capability bounding set to inhibit file capabilities.
	 * As stated into capabilities(7):
	 *   -- Removing a capability from the bounding set does not remove it
	 *      from the thread's inheritable set. However it does prevent the
	 *      capability from being added back into the thread's inheritable
	 *      set in the future.
	 */
	err = enbox_clear_bound_caps();
	if (err)
		return err;

	/*
	 * Finally jump into program given by arguments. Returning from
	 * execve(2) means failure...
	 */
	err = execve(path, argv, envp);
	enbox_assert(err);

	return err;
}

int
enbox_execve(const char * __restrict path,
             char * const            argv[__restrict_arr],
             char * const            envp[__restrict_arr],
             uint64_t                kept_caps)
{
	enbox_assert_setup();
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!(kept_caps & ENBOX_CAPS_INVAL));

	struct enbox_caps caps;
	int               err;

	enbox_enable_nonewprivs();

	/*
	 * Prepare capability sets for preservation across next execve(2).
	 * Basically, this means we must:
	 * - enable CAP_SETPCAP into the effective set for later bounding set
	 *   and securebits configuration ;
	 * - enable `kept_caps' capabilities into the permitted set for later
	 *   configuration of the ambient set.
	 * See enbox_execve_with_caps() for more details.
	 */
	enbox_load_epi_caps(&caps);
	enbox_raise_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
	enbox_raise_perm_caps(&caps, ENBOX_CAP(CAP_SETPCAP) | kept_caps);

	/* Complete capability configuration and call execve(2). */
	err = enbox_execve_with_caps(&caps, path, argv, envp, kept_caps);
	enbox_assert(err);

	enbox_info("failed to execute: %s (%d)", strerror(-err), -err);

	return err;
}

int
enbox_change_idsn_execve(const struct passwd * __restrict pwd_entry,
                         bool                             drop_supp,
                         const char * __restrict          path,
                         char * const                     argv[__restrict_arr],
                         char * const                     envp[__restrict_arr],
                         uint64_t                         kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!enbox_validate_pwd(pwd_entry, true));
	enbox_assert(path);
	enbox_assert(argv);
	enbox_assert(argv[0]);
	enbox_assert(*argv[0]);
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));
	enbox_assert(!(kept_caps & ENBOX_CAPS_INVAL));

	struct enbox_caps caps;
	uint64_t          eff;
	int               err;

	enbox_enable_nonewprivs();

	enbox_load_epi_caps(&caps);
	eff = enbox_get_eff_caps(&caps);

	if (pwd_entry->pw_uid != enbox_uid) {
		/*
		 * A change IDs is required before execve(2).
		 *
		 * Make sure we can modify :
		 * - capabilities (at least, to clear the bounding set),
		 * - and change UIDs / GIDs.
		 * Also make sure `kept_caps' are added to the permitted set so that we
		 * may enable them after the change IDs operation.
		 *
		 * Prepare capability sets for preservation across next change
		 * IDs and execve(2). Basically, this means we must:
		 * - enable CAP_SETUID and CAP_SETGID into the effective set to
		 *   perform successful change IDs operation ;
		 * - enable CAP_SETPCAP into the effective set for later
		 *   bounding set and securebits configuration ;
		 * - make sure `kept_caps' are added to the permitted set so
		 *   that we may enable them after the change IDs operation.
		 * - cleanup inheritable set to make things deterministic (this
		 *   is not really required though).
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAPS_CHIDS_MASK);
		enbox_raise_perm_caps(&caps,
		                      ENBOX_CAPS_CHIDS_MASK | kept_caps);
		enbox_set_inh_caps(&caps, 0);
		err = enbox_save_epi_caps(&caps);
		if (err)
			goto err;

		/*
		 * Request system to preserve capabilities (into the permitted
		 * set) across change IDs operation.
		 */
		err = enbox_enable_keep_caps(true);
		if (err)
			goto err;

		/*
		 * Change user and group IDs.
		 * On return from enbox_switch_ids() / setresuid(2), effective
		 * and ambients sets will be cleared.
		 */
		err = enbox_switch_ids(pwd_entry, drop_supp);
		if (err)
			goto err;

		/*
		 * Re-enable CAP_SETPCAP into the effective set for later
		 * bounding set and securebits configuration.
		 * `kept_caps' capabilities have already been enabled into the
		 * permitted set above, allowing later configuration of the
		 * ambient set.
		 * See enbox_execve_with_caps() for more details.
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAP(CAP_SETPCAP));
	}
	else {
		/*
		 * No change IDs is required. Just prepare capability set for
		 * preservation across next execve(2). Basically, this means we
		 * must:
		 * - enable CAP_SETPCAP into the effective set for later
		 *   bounding set and securebits configuration ;
		 * - enable `kept_caps' capabilities into the permitted set for
		 *   later configuration of the ambient set.
		 * See enbox_execve_with_caps() for more details.
		 */
		enbox_set_eff_caps(&caps, eff | ENBOX_CAP(CAP_SETPCAP));
		enbox_raise_perm_caps(&caps,
		                      ENBOX_CAP(CAP_SETPCAP) | kept_caps);
	}

	/* Complete capability configuration and call execve(2). */
	err = enbox_execve_with_caps(&caps, path, argv, envp, kept_caps);
	enbox_assert(err);

err:
	enbox_info("failed to change IDs and execute: %s (%d)",
	           strerror(-err),
	           -err);

	return err;
}

void
enbox_ensure_safe(uint64_t kept_caps)
{
	enbox_assert_setup();
	enbox_assert(!(kept_caps & ~((UINT64_C(1) << ENBOX_CAPS_NR) - 1)));

	struct enbox_caps caps;
	int               err __unused;

	enbox_enable_nonewprivs();

	enbox_load_epi_caps(&caps);
	if (enbox_perm_caps_have(&caps, CAP_SETPCAP)) {

		/*
		 * Enable CAP_SETPCAP to clear bounding set and setup securebits
		 * below.
		 */
		if (!enbox_eff_caps_have(&caps, CAP_SETPCAP)) {
			enbox_raise_eff_caps(&caps, ENBOX_CAP(CAP_SETPCAP));
			err = _enbox_save_epi_caps(&caps);
			enbox_assert(!err);
		}

		/*
		 * This may fail when trying to modify a locked bit.
		 * However, since we just want to provide the caller with the
		 * safest environment we can, ignore errors.
		 */
		enbox_save_secbits(SECBIT_NOROOT |
		                   SECBIT_NO_CAP_AMBIENT_RAISE |
		                   SECURE_ALL_LOCKS);

		/*
		 * This should never fail thanks to the enabled SETPCAP
		 * capability...
		 */
		err = enbox_clear_bound_caps();
		enbox_assert(!err);
	}

	/*
	 * We would no want our children to acquire capabilities from the actual
	 * ambient set...
	 */
	enbox_clear_amb_caps();

	/* This should never fail since we only drop capabilities... */
	enbox_set_eff_caps(&caps, enbox_get_eff_caps(&caps) & kept_caps);
	enbox_set_perm_caps(&caps, enbox_get_perm_caps(&caps) & kept_caps);
	enbox_set_inh_caps(&caps, 0);
	err = _enbox_save_epi_caps(&caps);
	enbox_assert(!err);
}
