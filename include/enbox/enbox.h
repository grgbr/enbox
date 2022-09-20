#ifndef _ENBOX_H
#define _ENBOX_H

#include <enbox/config.h>
#include <utils/pwd.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>

/*
 * Depending on glibc version, this definition may be missing whereas handled by
 * kernel...
 */
#ifndef MS_NOSYMFOLLOW
#define MS_NOSYMFOLLOW (1UL << 8)
#endif

#if defined(CONFIG_ENBOX_ASSERT)

#include <utils/assert.h>

#define enbox_assert(_expr) \
	uassert("enbox", _expr)

#define __enbox_nonull(_arg_index, ...)

#else  /* !defined(CONFIG_ENBOX_ASSERT) */

#define enbox_assert(_expr)

#define __enbox_nonull(_arg_index, ...) \
	__nonull(_arg_index, ## __VA_ARGS__)

#endif /* defined(CONFIG_ENBOX_ASSERT) */

/******************************************************************************
 * Raw API
 ******************************************************************************/

#define ENBOX_KEEP_UID  ((uid_t)-1)
#define ENBOX_KEEP_GID  ((gid_t)-1)
#define ENBOX_KEEP_MODE ((mode_t)-1)

extern mode_t enbox_umask;
extern uid_t  enbox_uid;
extern gid_t  enbox_gid;

static inline mode_t __nothrow
enbox_set_umask(mode_t mask)
{
	enbox_assert(!(mask & ~ALLPERMS));

	mode_t old;

	old = umask(mask);
	enbox_assert(old == enbox_umask);

	enbox_umask = mask;

	return old;
}

static inline mode_t __nothrow __pure
enbox_get_umask(void)
{
	enbox_assert(!(enbox_umask & ~ALLPERMS));

	return enbox_umask;
}

static inline uid_t __nothrow __pure
enbox_get_uid(void)
{
	enbox_assert(enbox_uid != (uid_t)-1);

	return enbox_uid;
}

static inline gid_t __nothrow __pure
enbox_get_gid(void)
{
	enbox_assert(enbox_gid != (gid_t)-1);

	return enbox_gid;
}

extern int
enbox_change_perms(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_dir(const char * __restrict path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_slink(const char * __restrict path,
                 const char * __restrict target,
                 uid_t                   uid,
                 gid_t                   gid)
	__enbox_nonull(1, 2) __nothrow;

extern int
enbox_make_chrdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_blkdev(const char * path,
                  uid_t        uid,
                  gid_t        gid,
                  mode_t       mode,
                  unsigned int major,
                  unsigned int minor)
	__enbox_nonull(1) __nothrow;

extern int
enbox_make_fifo(const char * path, uid_t uid, gid_t gid, mode_t mode)
	__enbox_nonull(1) __nothrow;

extern int
enbox_drop_ambient_caps(void) __nothrow;

extern int
enbox_drop_bounding_caps(void) __nothrow;

extern int
enbox_lock_caps(void) __nothrow;

enum enbox_dumpable {
	/* Disable coredump generation */
	ENBOX_DISABLE_DUMP = 0,
	/* Coredump generation allowed. */
	ENBOX_ENABLE_DUMP  = 1,
	/* Coredump generation allowed but readable by root only. */
	ENBOX_RDROOT_DUMP  = 2
};

extern int
enbox_setup_dump(enum enbox_dumpable dump) __nothrow;

#define ENBOX_KEEP_SUPP_GROUPS (false)
#define ENBOX_DROP_SUPP_GROUPS (true)

extern int
enbox_change_ids(const char * __restrict user, bool drop_supp)
	__enbox_nonull(1);

/******************************************************************************
 * High-level API
 ******************************************************************************/

enum enbox_entry_type {
	ENBOX_DIR_ENTRY_TYPE = 0,
	ENBOX_SLINK_ENTRY_TYPE,
	ENBOX_CHRDEV_ENTRY_TYPE,
	ENBOX_BLKDEV_ENTRY_TYPE,
	ENBOX_FIFO_ENTRY_TYPE,
	ENBOX_PROC_ENTRY_TYPE,
	ENBOX_TREE_ENTRY_TYPE,
	ENBOX_FILE_ENTRY_TYPE,
	ENBOX_ENTRY_TYPE_NR
};

struct enbox_dir_entry {
	mode_t mode;
};

struct enbox_slink_entry {
	const char * target;
};

struct enbox_dev_entry {
	mode_t       mode;
	unsigned int major;
	unsigned int minor;
};

struct enbox_fifo_entry {
	mode_t mode;
};

struct enbox_mount_entry {
	unsigned long flags;
	const char *  opts;
};

struct enbox_bind_entry {
	const char *  orig;
	unsigned long flags;
	const char *  opts;
};

struct enbox_entry {
	const char *                     path;
	enum enbox_entry_type            type;
	uid_t                            uid;
	gid_t                            gid;
	union {
		struct enbox_dir_entry   dir;
		struct enbox_slink_entry slink;
		struct enbox_dev_entry   dev;
		struct enbox_fifo_entry  fifo;
		struct enbox_mount_entry mount;
		struct enbox_bind_entry  bind;
	};
};

struct enbox_fsset {
	unsigned int               nr;
	const struct enbox_entry * entries;
};

extern int
enbox_populate_host(const struct enbox_fsset * __restrict host)
	__enbox_nonull(1);

#define ENBOX_NAMESPACE_FLAGS \
	(CLONE_NEWNS | \
	 CLONE_NEWCGROUP | \
	 CLONE_NEWUTS | \
	 CLONE_NEWIPC | \
	 CLONE_NEWNET)

struct enbox_ids {
	const struct passwd * pwd;
	bool                  drop_supp;
};

extern int
enbox_load_ids_byid(struct enbox_ids * __restrict ids,
                    uid_t                         id,
                    bool                          drop_supp)
	__enbox_nonull(1);

extern int
enbox_load_ids_byname(struct enbox_ids * __restrict ids,
                      const char * __restrict       user,
                      bool                          drop_supp)
	__enbox_nonull(1, 2);

struct enbox_jail {
	int                namespaces;
	const char *       root_path;
	struct enbox_fsset fsset;
};

extern int
enbox_enter_jail(const struct enbox_jail * __restrict jail,
                 const struct enbox_ids * __restrict  ids)
	__enbox_nonull(1, 2) __nothrow;

struct enbox_cmd {
	mode_t               umask;
	const char *         cwd;
	const char * const * exec;
};

extern int
enbox_run_cmd(const struct enbox_cmd * __restrict exec,
              const struct enbox_ids * __restrict ids)
	__enbox_nonull(1, 2) __nothrow;

/******************************************************************************
 * Configuration API
 ******************************************************************************/

struct enbox_conf;

extern int
enbox_run_conf(const struct enbox_conf * __restrict conf) __enbox_nonull(1);

extern struct enbox_conf *
enbox_create_conf_from_file(const char * __restrict path) __enbox_nonull(1);

void
enbox_destroy_conf(struct enbox_conf * __restrict conf) __enbox_nonull(1);

/******************************************************************************
 * Initialization API
 ******************************************************************************/

struct elog;

extern int __nothrow __leaf
enbox_setup(struct elog * __restrict logger);

#endif /* _ENBOX_H */
