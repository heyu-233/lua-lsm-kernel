/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/security.h>
#include "lsm.h"

static bool lua_lsm_capable(int cap)
{
	bool allow = true;
	int rc;

	/*
	 * All kernel tasks are privileged
	 */
	if (unlikely(current->flags & PF_KTHREAD))
		return true;

	rc = cap_capable(current_cred(), &init_user_ns, cap, CAP_OPT_NONE);
	if (rc < 0) {
		allow = false;
		__log_info("NO capability: cap = %d, allow=%d\n", cap, allow);
	}

	return allow;
}

static int version_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%u", LUA_LSM_VERSION);
	return 0;
}

static int open_version(struct inode *inode, struct file *filp)
{
	return single_open(filp, version_show, NULL);
}

static const struct file_operations fops_version = {
	.open		= open_version,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static ssize_t module_write(const char __user *buf, size_t len,
			    loff_t *ppos, int load)
{
	char *buffer, *p;
	int err;

	__log_info("len = %d\n", (int)len);
	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;
	if (len == 0)
		return -EINVAL;

	buffer = memdup_user_nul(buf, len);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	__log_info("buffer = [%d] %s\n", (int)len, buffer);
	if (load) {
		err = lua_lsm_module_register(buffer, len);
	} else {
		/* remove the tailing '\n' */
		p = &buffer[len - 1];
		while (p >= buffer && *p == '\n')
			*p-- = '\0';

		err = lua_lsm_module_unregister(buffer);
	}
	kfree(buffer);
	if (err < 0)
		return err;

	return len;
}

static ssize_t register_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	return module_write(buf, len, ppos, 1);
}

static const struct file_operations fops_register = {
	.write		= register_write,
};

static ssize_t unregister_write(struct file *file, const char __user *buf,
				size_t len, loff_t *ppos)
{
	return module_write(buf, len, ppos, 0);
}

static const struct file_operations fops_unregister = {
	.write		= unregister_write,
};

static int open_modules(struct inode *inode, struct file *filp)
{
	return single_open(filp, modules_show, NULL);
}

static const struct file_operations fops_modules = {
	.open		= open_modules,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * PoC shared-dict control file: /sys/kernel/security/lua/shdict
 *
 * UNSTABLE: development interface for the securityfs shared dict PoC
 * only.  Not a formal ABI; it may change or disappear without notice.
 *
 * One complete request per write (max SHDICT_IO_MAX bytes): the first line
 * names a registered module and the remaining bytes are a Lua chunk. The
 * chunk runs in a restricted environment that exposes only that module's
 * `shared` table. Its nil/bool/number/string result is read back from the
 * same file descriptor; strings are returned as raw bytes.
 */
#define SHDICT_IO_MAX		4096
#define SHDICT_NAME_MAX		128

struct shdict_ctx {
	char *buf;	/* response buffer */
	size_t len;	/* bytes valid in buf */
	size_t pos;	/* next byte to return from read() */
};

static int shdict_open(struct inode *inode, struct file *filp)
{
	struct shdict_ctx *ctx;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->buf = kmalloc(SHDICT_IO_MAX, GFP_KERNEL);
	if (!ctx->buf) {
		kfree(ctx);
		return -ENOMEM;
	}

	filp->private_data = ctx;
	return 0;
}

static int shdict_release(struct inode *inode, struct file *filp)
{
	struct shdict_ctx *ctx = filp->private_data;

	if (ctx) {
		kfree(ctx->buf);
		kfree(ctx);
	}
	return 0;
}

static ssize_t shdict_read(struct file *file, char __user *buf, size_t len,
			   loff_t *ppos)
{
	struct shdict_ctx *ctx = file->private_data;
	size_t n = ctx->len - ctx->pos;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (n == 0)
		return 0;
	if (n > len)
		n = len;
	if (copy_to_user(buf, ctx->buf + ctx->pos, n))
		return -EFAULT;
	ctx->pos += n;
	*ppos += n;
	return n;
}

static ssize_t shdict_write(struct file *file, const char __user *buf,
			    size_t len, loff_t *ppos)
{
	struct shdict_ctx *ctx = file->private_data;
	char *separator;
	char *code;
	char *input;
	size_t module_len;
	size_t code_len;
	size_t i;
	int err;

	if (!lua_lsm_capable(CAP_MAC_ADMIN))
		return -EPERM;
	if (len == 0)
		return -EINVAL;
	if (len > SHDICT_IO_MAX)
		return -E2BIG;

	/* every write invalidates the previous response */
	ctx->len = 0;
	ctx->pos = 0;

	input = memdup_user_nul(buf, len);
	if (IS_ERR(input))
		return PTR_ERR(input);

	/* Lua source uses escapes for NULs; literal NULs are not valid framing. */
	if (strnlen(input, len) != len) {
		err = -EINVAL;
		goto out;
	}

	separator = memchr(input, '\n', len);
	if (!separator) {
		err = -EINVAL;
		goto out;
	}

	module_len = separator - input;
	if (module_len && input[module_len - 1] == '\r')
		module_len--;
	if (!module_len || module_len > SHDICT_NAME_MAX) {
		err = module_len ? -E2BIG : -EINVAL;
		goto out;
	}
	for (i = 0; i < module_len; i++) {
		if (input[i] <= 0x20 || input[i] == 0x7f) {
			err = -EINVAL;
			goto out;
		}
	}
	input[module_len] = '\0';

	code = separator + 1;
	code_len = len - (code - input);
	if (!code_len) {
		err = -EINVAL;
		goto out;
	}

	err = lua_lsm_shdict_exec(input, code, code_len, ctx->buf,
				  SHDICT_IO_MAX, &ctx->len);
	if (!err)
		ctx->pos = 0;
out:
	kfree(input);
	return err ?: len;
}

static const struct file_operations fops_shdict = {
	.open		= shdict_open,
	.read		= shdict_read,
	.write		= shdict_write,
	.release	= shdict_release,
};

#ifdef CONFIG_SECURITY_LUA_LSM_STATS

static int stats_show(struct seq_file *m, void *v)
{
	lvm_stats_show(m);
	kvcache_stats_show(m);
	return 0;
}

static int open_stats(struct inode *inode, struct file *filp)
{
	return single_open(filp, stats_show, NULL);
}

static const struct file_operations fops_stats = {
	.open		= open_stats,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int open_lsm_funcs(struct inode *inode, struct file *filp)
{
	return single_open(filp, lsm_funcs_show, NULL);
}

static const struct file_operations fops_lsm_funcs = {
	.open		= open_lsm_funcs,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

static struct lua_lsm_file {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	struct dentry *dentry;
} files[] = {
	{ "version",	0444,	&fops_version		},	/* r--r--r-- */
	{ "register",	0222,	&fops_register		},	/* -w--w--w- */
	{ "unregister",	0222,	&fops_unregister	},	/* -w--w--w- */
	{ "modules",	0444,	&fops_modules		},	/* r--r--r-- */
	{ "shdict",	0600,	&fops_shdict		},	/* rw------- PoC */
#ifdef CONFIG_SECURITY_LUA_LSM_STATS
	{ "stats",	0444,	&fops_stats		},	/* r--r--r-- */
	{ "lsm_funcs",	0444,	&fops_lsm_funcs		},	/* r--r--r-- */
#endif
	{ NULL, 0, NULL }
};

int __init lua_lsm_securityfs_init(void)
{
	struct dentry *dir;
	struct dentry *dentry;
	struct lua_lsm_file *file;

	if (!lua_lsm_initialized)
		return 0;

	dir = securityfs_create_dir("lua", NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	for (file = files; file->name; file++) {
		dentry = securityfs_create_file(file->name, file->mode,
						dir, NULL, file->fops);
		if (IS_ERR(dentry))
			break;
		file->dentry = dentry;
	}

	if (IS_ERR(dentry)) {
		for (file--; file >= files; file--)
			securityfs_remove(file->dentry);

		securityfs_remove(dir);
		return PTR_ERR(dentry);
	}

	return 0;
}
