/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Lua based LSM
 *
 * Copyright (C) 2025 The Alibaba Cloud Linux Authors.
 */

#include "debug.h"
#include <linux/security.h>
#include <linux/kstrtox.h>
#include <linux/hex.h>
#include <linux/errname.h>
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
 * One complete command per write (max SHDICT_IO_MAX bytes), response read
 * back from the same file descriptor.  Each open() allocates an
 * independent response context that release() frees.  Commands:
 *
 *   set <module> <dict> <key> bool <0|1>
 *   set <module> <dict> <key> number <signed decimal integer>
 *   set <module> <dict> <key> string <hexadecimal bytes, even length>
 *   get <module> <dict> <key>
 *
 * Responses:
 *   OK
 *   bool <0|1>
 *   number <signed decimal integer>
 *   string <lowercase hexadecimal bytes>
 *   ERR -<errno>
 *
 * On failure write(2) also returns the negative errno: -EPERM (no
 * CAP_MAC_ADMIN), -EINVAL (format), -E2BIG (over limit), -ENOENT (no
 * such module/dict/key), -ESHUTDOWN (module not LIVE), -EOPNOTSUPP
 * (lightuserdata value), -ENOMEM.
 *
 * The dictionary must already exist: it is created by the Lua policy the
 * first time it touches `shared.<name>`, never by this file.
 */
#define SHDICT_IO_MAX		4096
#define SHDICT_NAME_MAX		128
#define SHDICT_VALUE_MAX	1024
#define SHDICT_TOKENS_MAX	7

struct shdict_ctx {
	char *buf;	/* response buffer */
	size_t len;	/* bytes valid in buf */
	size_t pos;	/* next byte to return from read() */
};

static int shdict_exec(struct shdict_ctx *ctx, char *input, size_t len);

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
	char *input;
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

	err = shdict_exec(ctx, input, len);
	kfree(input);
	return err ?: len;
}

static int shdict_reply_ok(struct shdict_ctx *ctx)
{
	ctx->len = scnprintf(ctx->buf, SHDICT_IO_MAX, "OK\n");
	ctx->pos = 0;
	return 0;
}

static int shdict_reply_value(struct shdict_ctx *ctx, const char *type,
			      const char *value)
{
	ctx->len = scnprintf(ctx->buf, SHDICT_IO_MAX, "%s %s\n", type, value);
	ctx->pos = 0;
	return 0;
}

static int shdict_reply_err(struct shdict_ctx *ctx, int err)
{
	ctx->len = scnprintf(ctx->buf, SHDICT_IO_MAX, "ERR %s\n",
			     errname(err));
	ctx->pos = 0;
	return err;
}

/* Split on ASCII whitespace; returns token count or -1 on overflow. */
static int shdict_split(char *s, char *tokens[], int max)
{
	int n = 0;

	for (;;) {
		while (*s == ' ' || *s == '\t' || *s == '\n' ||
		       *s == '\r' || *s == '\v' || *s == '\f')
			s++;
		if (!*s)
			break;
		if (n == max)
			return -1;
		tokens[n++] = s;
		while (*s && *s != ' ' && *s != '\t' && *s != '\n' &&
		       *s != '\r' && *s != '\v' && *s != '\f')
			s++;
		if (*s)
			*s++ = '\0';
	}
	return n;
}

static int shdict_name_ok(const char *name)
{
	size_t len = strlen(name);
	size_t i;

	if (len == 0 || len > SHDICT_NAME_MAX)
		return -E2BIG;
	for (i = 0; i < len; i++) {
		/* no whitespace or control characters */
		if (name[i] <= 0x20 || name[i] == 0x7f)
			return -EINVAL;
	}
	return 0;
}

static int shdict_exec_set(struct shdict_ctx *ctx, char **t)
{
	const char *module = t[1], *dict = t[2], *key = t[3];
	const char *type = t[4], *value = t[5];
	char *decoded;
	size_t value_len;
	int err;

	err = shdict_name_ok(module);
	if (!err)
		err = shdict_name_ok(dict);
	if (!err)
		err = shdict_name_ok(key);
	if (err)
		return shdict_reply_err(ctx, err);

	if (strcmp(type, "bool") == 0) {
		if (strcmp(value, "0") == 0)
			err = lua_lsm_shdict_set_bool(module, dict, key, false);
		else if (strcmp(value, "1") == 0)
			err = lua_lsm_shdict_set_bool(module, dict, key, true);
		else
			return shdict_reply_err(ctx, -EINVAL);
	} else if (strcmp(type, "number") == 0) {
		long long num;

		if (kstrtoll(value, 10, &num))
			return shdict_reply_err(ctx, -EINVAL);
		err = lua_lsm_shdict_set_number(module, dict, key, num);
	} else if (strcmp(type, "string") == 0) {
		size_t hex_len = strlen(value);

		if (hex_len % 2)
			return shdict_reply_err(ctx, -EINVAL);
		value_len = hex_len / 2;
		if (value_len > SHDICT_VALUE_MAX)
			return shdict_reply_err(ctx, -E2BIG);
		decoded = kmalloc(value_len ?: 1, GFP_KERNEL);
		if (!decoded)
			return shdict_reply_err(ctx, -ENOMEM);
		if (hex2bin(decoded, value, value_len))
			err = -EINVAL;
		else
			err = lua_lsm_shdict_set_string(module, dict, key,
							decoded, value_len);
		kfree(decoded);
	} else {
		return shdict_reply_err(ctx, -EINVAL);
	}

	if (err)
		return shdict_reply_err(ctx, err);
	return shdict_reply_ok(ctx);
}

static int shdict_exec_get(struct shdict_ctx *ctx, char **t)
{
	struct kvcache_snapshot snap;
	char numbuf[32];
	char *hex;
	size_t hex_len;
	int err;

	err = shdict_name_ok(t[1]);
	if (!err)
		err = shdict_name_ok(t[2]);
	if (!err)
		err = shdict_name_ok(t[3]);
	if (err)
		return shdict_reply_err(ctx, err);

	err = lua_lsm_shdict_get(t[1], t[2], t[3], &snap);
	if (err)
		return shdict_reply_err(ctx, err);

	switch (snap.tt) {
	case LUA_TBOOLEAN:
		err = shdict_reply_value(ctx, "bool", snap.b ? "1" : "0");
		break;
	case LUA_TNUMBER:
		scnprintf(numbuf, sizeof(numbuf), "%lld", (long long)snap.n);
		err = shdict_reply_value(ctx, "number", numbuf);
		break;
	case LUA_TSTRING:
		/*
		 * The response is "string " + hex + '\n'.  Lua-side values
		 * are not bounded by SHDICT_VALUE_MAX, so refuse values
		 * whose hex form would not fit the response buffer instead
		 * of letting scnprintf() truncate them silently.
		 */
		if (snap.s->len > (SHDICT_IO_MAX - 9) / 2) {
			err = shdict_reply_err(ctx, -E2BIG);
			break;
		}
		hex_len = snap.s->len * 2;
		hex = kmalloc(hex_len + 1, GFP_KERNEL);
		if (!hex) {
			err = shdict_reply_err(ctx, -ENOMEM);
			break;
		}
		bin2hex(hex, snap.s->data, snap.s->len);
		hex[hex_len] = '\0';
		err = shdict_reply_value(ctx, "string", hex);
		kfree(hex);
		break;
	default:
		WARN_ON(1);
		err = shdict_reply_err(ctx, -EINVAL);
		break;
	}

	kvcache_snapshot_put(&snap);
	return err;
}

static int shdict_exec(struct shdict_ctx *ctx, char *input, size_t len)
{
	char *tokens[SHDICT_TOKENS_MAX];
	int n;

	/* embedded NULs are control characters, not part of the grammar */
	if (strnlen(input, len) != len)
		return shdict_reply_err(ctx, -EINVAL);

	n = shdict_split(input, tokens, ARRAY_SIZE(tokens));
	if (n < 1)
		return shdict_reply_err(ctx, -EINVAL);

	if (strcmp(tokens[0], "set") == 0) {
		if (n != 6)
			return shdict_reply_err(ctx, -EINVAL);
		return shdict_exec_set(ctx, tokens);
	}
	if (strcmp(tokens[0], "get") == 0) {
		if (n != 4)
			return shdict_reply_err(ctx, -EINVAL);
		return shdict_exec_get(ctx, tokens);
	}
	return shdict_reply_err(ctx, -EINVAL);
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
