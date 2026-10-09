/*
 * fakepwd.c -- answer getpwnam(3)/getpwuid(3) from a file.
 *
 * For a dynamic program (OpenSSH's `ssh`, a shell, anything glibc) on a host
 * that has no /etc/passwd. Tailscale's own static daemon cannot use this; it
 * is shimmed with shim/tsgetent and shim/tsid instead, because it shells out
 * to those commands rather than calling libc.
 *
 * The table is named by $SANDHOME_PASSWD. When it is unset, or a name is not
 * in it, the real libc function is called, so the shim is safe to preload
 * everywhere.
 *
 * Build: cc -O2 -shared -fPIC -o fakepwd.so fakepwd.c -ldl
 * Use:   SANDHOME_PASSWD=/path/passwd LD_PRELOAD=/path/fakepwd.so ssh ...
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef struct passwd *(*pw_nam_fn)(const char *);
typedef struct passwd *(*pw_uid_fn)(uid_t);
typedef int (*pw_nam_r_fn)(const char *, struct passwd *, char *, size_t, struct passwd **);
typedef int (*pw_uid_r_fn)(uid_t, struct passwd *, char *, size_t, struct passwd **);

static const char *db_path(void)
{
	const char *p = getenv("SANDHOME_PASSWD");
	return (p && *p) ? p : NULL;
}

/* Parse one passwd(5) line into pw, pointing at buf. Returns 0, ERANGE or
 * EINVAL; *out is the passwd on success. */
static int parse_line(const char *line, struct passwd *pw, char *buf, size_t len,
		      struct passwd **out)
{
	char tmp[1024];
	char *fields[7];
	char *save = NULL;
	size_t off = 0;
	int n = 0, i;

	if (strlen(line) >= sizeof tmp)
		return EINVAL;
	strcpy(tmp, line);
	tmp[strcspn(tmp, "\r\n")] = 0;

	for (char *tok = strtok_r(tmp, ":", &save); tok && n < 7; tok = strtok_r(NULL, ":", &save))
		fields[n++] = tok;
	if (n < 7)
		return EINVAL;

	for (i = 0; i < 7; i++) {
		size_t fl = strlen(fields[i]) + 1;
		if (off + fl > len)
			return ERANGE;
		memcpy(buf + off, fields[i], fl);
		fields[i] = buf + off;
		off += fl;
	}

	pw->pw_name = fields[0];
	pw->pw_passwd = fields[1];
	pw->pw_uid = (uid_t)strtoul(fields[2], NULL, 10);
	pw->pw_gid = (gid_t)strtoul(fields[3], NULL, 10);
	pw->pw_gecos = fields[4];
	pw->pw_dir = fields[5];
	pw->pw_shell = fields[6];
	*out = pw;
	return 0;
}

/* Look up name (by_uid == 0) or uid (by_uid != 0). Returns 0 when the table
 * answered (found or not), -1 when the caller must fall back to libc. */
static int lookup(const char *name, uid_t uid, int by_uid, struct passwd *pw, char *buf,
		  size_t len, struct passwd **out)
{
	const char *path = db_path();
	FILE *f;
	char line[1024];

	if (!path)
		return -1;
	f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof line, f)) {
		struct passwd *got = NULL;
		if (parse_line(line, pw, buf, len, &got) != 0)
			continue;
		if (by_uid ? (got->pw_uid == uid) : (strcmp(got->pw_name, name) == 0)) {
			*out = pw;
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	*out = NULL;
	return 0;
}

struct passwd *getpwnam(const char *name)
{
	static char buf[4096];
	static struct passwd pw;
	struct passwd *out = NULL;

	if (lookup(name, 0, 0, &pw, buf, sizeof buf, &out) == 0)
		return out;
	pw_nam_fn next = (pw_nam_fn)dlsym(RTLD_NEXT, "getpwnam");
	return next ? next(name) : NULL;
}

struct passwd *getpwuid(uid_t uid)
{
	static char buf[4096];
	static struct passwd pw;
	struct passwd *out = NULL;

	if (lookup(NULL, uid, 1, &pw, buf, sizeof buf, &out) == 0)
		return out;
	pw_uid_fn next = (pw_uid_fn)dlsym(RTLD_NEXT, "getpwuid");
	return next ? next(uid) : NULL;
}

int getpwnam_r(const char *name, struct passwd *pw, char *buf, size_t len, struct passwd **out)
{
	if (lookup(name, 0, 0, pw, buf, len, out) == 0)
		return 0;
	pw_nam_r_fn next = (pw_nam_r_fn)dlsym(RTLD_NEXT, "getpwnam_r");
	return next ? next(name, pw, buf, len, out) : ENOENT;
}

int getpwuid_r(uid_t uid, struct passwd *pw, char *buf, size_t len, struct passwd **out)
{
	if (lookup(NULL, uid, 1, pw, buf, len, out) == 0)
		return 0;
	pw_uid_r_fn next = (pw_uid_r_fn)dlsym(RTLD_NEXT, "getpwuid_r");
	return next ? next(uid, pw, buf, len, out) : ENOENT;
}
