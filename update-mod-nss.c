/*
 * Copyright 2017 Ian Pilcher <arequipeno@gmail.com>
 *
 * This program is free software.  You can redistribute it or modify it under
 * the terms of version 2 of the GNU General Public License (GPL), as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY -- without even the implied warranty of MERCHANTIBILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the text of the GPL for more details.
 *
 * Version 2 of the GNU General Public License is available at:
 *
 *   http://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */


#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <pwd.h>

#include <pk11pub.h>
#include <plarena.h>
#include <prerror.h>
#include <certdb.h>
#include <prinit.h>
#include <secder.h>
#include <certt.h>
#include <cert.h>
#include <nss.h>


/*******************************************************************************
 *
 *
 * 	Global variables
 *
 *
 ******************************************************************************/

static const char httpd_conf_dir[] = "/etc/httpd";
static const char acme_cert_dir[] = "/var/lib/acme";

static const char *cert_hostname;

/* Minimum message severity that will be logged */
static int verbosity = LOG_NOTICE;

/* Log messages to syslog/journal instead of stderr? */
static _Bool use_syslog;

/* Effective user and group for NSS database modifications */
static uid_t nss_uid;
static gid_t nss_gid;

/*
 * mod_nss database directory names
 */
#define NSSDB_DIR_PATTERN	"alias-YYYYMMDDHHMMSS"
#define NSSDB_DIR_PTN_SIZE	(sizeof NSSDB_DIR_PATTERN)
#define NSSDB_DIR_PTN_LEN	(NSSDB_DIR_PTN_SIZE - 1)

#define NSSDB_DIR_PREFIX	"alias-"
#define NSSDB_DIR_PFX_SIZE	(sizeof NSSDB_DIR_PREFIX)
#define NSSDB_DIR_PFX_LEN	(NSSDB_DIR_PFX_SIZE - 1)

#define NSSDB_DIR_TSTAMP	"YYYYMMDDHHMMSS"
#define NSSDB_DIR_TS_SIZE	(sizeof NSSDB_DIR_TSTAMP)
#define NSSDB_DIR_TS_LEN	(NSSDB_DIR_TS_SIZE - 1)

static char new_dbdir_name[NSSDB_DIR_PTN_SIZE];
static char old_dbdir_name[NSSDB_DIR_PTN_SIZE];


/*******************************************************************************
 *
 *
 * 	Logging
 *
 *
 ******************************************************************************/

static void
__attribute__((format(printf, 2, 3)))
log_msg(const int severity, const char *const restrict format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (!use_syslog)
		vfprintf(stderr, format, ap);
	else
		vsyslog(severity, format, ap);

	va_end(ap);
}

/* Log DEBUG messages (if enabled) at LOG_INFO, so syslog doesn't drop them */
#define DEBUG(fmt, ...)		do { \
					if (verbosity == LOG_DEBUG) { \
						log_msg(LOG_INFO, \
							"DEBUG: %s:%d: " fmt, \
							__FILE__, __LINE__, \
							##__VA_ARGS__); \
					} \
				} while (0)

#define INFO(fmt, ...)		do { \
					if (verbosity >= LOG_INFO) { \
						log_msg(LOG_INFO, \
							"INFO: %s:%d: " fmt, \
							__FILE__, __LINE__, \
							##__VA_ARGS__); \
					} \
				} while (0)

#define NOTICE(fmt, ...)	log_msg(LOG_NOTICE, \
					"NOTICE: %s:%d: " fmt, \
					__FILE__, __LINE__, ##__VA_ARGS__)

#define WARN(fmt, ...)		log_msg(LOG_WARNING, \
					"WARNING: %s:%d: " fmt, \
					__FILE__, __LINE__, ##__VA_ARGS__)

#define ERROR(fmt, ...)		log_msg(LOG_ERR, \
					"ERROR: %s:%d: " fmt, \
					__FILE__, __LINE__, ##__VA_ARGS__)

#define FATAL(fmt, ...)		do { \
					log_msg(LOG_CRIT, \
						"FATAL: %s:%d: " fmt, \
						__FILE__, __LINE__, \
						##__VA_ARGS__); \
					exit(EXIT_FAILURE); \
				} while (0)

#define NSPR_LANG		PR_LANGUAGE_I_DEFAULT
#define NSS_FATAL(fmt, ...)	do { \
					PRErrorCode err = PR_GetError(); \
					log_msg(LOG_CRIT, \
						"FATAL: %s:%d: NSS error: " \
							"%s: %s\n", \
						__FILE__, __LINE__, \
						PR_ErrorToName(err), \
						PR_ErrorToString(err, \
								 NSPR_LANG)); \
					log_msg(LOG_CRIT, \
						"FATAL: %s:%d: " fmt, \
						__FILE__, __LINE__, \
						##__VA_ARGS__); \
					exit(EXIT_FAILURE); \
				} while (0)


/*******************************************************************************
 *
 *
 * 	Command-line parsing
 *
 *
 ******************************************************************************/

#define USAGE_MESSAGE	"Usage: %s {-h} [-d|-i] [-t|-s] NSS_USER HOSTNAME\n"

#define HELP_MESSAGE	USAGE_MESSAGE \
			"  -h,  --help         show this message\n" \
			"  -t,  --tty          log to stderr\n" \
			"  -s,  --syslog       log to syslog\n" \
			"  -d,  --debug        log debugging (and " \
						"informational) messages\n" \
			"  -i,  --info         log informational messages\n"

static void
__attribute__((noreturn))
show_help(const char *const argv0)
{
	printf(HELP_MESSAGE, argv0 == NULL ? "(unknown)" : argv0);
	exit(EXIT_SUCCESS);
}

static _Bool arg_matches(const char *const restrict arg,
			 const char *const restrict short_opt,
			 const char *const restrict long_opt)
{
	return (short_opt != NULL && strcmp(arg, short_opt) == 0)
		|| (long_opt != NULL && strcmp(arg, long_opt) == 0);
}

static void parse_args(const int argc, char **const argv)
{
	_Bool allow_root = 0;
	struct passwd *pw;
	int i;

	/* Make an intelligent guess about where to send errors */
	use_syslog = !isatty(fileno(stderr));

	if (argc < 3) {
		if (argc == 2 && arg_matches(argv[1], "-h", "--help"))
			show_help(argv[0]);
		FATAL(USAGE_MESSAGE, argv[0] == NULL ? "(unknown)" : argv[0]);
	}

	for (i = 1; i < argc - 2; ++i) {

		if (arg_matches(argv[i], "-h", "--help")) {
			show_help(argv[0]);
		}
		else if (arg_matches(argv[i], "-d", "--debug")) {
			verbosity = LOG_DEBUG;
		}
		else if (arg_matches(argv[i], "-i", "--info")) {
			verbosity = LOG_INFO;
		}
		else if (arg_matches(argv[i], "-t", "--tty")) {
			use_syslog = 0;
		}
		else if (arg_matches(argv[i], "-s", "--syslog")) {
			use_syslog = 1;
		}
		else if (arg_matches(argv[i], NULL, "--allow-root")) {
			allow_root = 1;
		}
		else {
			if (!use_syslog)
				ERROR(USAGE_MESSAGE, argv[0]);
			FATAL("Invalid option: %s\n", argv[i]);
		}
	}

	errno = 0; pw = getpwnam(argv[i]);
	if (pw == NULL) {
		if (errno == 0)
			FATAL("User does not exist: %s\n", argv[i]);
		else
			FATAL("Failed to get user info: %s: %m\n", argv[i]);
	}

	nss_uid = pw->pw_uid;
	if (nss_uid == 0 && !allow_root)
		FATAL("NSS user is root but --allow-root not specified\n");

	nss_gid = pw->pw_gid;
	if (nss_gid == 0 && !allow_root)
		FATAL("NSS group is root but --allow-root not specified\n");

	cert_hostname = argv[i + 1];

	DEBUG("  user = %s\n", pw->pw_name);
	DEBUG("  hostname = %s\n", cert_hostname);
}


/*******************************************************************************
 *
 *
 * 	mod_nss database directories
 *
 *
 ******************************************************************************/

/*
 * Finds the existing mod_nss database directory (by following the
 * /etc/httpd/alias symlink).  Also populates old_nssdb_dir.
 *
 * Returns a file descriptor that refers to the existing directory.  Link info
 * is returned via linkst.
 */
static int old_nssdb_dir(const int httpd_conf_dirfd, struct stat *const linkst)
{
	char *fdpath;
	int fd;

	fd = openat(httpd_conf_dirfd, "alias", O_RDONLY | O_NOFOLLOW | O_PATH);
	if (fd < 0) {
		FATAL("Failed to open symbolic link: %s/alias: %m\n",
		      httpd_conf_dir);
	}

	if (fstat(fd, linkst) < 0) {
		FATAL("Failed to read symbolic link info: %s/alias: %m\n",
		      httpd_conf_dir);
	}

	if (!S_ISLNK(linkst->st_mode))
		FATAL("Not a symbolic link: %s/alias\n", httpd_conf_dir);

	if (linkst->st_size > (off_t)NSSDB_DIR_PTN_LEN) {
		FATAL("Symbolic link target too long: %s/alias\n",
		      httpd_conf_dir);
	}

	memset(old_dbdir_name, 0, NSSDB_DIR_PTN_SIZE);

	if (readlinkat(fd, "", old_dbdir_name, NSSDB_DIR_PTN_LEN) < 0) {
		FATAL("Failed to read symbolic link target: %s/alias: %m\n",
		      httpd_conf_dir);
	}

	if (memchr(old_dbdir_name, '/', NSSDB_DIR_PTN_LEN) != NULL) {
		FATAL("Symbolic link target invalid: %s/alias -> %s\n",
		      httpd_conf_dir, old_dbdir_name);
	}

	if (asprintf(&fdpath, "/proc/self/fd/%d", fd) < 0)
		FATAL("Failed to format path: /proc/self/fd/%d: %m\n", fd);

	free(fdpath);

	if (close(fd) < 0) {
		FATAL("Failed to close symbolic link: %s/alias: %m\n",
		      httpd_conf_dir);
	}

	fd = openat(httpd_conf_dirfd, old_dbdir_name,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (fd < 0) {
		FATAL("Failed to open directory: %s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name);
	}

	return fd;
}

/*
 * Create a directory for the new copy of the mod_nss database.  Also populates
 * new_dbdir_name.
 *
 * Returns a file descriptor that refers to the new directory.
 */
static int new_nssdb_dir(const int httpd_conf_dirfd)
{
	/* Points to the timestamp in new_dbdir_name */
	static char *const new_dbdir_name_ts =
					new_dbdir_name + NSSDB_DIR_PFX_LEN;

	struct tm *tm;
	time_t now;
	int dirfd;

	now = time(NULL);
	tm = gmtime(&now);

	/* Am I being too optimistic? */
	if (tm->tm_year > 9999 - 1900) {
		FATAL("This program is not supported in the year %d\n",
		      tm->tm_year + 1900);
	}

	memcpy(new_dbdir_name, NSSDB_DIR_PREFIX, NSSDB_DIR_PFX_LEN);

	if (strftime(new_dbdir_name_ts, NSSDB_DIR_TS_SIZE, "%Y%m%d%H%M%S", tm)
			!= NSSDB_DIR_TS_LEN)  {
		FATAL("Failed to format timestamp (%ld)\n", now);
	}

	if (mkdirat(httpd_conf_dirfd, new_dbdir_name, 0750) < 0) {
		FATAL("Failed to create directory: %s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	dirfd = openat(httpd_conf_dirfd, new_dbdir_name,
		       O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (dirfd < 0) {
		FATAL("Failed to open directory: %s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	if (fchownat(dirfd, "", -1, nss_gid, AT_EMPTY_PATH) < 0) {
		FATAL("Failed to change owner of directory: %s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	return dirfd;
}

/*******************************************************************************
 *
 *
 * 	mod_nss database file-related functions
 *
 *
 ******************************************************************************/

/*
 * Copies the contents of the regular file refered to by src to the regular file
 * refered to by dest.
 *
 * path:  The path of the source and destination files, relative to the old and
 *	  new mod_nss database directories respectively.  It must NOT begin with
 * 	  a / (and it must not be an empty string).
 */
static void copy_file_contents(const int src, const int dest,
			       const char *const restrict path,
			       const struct stat *const restrict srcst)
{
	void *smap, *dmap;
	struct stat st;

	assert(*path != '/' && *path != 0);

	if (srcst->st_size == 0)
		return;

	if (srcst->st_size < 0 || srcst->st_size > SSIZE_MAX) {
		FATAL("File size invalid: %s/%s/%s\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	if (fallocate(dest, 0, 0, srcst->st_size) < 0) {
		FATAL("Failed to allocate file: %s/%s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	smap = mmap(NULL, srcst->st_size, PROT_READ, MAP_PRIVATE, src, 0);
	if (smap == MAP_FAILED) {
		FATAL("Failed to map file: %s/%s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	dmap = mmap(NULL, srcst->st_size, PROT_WRITE, MAP_SHARED, dest, 0);
	if (dmap == MAP_FAILED) {
		FATAL("Failed to map file: %s/%s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	memcpy(dmap, smap, srcst->st_size);

	if (munmap(smap, srcst->st_size) < 0) {
		FATAL("Failed to unmap file: %s/%s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	if (munmap(dmap, srcst->st_size) < 0) {
		FATAL("Failed to unmap file: %s/%s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	if (fstat(src, &st) < 0) {
		FATAL("Failed to read file info: %s/%s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	if (st.st_mtim.tv_sec != srcst->st_mtim.tv_sec
			|| st.st_mtim.tv_nsec != srcst->st_mtim.tv_nsec) {
		FATAL("File changed during copy: %s/%s/%s\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}
}

/*
 * Copies the files that make up an NSS database (cert8.db, key3.db, and
 * secmod.db) from the directory refered to by srcdir to the directory
 * refered to by destdir.  Timestamps (mtime and atime) are also copied.
 */
static void copy_nssdb_files(const int srcdir, const int destdir)
{
	static const char *const names[] = {
		"cert8.db", "key3.db", "secmod.db", NULL
	};

	struct timespec times[2];
	const char *const *name;
	struct stat srcst;
	int src, dest;

	for (name = names; *name != NULL; ++name) {

		src = openat(srcdir, *name, O_RDONLY | O_NOFOLLOW);
		if (src < 0) {
			FATAL("Failed to open file: %s/%s/%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, *name);
		}

		if (fstat(src, &srcst) < 0) {
			FATAL("Failed to read file info: %s/%s/%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, *name);
		}

		if (!S_ISREG(srcst.st_mode)) {
			FATAL("Not a regular file: %s/%s/%s\n",
			      httpd_conf_dir, old_dbdir_name, *name);
		}

		dest = openat(destdir, *name, O_RDWR | O_CREAT | O_EXCL, 0660);
		if (dest < 0) {
			FATAL("Failed to create file: %s/%s/%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, *name);
		}

		copy_file_contents(src, dest, *name, &srcst);

		if (fchown(dest, -1, nss_gid) < 0) {
			FATAL("Failed to change owner of file: %s/%s/%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, *name);
		}

		if (fchmod(dest, 0660) < 0) {
			FATAL("Failed to set permissions: %s/%s/%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, *name);
		}

		times[0] = srcst.st_atim;
		times[1] = srcst.st_mtim;

		if (futimens(dest, times) < 0) {
			FATAL("Failed to set timestamp: %s/%s/%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, *name);
		}

		if (close(src) < 0) {
			FATAL("Failed to close file: %s/%s/%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, *name);
		}

		if (close(dest) < 0) {
			FATAL("Failed to close file: %s/%s/%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, *name);
		}
	}
}

/*
 * Open a "copy" of a file descriptor.
 */
static int copy_fd(const int orig, const int flags)
{
	char *path;
	int fd;

	if (asprintf(&path, "/proc/self/fd/%d", orig) < 0)
		FATAL("Failed to format path: /proc/self/fd/%d: %m\n", orig);

	fd = open(path, flags);
	if (fd < 0)
		FATAL("Failed to open file: %s: %m\n", path);

	free(path);

	return fd;
}

/*
 * Create a new symbolic link and return a file descriptor that refers to it.
 *
 * path:	The path of the symbolic link to be created, relative to
 *		either old_nssdb_dir, new_nssdb_dir, or httpd_conf_dir.  If
 * 		dbdir_name is an empty string, path must NOT begin with a /;
 * 		otherwise it MUST begin with a slash.  In either case, it must
 * 		not be an empty string.
 *
 * name:	The name of the symbolic link to be created.  (path always ends
 * 		with name.)
 *
 * dbdir_name:  The name of the directory (under httpd_conf_dir) relative to
 * 		which path is interpreted -- either old_dbdir_name,
 * 		new_dbdir_name, or an empty string which indicates that the
 * 		symbolic link is being created in httpd_conf_dir itself.
 */
static int create_symlink(const int dirfd,
			  const char *const restrict target,
			  const char *const restrict name,
			  const char *const restrict dbdir_name,
			  const char *const restrict path)
{
	char *new_target;
	struct stat st;
	int fd;

	if (*dbdir_name == 0)
		assert(*path != '/'&& *path != 0);
	else
		assert(path[0] == '/' && path[1] != 0);

	if (symlinkat(target, dirfd, name) < 0) {
		FATAL("Failed to create symbolic link: %s/%s%s: %m\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_PATH);
	if (fd < 0) {
		FATAL("Failed to open symbolic link: %s/%s%s: %m\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	if (fstat(fd, &st) < 0) {
		FATAL("Failed to read symbolic link info: %s/%s%s: %m\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	if (!S_ISLNK(st.st_mode)) {
		FATAL("Not a symbolic link: %s/%s%s\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	if (st.st_size <= 0 || st.st_size > SSIZE_MAX - 1) {
		FATAL("Symbolic link target size invalid: %s/%s%s\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	if ((size_t)st.st_size != strlen(target)) {
		FATAL("Symbolic link target changed: %s/%s%s\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	new_target = malloc(st.st_size + 1);
	if (new_target == NULL)
		FATAL("Memory allocation failed: %m\n");

	memset(new_target, 0, st.st_size + 1);

	if (readlinkat(fd, "", new_target, st.st_size) < 0) {
		FATAL("Failed to read symbolic link target: %s/%s%s: %m\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	if (memcmp(target, new_target, st.st_size) != 0) {
		FATAL("Symbolic link target changed: %s/%s%s: %m\n",
		      httpd_conf_dir, dbdir_name, path);
	}

	free(new_target);

	return fd;
}

/*
 * Copy ownership, permissions, and (optionally) timestamps from src to dest.
 * (Permissions are not copied for symbolic links.)
 *
 * path:  The path of the source and destination files, relative to the old and
 *	  new mod_nss database directories respectively.  It MUST begin with a /
 * 	  or be an empty string.
 */
static void copy_metadata(const int src, const int dest,
			  const char *const restrict path,
			  const struct stat *const restrict srcst,
			  const _Bool copy_timestamps)
{
	struct timespec times[2];
	char *sproc, *dproc;

	assert(*path == '/' || *path == 0);

	if (fchownat(dest, "", srcst->st_uid, srcst->st_gid, AT_EMPTY_PATH)
			< 0) {
		FATAL("Failed to set ownership: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	if (!S_ISLNK(srcst->st_mode)) {

		/*
		 * Since src doesn't refer to a symlink, it isn't an O_PATH
		 * file descriptor, and fchmod will work.
		 */
		if (fchmod(dest, srcst->st_mode & 07777) < 0) {
			FATAL("Failed to set permissions: %s/%s%s: %m\n",
				httpd_conf_dir, new_dbdir_name, path);
		}
	}

	/*
	 * utimensat doesn't accept AT_EMPTY_PATH, so use the links
	 * in /proc/self/fd/ to achieve the desired effect.
	 */

	if (asprintf(&sproc, "/proc/self/fd/%d", src) < 0)
		FATAL("Failed to format path: /proc/self/fd/%d: %m\n", src);

	if (asprintf(&dproc, "/proc/self/fd/%d", dest) < 0)
		FATAL("Failed to format path: /proc/self/fd/%d: %m\n", dest);

	if (copy_timestamps) {

		times[0] = srcst->st_atim;
		times[1] = srcst->st_mtim;

		if (utimensat(-1, dproc, times, 0) < 0) {
			FATAL("Failed to set timestamp: %s/%s%s: %m\n",
				httpd_conf_dir, new_dbdir_name, path);
		}
	}

	free(dproc);
	free(sproc);
}

/*
 * Atomically update the /etc/httpd/alias symlink.
 */
static void update_nssdb_symlink(const int httpd_conf_dirfd,
				 const struct stat *const restrict linkst)
{
	int fd;

	fd = create_symlink(httpd_conf_dirfd, new_dbdir_name,
			    "alias.new", "", "alias.new");

	if (fchownat(fd, "", linkst->st_uid, linkst->st_gid, AT_EMPTY_PATH)
			< 0) {
		FATAL("Failed to set symbolic link ownership: "
		      "%s/alias.new: %m\n",
		      httpd_conf_dir);
	}

	if (close(fd) < 0) {
		FATAL("Failed to close symbolic link: %s/alias.new: %m\n",
		      httpd_conf_dir);
	}

	if (renameat(httpd_conf_dirfd, "alias.new", httpd_conf_dirfd, "alias")
			< 0) {
		FATAL("Failed to rename symbolic link: "
		      "%s/alias.new to %s/alias: %m\n",
		      httpd_conf_dir, httpd_conf_dir);
	}
}


/*******************************************************************************
 *
 *
 * 	Copy contents of old mod_nss database directory to new directory
 *
 *
 ******************************************************************************/

/*
 * See copy_nssdb_dir().
 *
 * If the named file does not exist in the directory refered to by destdir,
 * it is copied from the directory refered to by srcdir.
 *
 * If the file already exists, only its metadata (ownership and permissions) are
 * copied.
 *
 * path:  The path of the source and destination files, relative to the old and
 *	  new mod_nss database directories respectively.  It MUST begin with a /
 * 	  (and it cannot be an empty string).
 *
 * name:  The name of the source and destination files.  (path always ends with
 * 	  name.)
 */
static void copy_file(const int srcpfd, const int destdir,
		      const char *const restrict name,
		      const char *const restrict path,
		      const struct stat *const restrict srcst)
{
	_Bool copy_timestamps;
	int src, dest;

	assert(path[0] == '/' && path[1] != 0);

	src = copy_fd(srcpfd, O_RDONLY);

	dest = openat(destdir, name, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (dest < 0) {

		if (errno != EEXIST) {
			FATAL("Failed to create file: %s/%s%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, path);
		}

		/*
		 * If the file already exists, assume that it's one of the
		 * mod_nss database files that was copied earlier.
		 */

		dest = openat(destdir, name, O_WRONLY | O_NOFOLLOW);
		if (dest < 0) {
			FATAL("Failed to open file: %s/%s%s: %m\n",
			      httpd_conf_dir, new_dbdir_name, path);
		}

		copy_timestamps = 0;
	}
	else {
		/* Skip leading / in path for copy_file_contents() */
		copy_file_contents(src, dest, path + 1, srcst);
		copy_timestamps = 1;
	}

	copy_metadata(src, dest, path, srcst, copy_timestamps);

	if (close(src) < 0) {
		FATAL("Failed to close file: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	if (close(dest) < 0) {
		FATAL("Failed to close file: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}
}

/*
 * See copy_nssdb_dir().
 *
 * Create a symbolic link in the directory refered to by destdir.  The link
 * target is copied from the symbolic link refered to by src.
 *
 * See copy_file() for the path and name parameters.
 */
static void copy_link(const int src, const int destdir,
		      const char *const restrict name,
		      const char *const restrict path,
		      const struct stat *const restrict srcst)
{
	char *target;
	int dest;

	assert(path[0] == '/' && path[1] != 0);

	if (srcst->st_size <= 0 || srcst->st_size > SSIZE_MAX - 1) {
		FATAL("Symbolic link target size invalid: %s/%s%s\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	target = malloc(srcst->st_size + 1);
	if (target == NULL)
		FATAL("Memory allocation failed: %m\n");

	memset(target, 0, srcst->st_size + 1);

	if (readlinkat(src, "", target, srcst->st_size) < 0) {
		FATAL("Failed to read symbolic link target: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	dest = create_symlink(destdir, target, name, new_dbdir_name, path);

	copy_metadata(src, dest, path, srcst, /* copy_timestamps = */ 1);

	if (close(dest) < 0) {
		FATAL("Failed to close symbolic link: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	free(target);
}

/* Forward declaration for recursive call */
static void copy_dir_contents(int, int, const char *);

/*
 * See copy_nssdb_dir().
 *
 * Copy the named subdirectory from srcdir to destdir.
 *
 * See copy_file() for the path and name parameters.
 */
static void copy_subdir(const int srcpfd, const int destdir,
			const char *const restrict name,
			const char *const restrict path,
			const struct stat *const restrict srcst)
{
	int src, dest;

	assert(path[0] == '/' && path[1] != 0);

	src = copy_fd(srcpfd, O_RDONLY | O_DIRECTORY);

	if (mkdirat(destdir, name, 0700) < 0) {
		FATAL("Failed to create directory: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	dest = openat(destdir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (dest < 0) {
		FATAL("Failed to open directory: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}

	copy_dir_contents(src, dest, path);
	copy_metadata(src, dest, path, srcst, /* copy_timestamps = */ 1);

	if (close(src) < 0) {
		FATAL("Failed to close directory: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, path);
	}

	if (close(dest) < 0) {
		FATAL("Failed to close directory: %s/%s%s: %m\n",
		      httpd_conf_dir, new_dbdir_name, path);
	}
}

/*
 * See copy_nssdb_dir().
 *
 * Copy the contents of the directory refered to by srcdir to the directory
 * refered to by by destdir.
 *
 * subdir is the path to srcdir and destdir, relative to old_nssdb_dir and
 * new_nssdb_dir respectively.
 *
 * subdir:  The path of the source and destination directories, relative to the
 * 	    old and new mod_nss database directories respectively.  It MUST
 * 	    begin with a / or be an empty string.
 */
static void copy_dir_contents(const int srcdir, const int destdir,
			      const char *const subdir)
{
	struct dirent *d;
	struct stat st;
	int dirfd, src;
	char *path;
	DIR *sdir;

	assert(*subdir == '/' || *subdir == 0);

	/* Get an independent file descriptor for the directory stream */
	dirfd = copy_fd(srcdir, O_RDONLY | O_DIRECTORY);

	sdir = fdopendir(dirfd);
	if (sdir == NULL) {
		FATAL("Failed to open directory stream: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}

	while ((errno = 0, d = readdir(sdir)) != NULL) {

		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;

		if (asprintf(&path, "%s/%s", subdir, d->d_name) < 0) {
			FATAL("Failed to format path: %s/%s: %m\n",
			      subdir, d->d_name);
		}

		src = openat(srcdir, d->d_name,
			     O_RDONLY  | O_NOFOLLOW | O_PATH);
		if (src < 0) {
			FATAL("Failed to open file: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		if (fstat(src, &st) < 0) {
			FATAL("Failed to read file info: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		switch (st.st_mode & S_IFMT) {

			case S_IFREG:
				copy_file(src, destdir, d->d_name, path, &st);
				break;

			case S_IFLNK:
				copy_link(src, destdir, d->d_name, path, &st);
				break;

			case S_IFDIR:
				copy_subdir(src, destdir, d->d_name, path, &st);
				break;

			default:
				FATAL("Unsupported file type: %s/%s%s\n",
				      httpd_conf_dir, old_dbdir_name, path);
		}

		if (close(src) < 0) {
			FATAL("Failed to close file: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		free(path);
	}
	if (errno != 0) {
		FATAL("Failed to read directory: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}

	if (closedir(sdir) < 0) {
		FATAL("Failed to close directory stream: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}
}

/*
 * Recursively copies the contents of the directory refered to by srcdir
 * (old_dbdir_name) to the directory refered to by destdir (new_dbdir_name).
 * Ownership, permissions, and SELinux contexts are also copied.  Timestamps
 * (atime and mtime) are copied for files that don't already exist in the
 * destination directory.
 *
 * Files that already exist in the destination directory (NSS database files)
 * are not overwritten, nor are their timestamps modified.  Ownership,
 * permissions, and SELinux contexts ARE copied from the corresponding file in
 * the source directory.
 *
 * Only regular files, symbolic links, and subdirectories may exist in the
 * source directory; the presence of any other type of filesystem object is a
 * fatal error.  The presence of any pre-existing filesystem object other than
 * a regular file in the destination directory is also a fatal error (if its
 * relative path matches that of an object in the source directory).
 *
 * Call graph:
 *
 *   copy_nssdb_dir
 *     │
 *     └─> copy_dir_contents <──────────┐
 *          │                           │
 *          ├─> copy_subdir ────────────┘
 *          │
 *          ├─> copy_file
 *          │
 *          └─> copy_link
 */
static void copy_nssdb_dir(const int srcdir, const int destdir)
{
	struct stat srcst;

	copy_dir_contents(srcdir, destdir, "");

	if (fstat(srcdir, &srcst) < 0) {
		FATAL("Failed to read directory info: %s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name);
	}

	copy_metadata(srcdir, destdir, "", &srcst, /* copy_timestamps = */ 0);
}


/*******************************************************************************
 *
 *
 * 	Delete the old mod_nss database directory
 *
 *
 ******************************************************************************/

/*
 * See delete_old_nssdb_dir().
 *
 * Deletes all files, symbolic links, and subdirectories in the directory
 * refered to by dirfd.
 *
 * subdir:  The path of the directory refered to by dirfd, relative to the old
 * 	    mod_nss database directory.  It MUST begin with a / or be an empty
 * 	    string.
 */
static void delete_dir_contents(const int dirfd,
				const char *const restrict subdir)
{
	struct dirent *d;
	struct stat st;
	int fd, flags;
	char *path;
	DIR *dir;

	assert(*subdir == '/' || *subdir == 0);

	/* Get an independent file descriptor for the directory stream */
	fd = copy_fd(dirfd, O_RDONLY | O_DIRECTORY);

	dir = fdopendir(fd);
	if (dir == NULL) {
		FATAL("Failed to open directory stream: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}

	while ((errno = 0, d = readdir(dir)) != NULL) {

		if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
			continue;

		if (asprintf(&path, "%s/%s", subdir, d->d_name) < 0) {
			FATAL("Failed to format path: %s/%s: %m\n",
			      subdir, d->d_name);
		}

		fd = openat(dirfd, d->d_name, O_RDONLY  | O_NOFOLLOW | O_PATH);
		if (fd < 0) {
			FATAL("Failed to open file: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		if (fstat(fd, &st) < 0) {
			FATAL("Failed to read file info: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		if (S_ISDIR(st.st_mode)) {
			delete_dir_contents(fd, path);
			flags = AT_REMOVEDIR;
		}
		else {
			flags = 0;
		}

		if (unlinkat(dirfd, d->d_name, flags) < 0) {
			FATAL("Failed to delete file: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		if (close(fd) < 0) {
			FATAL("Failed to close file: %s/%s%s: %m\n",
			      httpd_conf_dir, old_dbdir_name, path);
		}

		free(path);
	}
	if (errno != 0) {
		FATAL("Failed to read directory: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}

	if (closedir(dir) < 0) {
		FATAL("Failed to close directory stream: %s/%s%s: %m\n",
		      httpd_conf_dir, old_dbdir_name, subdir);
	}
}

/*
 * Recursively deletes the old NSS database directory.
 */
static void delete_old_nssdb_dir(const int httpd_conf_dirfd,
				 const int old_nssdb_dirfd)
{
	delete_dir_contents(old_nssdb_dirfd, "");

	if (unlinkat(httpd_conf_dirfd, old_dbdir_name, AT_REMOVEDIR) < 0) {
		FATAL("Failed to remove directory: %s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name);
	}
}


/*******************************************************************************
 *
 *
 * 	mod_nss database stuff
 *
 *
 ******************************************************************************/

static PK11SlotInfo *init_libnss(const int new_nssdb_dirfd)
{
	PK11SlotInfo *slot;

	if (fchdir(new_nssdb_dirfd) < 0) {
		FATAL("Failed to change directory: %s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	if (NSS_InitReadWrite(".") != SECSuccess) {
		NSS_FATAL("Failed to open NSS database: %s/%s\n",
			  httpd_conf_dir, new_dbdir_name);
	}

	slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		NSS_FATAL("Failed to open NSS database slot: %s/%s\n",
			  httpd_conf_dir, new_dbdir_name);
	}

	if (!PK11_IsFriendly(slot)) {
		FATAL("NSS database requires authentication: %s/%s\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	return slot;
}

static void shutdown_libnss(PK11SlotInfo *const slot)
{
	PK11_FreeSlot(slot);

	if (NSS_Shutdown() != SECSuccess) {
		NSS_FATAL("Failed to close NSS database: %s/%s\n",
			  httpd_conf_dir, new_dbdir_name);
	}

	PL_ArenaFinish();

	if (PR_Cleanup() != PR_SUCCESS)
		NSS_FATAL("Failed to shut down NSPR library\n");
}

static CERTCertificate *new_certificate(void)
{
	CERTCertificate *cert;
	char *cert_file, *pem;
	ssize_t bytes_read;
	struct stat st;
	int fd;

	if (asprintf(&cert_file, "%s/%s.crt", acme_cert_dir, cert_hostname)
			< 0) {
		FATAL("Failed to format path: %s/%s.crt: %m\n",
		      acme_cert_dir, cert_hostname);
	}

	fd = open(cert_file, O_RDONLY);
	if (fd < 0)
		FATAL("Failed to open file: %s: %m\n", cert_file);

	if (fstat(fd, &st) < 0)
		FATAL("Failed to read file info: %s: %m\n", cert_file);

	if (st.st_size <= 0 || st.st_size > SSIZE_MAX)
		FATAL("File size invalid: %s\n", cert_file);

	pem = malloc(st.st_size);
	if (pem == NULL)
		FATAL("Memory allocation failed: %m\n");

	bytes_read = read(fd, pem, st.st_size);
	if (bytes_read < 0)
		FATAL("Failed to read file: %s: %m\n", cert_file);
	if (bytes_read != st.st_size)
		FATAL("Failed to read complete file: %s\n", cert_file);

	if (close(fd) < 0)
		FATAL("Failed to close file: %s: %m\n", cert_file);

	cert = CERT_DecodeCertFromPackage(pem, st.st_size);
	if (cert == NULL)
		NSS_FATAL("Failed to parse certificate: %s\n", cert_file);

	free(pem);
	free(cert_file);

	return cert;
}

static const char *format_not_after(const CERTCertificate *const cert)
{
	static const char time_format[] = "%a %b %d %H:%M:%S %Y UTC";
	static char buf[100];

	PRExplodedTime etime;
	PRTime prtime;

	if (cert->validity.notAfter.type == siUTCTime) {

		if (DER_UTCTimeToTime(&prtime, &cert->validity.notAfter)
				!= SECSuccess) {
			NSS_FATAL("Failed to decode ASN.1 time "
				  "in certificate for %s\n",
				  cert->nickname);
		}
	}
	else if (cert->validity.notAfter.type == siGeneralizedTime) {

		if (DER_GeneralizedTimeToTime(&prtime, &cert->validity.notAfter)
				!= SECSuccess) {
			NSS_FATAL("Failed to decode ASN.1 time "
				  "in certificate for %s\n",
				  cert->nickname);
		}
	}
	else {
		FATAL("Unknown ASN.1 time type in certificate for %s\n",
		      cert->nickname);
	}

	PR_ExplodeTime(prtime, PR_GMTParameters, &etime);
	PR_FormatTime(buf, sizeof buf, time_format, &etime);

	return buf;
}

static void remove_old_certs(PK11SlotInfo *const slot)
{
	CERTCertListNode *node;
	CERTCertList *list;
	unsigned deleted;

	list = PK11_ListCertsInSlot(slot);
	if (list == NULL) {
		NSS_FATAL("Failed to read certificates from NSS database: "
			  "%s/%s\n",
			  httpd_conf_dir, new_dbdir_name);
	}

	INFO("Deleting existing certificates for %s from NSS database: %s/%s\n",
	     cert_hostname, httpd_conf_dir, new_dbdir_name);

	for (	deleted = 0,
		node = CERT_LIST_HEAD(list);
				!CERT_LIST_END(node, list);
						node = CERT_LIST_NEXT(node)) {

		DEBUG("  %s: expires %s\n", node->cert->nickname,
		      format_not_after(node->cert));

		if (strcmp(node->cert->nickname, cert_hostname) != 0) {
			DEBUG("    ... ignoring\n");
			continue;
		}

		DEBUG("    ... DELETING\n");

		if (SEC_DeletePermCertificate(node->cert) != SECSuccess) {
			NSS_FATAL("Failed to delete certificate for %s "
				  "expiring %s from NSS database: %s/%s\n",
				  cert_hostname, format_not_after(node->cert),
				  httpd_conf_dir, new_dbdir_name);
		}

		++deleted;
	}

	INFO("Deleted %u existing certificate(s)\n", deleted);

	CERT_DestroyCertList(list);
}

static void add_new_cert(PK11SlotInfo *const restrict slot,
			 CERTCertificate *const restrict cert)
{
	if (PK11_ImportCert(slot, cert, 0, cert_hostname, 0) != SECSuccess) {
		NSS_FATAL("Failed to add certificate for %s to NSS database: "
			  "%s/%s\n",
			  cert_hostname, httpd_conf_dir, new_dbdir_name);
	}

	NOTICE("Updated mod_nss certificate for %s\n", cert_hostname);
	NOTICE("New certificate valid until %s\n", format_not_after(cert));
}


/*******************************************************************************
 *
 *
 * 	main()
 *
 *
 ******************************************************************************/

static void set_effective_user(const uid_t uid, const gid_t gid)
{
	if (setegid(gid) != 0) {
		FATAL("Failed to change effective GID to %" PRIdMAX ": %m\n",
		      (intmax_t)gid);
	}

	if (seteuid(uid) != 0) {
		FATAL("Failed to change effective UID to %" PRIdMAX ": %m\n",
		      (intmax_t)uid);
	}

	if (geteuid() != uid) {
		FATAL("Effective UID not really changed (still %" PRIdMAX ")\n",
		      (intmax_t)geteuid());
	}

	if (getegid() != gid) {
		FATAL("Effective GID not really changed (still %" PRIdMAX ")\n",
		      (intmax_t)getegid());
	}

	DEBUG("Effective uid/gid changed to %" PRIdMAX "/%" PRIdMAX "\n",
	      (intmax_t)uid, (intmax_t)gid);
}

int main(int argc, char **const argv)
{
	int httpd_conf_dirfd, new_nssdb_dirfd, old_nssdb_dirfd;
	CERTCertificate *cert;
	PK11SlotInfo *slot;
	struct stat linkst;
	uid_t saved_uid;
	gid_t saved_gid;

	parse_args(argc, argv);

	httpd_conf_dirfd = open(httpd_conf_dir, O_RDONLY | O_DIRECTORY);
	if (httpd_conf_dirfd < 0)
		FATAL("Failed to open directory: %s: %m\n", httpd_conf_dir);

	old_nssdb_dirfd = old_nssdb_dir(httpd_conf_dirfd, &linkst);
	new_nssdb_dirfd = new_nssdb_dir(httpd_conf_dirfd);
	copy_nssdb_files(old_nssdb_dirfd, new_nssdb_dirfd);

	saved_uid = geteuid();
	saved_gid = getegid();
	set_effective_user(nss_uid, nss_gid);

	slot = init_libnss(new_nssdb_dirfd);
	cert = new_certificate();
	remove_old_certs(slot);
	add_new_cert(slot, cert);
	CERT_DestroyCertificate(cert);
	shutdown_libnss(slot);

	set_effective_user(saved_uid, saved_gid);

	copy_nssdb_dir(old_nssdb_dirfd, new_nssdb_dirfd);
	update_nssdb_symlink(httpd_conf_dirfd, &linkst);

	delete_old_nssdb_dir(httpd_conf_dirfd, old_nssdb_dirfd);

	if (close(new_nssdb_dirfd) < 0) {
		FATAL("Failed to close directory: %s/%s: %m\n",
		      httpd_conf_dir, new_dbdir_name);
	}

	if (close(old_nssdb_dirfd) < 0) {
		FATAL("Failed to close directory: %s/%s: %m\n",
		      httpd_conf_dir, old_dbdir_name);
	}

	if (close(httpd_conf_dirfd) < 0)
		FATAL("Failed to close directory: %s: %m\n", httpd_conf_dir);
}
