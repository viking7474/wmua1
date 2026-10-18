/* Copyright 2026 myJB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * myjb_stage — myJB stage that replaces /payload (checkra1n's loaderd) inside
 * legacy_ramdisk.bin (checkra1n 0.12.4b "legacy" chain, iOS 12.0–14.8.1).
 *
 * Boot environment: the kernel boots the ramdisk as root; /usr/lib/dyld is
 * checkra1n's fake dyld (waits for rootfs, reverts the iOS 14 boot snapshot),
 * it execs /patch_dyld.ios (args: <input=/usr/lib/dyld> <output=/binpack/lib/
 * dyld> <exec=/payload>), which patches dyld and then execs /payload via
 * "/bin/sh -c 'exec \"$0\" \"$@\"' /payload" — as PID 1. Later /payload.dylib
 * (injected into the real launchd via DYLD_INSERT_LIBRARIES) remounts the
 * ramdisk and posix_spawns /payload with argv={"stage4entry"}.
 *
 * loaderd (the stock /payload) is a multi-call binary dispatching on argv[0]:
 * launchd | save_kerninfo | ldload | AppImageMounter | checkra1nd | stage4entry
 * — with getpid()==1 force-selecting "launchd"; anything else exits 1 with
 * "this is a checkra1n internal utility, do not run".  This stage therefore
 * must forward argv UNCHANGED (argv[0] included) when chaining to /payload.real,
 * or the second (stage4entry) invocation dies in that guard.
 *
 * v0 (this file): diagnostics only — dump the environment to /dev/console
 * (visible in verbose boot) and chain to the stock loaderd, shipped by the
 * repack as /payload.real.
 *
 * Planned v1+: fakefs (create APFS volume "Xystem", mount + copy real rootfs,
 * install myJB basebin) before chaining.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

#define REAL_LOADER "/payload.real"
#define OUT_LIMIT 48

static int g_console = -1;

static void stage_log(const char *fmt, ...) {
	char buf[1024];
	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(buf) - 2)
		n = (int)sizeof(buf) - 2;
	buf[n++] = '\n';

	if (g_console >= 0)
		(void)write(g_console, buf, (size_t)n);
	(void)write(STDERR_FILENO, buf, (size_t)n);
}

#define STAGE(...) stage_log("[myjb-stage] " __VA_ARGS__)

static void dump_path(const char *path) {
	struct stat st;

	if (stat(path, &st) == 0)
		STAGE("%-46s ok (mode %o, size %lld)", path, (unsigned)(st.st_mode & 07777), (long long)st.st_size);
	else
		STAGE("%-46s stat failed, errno=%d", path, errno);
}

static void dump_dir(const char *path, int max, const char *needle) {
	DIR *d;
	struct dirent *de;
	int shown = 0, total = 0;

	d = opendir(path);
	if (!d) {
		STAGE("dir %s: opendir failed, errno=%d", path, errno);
		return;
	}
	while ((de = readdir(d)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		total++;
		if (needle && !strstr(de->d_name, needle))
			continue;
		if (shown < max) {
			STAGE("  %s/%s", path, de->d_name);
			shown++;
		}
	}
	closedir(d);
	STAGE("dir %s: %d entries (%d shown)", path, total, shown);
}

static void dump_mounts(void) {
	struct statfs *mnts;
	int i, n;

	n = getmntinfo(&mnts, MNT_NOWAIT);
	if (n <= 0) {
		STAGE("getmntinfo failed, errno=%d", errno);
		return;
	}
	STAGE("mount table (%d entries):", n);
	for (i = 0; i < n && i < 64; i++)
		STAGE("  %s (%s) -> %s", mnts[i].f_mntfromname, mnts[i].f_fstypename, mnts[i].f_mntonname);
}

static void dump_system_version(void) {
	const char *path = "/System/Library/CoreServices/SystemVersion.plist";
	char buf[512];
	ssize_t r;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		STAGE("SystemVersion.plist: open failed, errno=%d (rootfs at / ?)", errno);
		return;
	}
	r = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (r <= 0) {
		STAGE("SystemVersion.plist: read failed, errno=%d", errno);
		return;
	}
	buf[r] = 0;
	STAGE("SystemVersion.plist (%d bytes):", (int)r);
	STAGE("%s", buf);
}

static void dump_environ(void) {
	int i;

	if (!environ)
		return;
	for (i = 0; environ[i] && i < 64; i++)
		STAGE("env[%d] %s", i, environ[i]);
}

int main(int argc, char **argv) {
	char **fwd;
	int i;

	g_console = open("/dev/console", O_WRONLY | O_NOCTTY);
	STAGE("myJB stage v0 on the ramdisk (built %s %s)", __DATE__, __TIME__);
	STAGE("pid=%d uid=%u euid=%u gid=%u egid=%u", getpid(), (unsigned)getuid(), (unsigned)geteuid(),
	      (unsigned)getgid(), (unsigned)getegid());
	STAGE("argc=%d argv[0]=%s", argc, (argc > 0 && argv[0]) ? argv[0] : "(null)");

	dump_mounts();
	dump_system_version();
	dump_dir("/", OUT_LIMIT, NULL);
	dump_dir("/dev", OUT_LIMIT, "disk");
	dump_path("/payload.real");
	dump_path("/dev/disk0s1s1");
	dump_path("/dev/disk0s1");
	dump_path("/dev/md0");
	dump_path("/dev/rmd0");
	dump_path("/binpack");
	dump_path("/cores");
	dump_path("/.mount_rw");
	dump_environ();

	fwd = calloc((size_t)argc + 1, sizeof(char *));
	if (!fwd) {
		STAGE("calloc failed");
		return 1;
	}
	fwd[0] = (argc > 0 && argv[0]) ? argv[0] : (char *)REAL_LOADER;
	for (i = 1; i < argc; i++)
		fwd[i] = argv[i];

	STAGE("chaining to %s (argv[0]=%s, pid=%d)", REAL_LOADER, fwd[0], getpid());
	execv(REAL_LOADER, fwd);
	STAGE("execv(%s) failed, errno=%d (%s)", REAL_LOADER, errno, strerror(errno));
	return 1;
}
