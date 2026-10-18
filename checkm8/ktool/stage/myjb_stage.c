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
 * dyld> <exec=/payload>), which patches dyld and then execs /payload as
 * PID 1.  Later /payload.dylib (injected into the real launchd via
 * DYLD_INSERT_LIBRARIES) remounts the ramdisk and posix_spawns /payload with
 * argv={"stage4entry"}.
 *
 * loaderd (the stock /payload) is a multi-call binary dispatching on argv[0]:
 * launchd | save_kerninfo | ldload | AppImageMounter | checkra1nd | stage4entry
 * — with getpid()==1 force-selecting "launchd"; anything else exits 1 with
 * "this is a checkra1n internal utility, do not run".  This stage therefore
 * must forward argv UNCHANGED (argv[0] included) when chaining to /payload.real,
 * or the second (stage4entry) invocation dies in that guard.
 *
 * v0.1 (this file): diagnostics build.  Every invocation appends a full state
 * dump to several sinks (best-effort), emits the same lines on stderr and
 * syslog (live-relayed to idevicesyslog once the device is up), and pulls the
 * previous-phase log from the ramdisk so multi-phase evidence can be recovered
 * from a single later phase:
 *   - /var/mobile/Media/.myjb-stage.log                 (host AFC / backups)
 *   - /var/mobile/Library/Logs/CrashReporter/myjb-stage.txt  (idevicecrashreport)
 *   - /private/var/tmp/.myjb-stage.log                  (next to the job plists)
 *   - /binpack/lib/.myjb-stage1.log                     (ramdisk, PID1 phase bus)
 *   - /binpack/binpack/.myjb-stage1.log                 (ramdisk, fallback)
 *
 * The observed failure to diagnose: the loader app (bundle kjc.loader, the
 * WinRa1n build, CDHash 2aec95fa…, NOT one of the two CDHashes loaderd
 * whitelists) gets XPC "Connection invalid" ~2 ms after connecting to
 * com.apple.checkra1n.loaderd.  Either the checkra1nd job was never registered
 * (chain broke earlier: md0 remount / stage4entry / ldload / JobLoad) or the
 * service is up but the connection is killed.  These sinks discriminate.
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
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define REAL_LOADER "/payload.real"
#define OUT_LIMIT 48

#define LOG_MEDIA "/var/mobile/Media/.myjb-stage.log"
#define LOG_CRASH "/var/mobile/Library/Logs/CrashReporter/myjb-stage.txt"
#define LOG_TMP "/private/var/tmp/.myjb-stage.log"
#define LOG_RAM1 "/binpack/lib/.myjb-stage1.log"
#define LOG_RAM1B "/binpack/binpack/.myjb-stage1.log"

#define SINK_MAX 8
#define PULL_LIMIT (64 * 1024)

static int g_sinks[SINK_MAX];
static int g_nsink = 0;
static int g_console = -1;

static void
sink_writes(const char *buf, int n) {
	int i;

	for(i = 0; i < g_nsink; i++)
		(void)write(g_sinks[i], buf, (size_t)n);
	if(g_console >= 0)
		(void)write(g_console, buf, (size_t)n);
	(void)write(STDERR_FILENO, buf, (size_t)n);
}

static void
open_sink(const char *path) {
	int fd;

	if(g_nsink >= SINK_MAX)
		return;
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if(fd >= 0)
		g_sinks[g_nsink++] = fd;
}

/*
 * Emits one line to every sink, the console, stderr and syslog.  syslog gets
 * the bare line (openlog ident already tags it) so live idevicesyslog output
 * shows "[myjb-stage][pid] ..." exactly once.
 */
static void
stage_log(const char *fmt, ...) {
	char line[1024];
	char tagged[1152];
	int n, m;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if(n < 0)
		return;
	if(n > (int)sizeof(line) - 1)
		n = (int)sizeof(line) - 1;

	m = snprintf(tagged, sizeof(tagged), "[myjb-stage] %s\n", line);
	if(m > 0 && m < (int)sizeof(tagged))
		sink_writes(tagged, m);

	(void)syslog(LOG_NOTICE, "pid=%d %s", getpid(), line);
}

#define STAGE(...) stage_log(__VA_ARGS__)

static void
dump_path(const char *path) {
	struct stat st;

	if(stat(path, &st) == 0)
		STAGE("%-46s ok (mode %o, size %lld, dev %#llx)", path, (unsigned)(st.st_mode & 07777),
		      (long long)st.st_size, (unsigned long long)st.st_dev);
	else
		STAGE("%-46s stat failed, errno=%d", path, errno);
}

static void
dump_dir(const char *path, int max, const char *needle) {
	DIR *d;
	struct dirent *de;
	int shown = 0, total = 0;

	d = opendir(path);
	if(!d) {
		STAGE("dir %s: opendir failed, errno=%d", path, errno);
		return;
	}
	while((de = readdir(d)) != NULL) {
		if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		total++;
		if(needle && needle[0] && !strstr(de->d_name, needle))
			continue;
		if(shown < max) {
			STAGE("  %s/%s", path, de->d_name);
			shown++;
		}
	}
	closedir(d);
	STAGE("dir %s: %d entries (%d shown)", path, total, shown);
}

static void
dump_mounts(void) {
	struct statfs *mnts;
	int i, n;

	n = getmntinfo(&mnts, MNT_NOWAIT);
	if(n <= 0) {
		STAGE("getmntinfo failed, errno=%d", errno);
		return;
	}
	STAGE("mount table (%d entries):", n);
	for(i = 0; i < n && i < 64; i++)
		STAGE("  %s (%s) -> %s", mnts[i].f_mntfromname, mnts[i].f_fstypename, mnts[i].f_mntonname);
}

static void
dump_statfs(const char *path) {
	struct statfs sf;

	if(statfs(path, &sf) == 0)
		STAGE("statfs %-16s type=%-6s flags=%#x from=%s", path, sf.f_fstypename, sf.f_flags, sf.f_mntfromname);
	else
		STAGE("statfs %-16s failed, errno=%d", path, errno);
}

static void
dump_file(const char *path, int max) {
	int fd, r;
	char buf[4096];

	fd = open(path, O_RDONLY);
	if(fd < 0) {
		STAGE("file %s: open failed, errno=%d", path, errno);
		return;
	}
	STAGE("--- begin %s ---", path);
	while(max > 0 && (r = (int)read(fd, buf, sizeof(buf) - 1)) > 0) {
		if(r > max)
			r = max;
		buf[r] = 0;
		STAGE("%s", buf);
		max -= r;
	}
	close(fd);
	STAGE("--- end %s ---", path);
}

/*
 * Copies an earlier phase's ramdisk log into the current sinks/console/syslog.
 * Called after the sinks are open so a later phase (stage4entry / on-demand
 * service) forwards the PID1-phase log to places that are reachable from the
 * host, or to the live syslog stream.
 */
static void
pull_file(const char *path) {
	int fd, r;
	size_t total = 0;
	char buf[1024];

	fd = open(path, O_RDONLY);
	if(fd < 0)
		return;
	STAGE("--- pulled %s ---", path);
	while((r = (int)read(fd, buf, sizeof(buf) - 1)) > 0 && total < PULL_LIMIT) {
		buf[r] = 0;
		sink_writes(buf, r);
		(void)syslog(LOG_NOTICE, "pull: %s", buf);
		total += (size_t)r;
	}
	close(fd);
	STAGE("--- end pulled %s (%zu bytes) ---", path, total);
}

static void
dump_system_version(void) {
	const char *path = "/System/Library/CoreServices/SystemVersion.plist";
	char buf[512];
	ssize_t r;
	int fd;

	fd = open(path, O_RDONLY);
	if(fd < 0) {
		STAGE("SystemVersion.plist: open failed, errno=%d (rootfs at / ?)", errno);
		return;
	}
	r = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if(r <= 0) {
		STAGE("SystemVersion.plist: read failed, errno=%d", errno);
		return;
	}
	buf[r] = 0;
	STAGE("SystemVersion.plist (%d bytes):", (int)r);
	STAGE("%s", buf);
}

static void
dump_environ(void) {
	int i;

	if(!environ)
		return;
	for(i = 0; environ[i] && i < 64; i++)
		STAGE("env[%d] %s", i, environ[i]);
}

int main(int argc, char **argv) {
	const char *a0;
	const char *phase = "unknown";
	char **fwd;
	int i;

	g_console = open("/dev/console", O_WRONLY | O_NOCTTY);

	a0 = (argc > 0 && argv[0]) ? argv[0] : "";
	if(strstr(a0, "launchd"))
		phase = "launchd";
	else if(strstr(a0, "stage4entry"))
		phase = "stage4entry";
	else if(strstr(a0, "ldload"))
		phase = "ldload";
	else if(strstr(a0, "AppImageMounter"))
		phase = "AppImageMounter";
	else if(strstr(a0, "checkra1nd"))
		phase = "checkra1nd";

	open_sink(LOG_TMP);
	open_sink(LOG_MEDIA);
	open_sink(LOG_CRASH);
	open_sink(LOG_RAM1);
	open_sink(LOG_RAM1B);
	openlog("myjb-stage", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	STAGE("=== myjb-stage v0.1 diag, phase=%s ===", phase);
	STAGE("stage build %s %s, time=%ld", __DATE__, __TIME__, (long)time(NULL));
	STAGE("pid=%d uid=%u euid=%u gid=%u egid=%u", getpid(), (unsigned)getuid(), (unsigned)geteuid(),
	      (unsigned)getgid(), (unsigned)getegid());
	STAGE("argc=%d", argc);
	for(i = 0; i < argc && i < 16; i++)
		STAGE("argv[%d]=%s", i, argv[i] ? argv[i] : "(null)");
	STAGE("sinks open: total %d (want 5)", g_nsink);

	/* The launchd phase is PID 1 pre-pivot: /var is not mounted yet, only the
	 * ramdisk sinks can work.  Later phases pull its record. */
	if(strcmp(phase, "launchd") != 0) {
		pull_file(LOG_RAM1);
		pull_file(LOG_RAM1B);
	}

	dump_mounts();
	dump_statfs("/");
	dump_statfs("/private");
	dump_statfs("/private/var");
	dump_statfs("/binpack");
	dump_statfs("/var/binpack");
	dump_system_version();
	dump_dir("/", OUT_LIMIT, NULL);
	dump_dir("/dev", OUT_LIMIT, "disk");
	dump_dir("/binpack", OUT_LIMIT, NULL);
	dump_dir("/binpack/lib", OUT_LIMIT, NULL);
	dump_dir("/binpack/binpack", OUT_LIMIT, NULL);
	dump_dir("/var", OUT_LIMIT, NULL);
	dump_dir("/var/binpack", OUT_LIMIT, NULL);
	dump_dir("/private/var/tmp", OUT_LIMIT, NULL);
	dump_dir("/private/var/tmp/.req", OUT_LIMIT, NULL);
	dump_dir("/private/var/tmp/.opt", OUT_LIMIT, NULL);
	dump_dir("/Applications", OUT_LIMIT, NULL);

	dump_path("/payload");
	dump_path("/payload.real");
	dump_path("/payload.dylib");
	dump_path("/binpack/loader.dmg");
	dump_path("/binpack/tvloader.dmg");
	dump_path("/binpack/lib/dyld");
	dump_path("/private/var/tmp/checkra1n.dmg");
	dump_path("/private/var/checkra1n.dmg");
	dump_path("/.bootstrapped");
	dump_path("/private/var/lib/dpkg/status");
	dump_path("/dev/md0");
	dump_path("/dev/rmd0");
	dump_path("/dev/disk0s1");
	dump_path("/dev/disk0s1s1");
	dump_path("/var/mobile");
	dump_path("/var/mobile/Media");

	dump_file("/private/var/tmp/.req/com.apple.checkra1nd.plist", 8192);
	dump_file("/private/var/tmp/.opt/com.apple.checkra1nd.plist", 8192);
	dump_file("/private/var/tmp/.opt/com.apple.AppImageMounter.plist", 8192);

	dump_environ();

	fwd = calloc((size_t)argc + 1, sizeof(char *));
	if(!fwd) {
		STAGE("calloc failed");
		return 1;
	}
	fwd[0] = (argc > 0 && argv[0]) ? argv[0] : (char *)REAL_LOADER;
	for(i = 1; i < argc; i++)
		fwd[i] = argv[i];

	STAGE("chaining to %s (argv[0]=%s, pid=%d)", REAL_LOADER, fwd[0], getpid());
	execv(REAL_LOADER, fwd);
	STAGE("execv(%s) failed, errno=%d (%s)", REAL_LOADER, errno, strerror(errno));
	return 1;
}
