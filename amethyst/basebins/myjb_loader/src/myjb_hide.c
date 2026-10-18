#include "basebin_hook.h"
#include "basebin_util.h"
#include "myjb_hide.h"

#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <syslog.h>

#define MYJB_HIDE_MAX_HOOKS 64
#define MYJB_HIDE_MAX_IMAGES 2048
#define MYJB_HIDE_MAX_BULK_ENTRIES 160
#define MYJB_HIDE_MAX_KEEP_EXTRA 8
#define MYJB_HIDE_MAX_VISIBLE 1024
#define MYJB_HIDE_MAX_ENV_SCRUB 16
#define MYJB_HIDE_MAX_BLOCK_LOGS 128

#define MYJB_CS_OPS_STATUS 0
#define MYJB_CS_GET_TASK_ALLOW 0x00000004
#define MYJB_CS_INVALID_ALLOWED 0x00000020
#define MYJB_CS_HARD 0x00000100
#define MYJB_CS_KILL 0x00000200
#define MYJB_CS_RESTRICT 0x00000800
#define MYJB_CS_ENFORCEMENT 0x00001000
#define MYJB_CS_REQUIRE_LV 0x00002000
#define MYJB_CS_PLATFORM_BINARY 0x04000000
#define MYJB_CS_DEBUGGED 0x10000000

static bool g_hide_installed = false;

static const char *myjb_hide_paths[] = {
    "/.bootstrapped",
    "/.installed_unc0ver",
    "/amethyst",
    "/bootstrap",
    "/jb",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate",
    "/Library/TweakInject",
    "/Library/PreferenceLoader",
    "/Library/PreferenceBundles",
    "/Library/Themes",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/usr/lib/base_hook.dylib",
    "/usr/lib/dyld_patch",
    "/usr/lib/libjailbreak.dylib",
    "/usr/lib/libsubstrate.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libellekit.dylib",
    "/usr/lib/myjb_loader.dylib",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/Library/Caches/cy-*",
    "/usr/libexec/cydia",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/substrate",
    "/usr/libexec/substituted",
    "/usr/libexec/substitute-inserter",
    "/usr/libexec/sshd-keygen-wrapper",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/bin/bash",
    "/etc/apt",
    "/etc/dpkg",
    "/etc/profile",
    "/etc/ssh",
    "/var/binpack",
    "/var/stash",
    "/var/staged_system_apps/Mobile/Cydia.app",
    "/var/containers/Bundle/tweaksupport",
    "/var/lib/apt",
    "/var/lib/dpkg",
    "/var/lib/cydia",
    "/var/cache/apt",
    "/var/mobile/Library/Caches/com.saurik.Cydia",
    "/var/mobile/Library/Cydia",
    "/var/mobile/Library/MobileSubstrate",
    "/var/mobile/Library/MyJB",
    "/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
    "/var/mobile/Library/Sileo",
    "/var/mobile/Library/TweakInject",
    "/var/jb",
    "/tmp/myjb-*",
    "/var/tmp/myjb-*",
    NULL
};

static const char *myjb_hide_image_names[] = {
    "myjb_loader.dylib",
    "base_hook.dylib",
    "MobileSubstrate.dylib",
    "SubstrateBootstrap.dylib",
    "SubstrateLoader.dylib",
    "SubstrateInserter.dylib",
    "TweakInject.dylib",
    "libsubstrate.dylib",
    "libhooker.dylib",
    "libsubstitute.dylib",
    "substitute-inserter.dylib",
    "libellekit.dylib",
    "libjailbreak.dylib",
    NULL
};

static const char *myjb_hide_keep_names[] = {
    "Cydia",
    "Sileo",
    "Zebra",
    "Installer",
    "Filza",
    "dpkg",
    "apt",
    "apt-get",
    "bash",
    "sh",
    "zsh",
    "dash",
    "sshd",
    "ssh",
    "scp",
    "sftp",
    "NewTerm",
    "NewTerm3",
    "mTerminal",
    "MobileTerminal",
    "Terminal",
    "myjbd",
    "myjbctl",
    NULL
};

static const char *myjb_hide_url_schemes[] = {
    "cydia",
    "sileo",
    "zebra",
    "installer",
    "undecimus",
    "checkra1n",
    "filza",
    NULL
};

static char g_keep_extra[MYJB_HIDE_MAX_KEEP_EXTRA][64];
static uint32_t g_keep_extra_count = 0;

static uint32_t g_block_log_count = 0;

static FILE *(*orig_fopen)(const char *, const char *);

static void myjb_hide_log(const char *fmt, ...) {
    char message[512] = {0};

    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    fprintf(stderr, "%s\n", message);
    syslog(LOG_NOTICE, "%s", message);

    if (getenv("MYJB_DEBUG") != NULL) {
        const char *log_path = "/var/mobile/Library/MyJB/loader.log";
        FILE *file = orig_fopen != NULL ? orig_fopen(log_path, "a") : fopen(log_path, "a");
        if (file != NULL) {
            fprintf(file, "%s\n", message);
            fclose(file);
        }
    }
}

static void myjb_hide_log_blocked(const char *what, const char *path) {
    if (g_block_log_count >= MYJB_HIDE_MAX_BLOCK_LOGS) return;

    g_block_log_count++;
    if (g_block_log_count == MYJB_HIDE_MAX_BLOCK_LOGS) {
        myjb_hide_log("myjb_hide: block log cap reached, muting");
        return;
    }
    myjb_hide_log("myjb_hide: blocked %s %s", what, path != NULL ? path : "(null)");
}

static void myjb_hide_log_dir_entry(const char *what, const char *dir, const char *name) {
    if (g_block_log_count >= MYJB_HIDE_MAX_BLOCK_LOGS) return;

    char full[PATH_MAX * 2] = {0};
    size_t dlen = dir != NULL ? strlen(dir) : 0;
    snprintf(full, sizeof(full), "%s%s%s",
             dir != NULL ? dir : "",
             (dlen > 0 && dir[dlen - 1] != '/') ? "/" : "",
             name != NULL ? name : "");
    myjb_hide_log_blocked(what, full);
}

static int myjb_hide_block(const char *what, const char *path) {
    myjb_hide_log_blocked(what, path);
    errno = ENOENT;
    return -1;
}

static void *myjb_hide_block_ptr(const char *what, const char *path) {
    myjb_hide_log_blocked(what, path);
    errno = ENOENT;
    return NULL;
}

static size_t myjb_hide_basename_offset(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? (size_t)(slash - path) + 1 : 0;
}

static bool myjb_hide_match_entry(const char *path, const char *entry) {
    size_t len = strlen(entry);
    bool wildcard = false;
    if (len > 0 && entry[len - 1] == '*') {
        wildcard = true;
        len--;
    }
    if (strncasecmp(path, entry, len) != 0) return false;
    if (wildcard) return true;
    if (path[len] == '\0') return true;
    if (path[len] == '/') return true;
    return false;
}

static bool myjb_hide_path_hidden(const char *path) {
    if (path == NULL || path[0] != '/') return false;

    const char *norm = path;
    if (strncasecmp(path, "/private/", 9) == 0) norm = path + 8;

    for (uint32_t i = 0; myjb_hide_paths[i] != NULL; i++) {
        if (myjb_hide_match_entry(path, myjb_hide_paths[i])) return true;
        if (norm != path && myjb_hide_match_entry(norm, myjb_hide_paths[i])) return true;
    }
    return false;
}

static bool myjb_hide_is_keep_name(const char *exec_path) {
    if (exec_path == NULL || exec_path[0] == '\0') return false;

    const char *base = exec_path + myjb_hide_basename_offset(exec_path);
    for (uint32_t i = 0; myjb_hide_keep_names[i] != NULL; i++) {
        if (strcasecmp(base, myjb_hide_keep_names[i]) == 0) return true;
    }
    for (uint32_t i = 0; i < g_keep_extra_count; i++) {
        if (strcasecmp(base, g_keep_extra[i]) == 0) return true;
    }
    return false;
}

static void myjb_hide_load_env_keep(void) {
    const char *env = getenv("MYJB_HIDE_KEEP");
    if (env == NULL) return;

    char buf[512] = {0};
    strlcpy(buf, env, sizeof(buf));

    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok != NULL && g_keep_extra_count < MYJB_HIDE_MAX_KEEP_EXTRA) {
        while (*tok == ' ') tok++;
        size_t len = strlen(tok);
        while (len > 0 && tok[len - 1] == ' ') tok[--len] = '\0';
        if (len > 0) {
            strlcpy(g_keep_extra[g_keep_extra_count], tok, 64);
            g_keep_extra_count++;
        }
        tok = strtok_r(NULL, ",", &save);
    }
}

static const char *myjb_hide_env_prefixes[] = {
    "DYLD_",
    "MYJB_",
    "JBUTIL_",
    "DISABLE_TWEAKS",
    "SONAR_LOADER",
    "_SafeMode",
    "_MSSafeMode",
    "_LHSafeMode",
    "MSSafeMode",
    NULL
};

static bool myjb_hide_env_name_filtered(const char *name) {
    if (name == NULL) return false;

    for (uint32_t i = 0; myjb_hide_env_prefixes[i] != NULL; i++) {
        size_t len = strlen(myjb_hide_env_prefixes[i]);
        if (strncmp(name, myjb_hide_env_prefixes[i], len) == 0) return true;
    }
    return false;
}

static void myjb_hide_scrub_environ(void) {
    extern char **environ;

    char names[MYJB_HIDE_MAX_ENV_SCRUB][64] = {0};
    uint32_t count = 0;

    for (char **env = environ; env != NULL && *env != NULL && count < MYJB_HIDE_MAX_ENV_SCRUB; env++) {
        const char *entry = *env;
        const char *eq = strchr(entry, '=');
        if (eq == NULL || eq == entry) continue;

        size_t len = (size_t)(eq - entry);
        if (len >= 64) continue;

        char name[64] = {0};
        memcpy(name, entry, len);
        if (!myjb_hide_env_name_filtered(name)) continue;

        strlcpy(names[count], name, sizeof(names[count]));
        count++;
    }

    for (uint32_t i = 0; i < count; i++) {
        unsetenv(names[i]);
    }

    if (count > 0) {
        myjb_hide_log("myjb_hide: scrubbed %u environment variable(s)", count);
    }
}

static void myjb_hide_scrub_env_buffer(void *buffer, size_t *size) {
    uint8_t *base = (uint8_t *)buffer;
    size_t total = *size;

    if (base == NULL || total < 8) return;

    size_t pos = sizeof(int);
    while (pos < total && base[pos] != 0) pos++;
    if (pos >= total) return;
    pos++;

    size_t write = pos;
    size_t read = pos;
    bool dropped = false;

    while (read + 1 < total) {
        const char *string = (const char *)(base + read);
        size_t remaining = total - read;
        size_t len = strnlen(string, remaining);
        if (len == remaining) break;

        if (len > 0 && myjb_hide_env_name_filtered(string)) {
            dropped = true;
            read += len + 1;
            continue;
        }

        if (write != read) memmove(base + write, base + read, len + 1);
        write += len + 1;
        read += len + 1;
    }

    if (write < total) memset(base + write, 0, total - write);
    if (dropped) {
        *size = write;
        myjb_hide_log("myjb_hide: scrubbed process environment copy");
    }
}

static bool myjb_hide_should_activate(void) {
    const char *env = getenv("MYJB_HIDE");
    if (env != NULL && strcmp(env, "0") == 0) return false;
    if (access("/amethyst/.myjb_nohide", F_OK) == 0) return false;
    if (env != NULL && strcmp(env, "1") == 0) return true;

    char exec_path[PATH_MAX] = {0};
    uint32_t size = sizeof(exec_path);
    _NSGetExecutablePath(exec_path, &size);

    if (myjb_hide_is_keep_name(exec_path)) return false;

    if (strncmp(exec_path, "/var/containers/Bundle/Application/", 35) == 0) return true;
    if (strncmp(exec_path, "/private/var/containers/Bundle/Application/", 43) == 0) return true;
    if (strncmp(exec_path, "/Applications/", 14) == 0) return true;
    return false;
}

typedef struct {
    void *target;
    void *original;
} myjb_hook_entry_t;

static myjb_hook_entry_t g_hook_table[MYJB_HIDE_MAX_HOOKS];
static uint32_t g_hook_table_count = 0;

static void *myjb_hide_install_hook(const char *name, void *replacement) {
    void *target = dlsym(RTLD_DEFAULT, name);
    if (target == NULL) {
        myjb_hide_log("myjb_hide: hook %s: symbol not found", name);
        return NULL;
    }

    for (uint32_t i = 0; i < g_hook_table_count; i++) {
        if (g_hook_table[i].target == target) return g_hook_table[i].original;
    }

    if (g_hook_table_count >= MYJB_HIDE_MAX_HOOKS) {
        myjb_hide_log("myjb_hide: hook %s: table full", name);
        return NULL;
    }

    void *original = NULL;
    int status = hook_function(target, replacement, &original);
    if (status != 0) {
        myjb_hide_log("myjb_hide: hook %s: patch failed (%d)", name, status);
        return NULL;
    }

    g_hook_table[g_hook_table_count].target = target;
    g_hook_table[g_hook_table_count].original = original;
    g_hook_table_count++;
    return original;
}

static bool myjb_hide_join_path(int fd, const char *path, char *out, size_t out_size) {
    if (path == NULL || out == NULL || out_size == 0) return false;
    if (path[0] == '/') {
        strlcpy(out, path, out_size);
        return true;
    }
    if (fd == AT_FDCWD) return false;

    char dir[PATH_MAX] = {0};
    if (fcntl(fd, F_GETPATH, dir) != 0) return false;
    size_t dlen = strlen(dir);
    if (dlen == 0) return false;
    if (dir[dlen - 1] == '/') {
        snprintf(out, out_size, "%s%s", dir, path);
    } else {
        snprintf(out, out_size, "%s/%s", dir, path);
    }
    return true;
}

static bool myjb_hide_at_hidden(int fd, const char *path) {
    char full[PATH_MAX * 2] = {0};
    if (!myjb_hide_join_path(fd, path, full, sizeof(full))) return false;
    return myjb_hide_path_hidden(full);
}

static int (*orig_open)(const char *, int, ...) = NULL;
static int (*orig_openat)(int, const char *, int, ...) = NULL;
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_stat64)(const char *, void *) = NULL;
static int (*orig_lstat)(const char *, struct stat *) = NULL;
static int (*orig_lstat64)(const char *, void *) = NULL;
static int (*orig_fstatat)(int, const char *, struct stat *, int) = NULL;
static int (*orig_access)(const char *, int) = NULL;
static int (*orig_faccessat)(int, const char *, int, int) = NULL;
static ssize_t (*orig_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*orig_readlinkat)(int, const char *, char *, size_t) = NULL;
static char *(*orig_realpath)(const char *, char *) = NULL;
static DIR *(*orig_opendir)(const char *) = NULL;
static struct dirent *(*orig_readdir)(DIR *) = NULL;
static int (*orig_readdir_r)(DIR *, struct dirent *, struct dirent **) = NULL;
static FILE *(*orig_fopen)(const char *, const char *) = NULL;
static int (*orig_getattrlist)(const char *, struct attrlist *, void *, size_t, unsigned long) = NULL;
static int (*orig_getattrlistbulk)(int, struct attrlist *, void *, size_t, uint64_t) = NULL;
static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int (*orig_statfs64)(const char *, void *) = NULL;
static int (*orig_getdirentries)(int, char *, int, long *) = NULL;
static int (*orig_getdirentries64)(int, char *, int, long *) = NULL;
static int (*orig_stat_inode64)(const char *, struct stat *) = NULL;
static int (*orig_lstat_inode64)(const char *, struct stat *) = NULL;
static int (*orig_fstatat_inode64)(int, const char *, struct stat *, int) = NULL;

static int myjb_hide_open_hook(const char *path, int oflag, ...) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("open", path);
    if ((oflag & O_CREAT) != 0) {
        va_list args;
        va_start(args, oflag);
        int mode = va_arg(args, int);
        va_end(args);
        return orig_open(path, oflag, (mode_t)mode);
    }
    return orig_open(path, oflag);
}

static int myjb_hide_openat_hook(int fd, const char *path, int oflag, ...) {
    if (myjb_hide_at_hidden(fd, path)) return myjb_hide_block("openat", path);
    if ((oflag & O_CREAT) != 0) {
        va_list args;
        va_start(args, oflag);
        int mode = va_arg(args, int);
        va_end(args);
        return orig_openat(fd, path, oflag, (mode_t)mode);
    }
    return orig_openat(fd, path, oflag);
}

static int myjb_hide_stat_hook(const char *path, struct stat *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("stat", path);
    return orig_stat(path, st);
}

static int myjb_hide_stat64_hook(const char *path, void *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("stat64", path);
    return orig_stat64(path, st);
}

static int myjb_hide_lstat_hook(const char *path, struct stat *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("lstat", path);
    return orig_lstat(path, st);
}

static int myjb_hide_lstat64_hook(const char *path, void *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("lstat64", path);
    return orig_lstat64(path, st);
}

static int myjb_hide_fstatat_hook(int fd, const char *path, struct stat *st, int flag) {
    if (myjb_hide_at_hidden(fd, path)) return myjb_hide_block("fstatat", path);
    return orig_fstatat(fd, path, st, flag);
}

static int myjb_hide_access_hook(const char *path, int mode) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("access", path);
    return orig_access(path, mode);
}

static int myjb_hide_faccessat_hook(int fd, const char *path, int mode, int flag) {
    if (myjb_hide_at_hidden(fd, path)) return myjb_hide_block("faccessat", path);
    return orig_faccessat(fd, path, mode, flag);
}

static ssize_t myjb_hide_readlink_hook(const char *path, char *buf, size_t size) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("readlink", path);
    return orig_readlink(path, buf, size);
}

static ssize_t myjb_hide_readlinkat_hook(int fd, const char *path, char *buf, size_t size) {
    if (myjb_hide_at_hidden(fd, path)) return myjb_hide_block("readlinkat", path);
    return orig_readlinkat(fd, path, buf, size);
}

static char *myjb_hide_realpath_hook(const char *path, char *resolved) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block_ptr("realpath", path);
    return orig_realpath(path, resolved);
}

static DIR *myjb_hide_opendir_hook(const char *path) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block_ptr("opendir", path);
    return orig_opendir(path);
}

static bool myjb_hide_entry_hidden(const char *dir, const char *name) {
    if (name == NULL) return false;
    if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) return false;
    if (dir == NULL || dir[0] != '/') return false;

    char full[PATH_MAX * 2] = {0};
    size_t dlen = strlen(dir);
    if (dir[dlen - 1] == '/') {
        snprintf(full, sizeof(full), "%s%s", dir, name);
    } else {
        snprintf(full, sizeof(full), "%s/%s", dir, name);
    }
    return myjb_hide_path_hidden(full);
}

static struct dirent *myjb_hide_readdir_hook(DIR *dirp) {
    char dir[PATH_MAX] = {0};
    bool have_dir = dirp != NULL && fcntl(dirfd(dirp), F_GETPATH, dir) == 0 && dir[0] == '/';

    for (;;) {
        struct dirent *entry = orig_readdir(dirp);
        if (entry == NULL || !have_dir) return entry;
        if (!myjb_hide_entry_hidden(dir, entry->d_name)) return entry;
        myjb_hide_log_dir_entry("readdir", dir, entry->d_name);
    }
}

static int myjb_hide_readdir_r_hook(DIR *dirp, struct dirent *entry, struct dirent **result) {
    char dir[PATH_MAX] = {0};
    bool have_dir = dirp != NULL && fcntl(dirfd(dirp), F_GETPATH, dir) == 0 && dir[0] == '/';

    for (;;) {
        int status = orig_readdir_r(dirp, entry, result);
        if (status != 0 || result == NULL || *result == NULL || !have_dir) return status;
        if (!myjb_hide_entry_hidden(dir, entry->d_name)) return status;
        myjb_hide_log_dir_entry("readdir_r", dir, entry->d_name);
    }
}

static FILE *myjb_hide_fopen_hook(const char *path, const char *mode) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block_ptr("fopen", path);
    return orig_fopen(path, mode);
}

static int myjb_hide_getattrlist_hook(const char *path, struct attrlist *alist, void *buffer, size_t size, unsigned long options) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("getattrlist", path);
    return orig_getattrlist(path, alist, buffer, size, options);
}

static int myjb_hide_attr_size_common(uint32_t attr) {
    switch (attr) {
        case ATTR_CMN_NAME: return (int)sizeof(attrreference_t);
        case ATTR_CMN_DEVID: return (int)sizeof(dev_t);
        case ATTR_CMN_FSID: return (int)sizeof(fsid_t);
        case ATTR_CMN_OBJTYPE: return (int)sizeof(fsobj_type_t);
        case ATTR_CMN_OBJTAG: return (int)sizeof(fsobj_tag_t);
        case ATTR_CMN_OBJID:
        case ATTR_CMN_OBJPERMANENTID:
        case ATTR_CMN_PAROBJID: return (int)sizeof(fsobj_id_t);
        case ATTR_CMN_SCRIPT: return (int)sizeof(text_encoding_t);
        case ATTR_CMN_CRTIME:
        case ATTR_CMN_MODTIME:
        case ATTR_CMN_CHGTIME:
        case ATTR_CMN_ACCTIME:
        case ATTR_CMN_BKUPTIME:
        case ATTR_CMN_ADDEDTIME: return (int)sizeof(struct timespec);
        case ATTR_CMN_FNDRINFO: return 32;
        case ATTR_CMN_OWNERID: return (int)sizeof(uid_t);
        case ATTR_CMN_GRPID: return (int)sizeof(gid_t);
        case ATTR_CMN_ACCESSMASK:
        case ATTR_CMN_FLAGS:
        case ATTR_CMN_GEN_COUNT:
        case ATTR_CMN_DOCUMENT_ID:
        case ATTR_CMN_USERACCESS:
        case ATTR_CMN_ERROR:
        case ATTR_CMN_DATA_PROTECT_FLAGS: return 4;
        case ATTR_CMN_EXTENDED_SECURITY:
        case ATTR_CMN_FULLPATH: return (int)sizeof(attrreference_t);
        case ATTR_CMN_UUID:
        case ATTR_CMN_GRPUUID: return 16;
        case ATTR_CMN_FILEID:
        case ATTR_CMN_PARENTID: return 8;
        case ATTR_CMN_RETURNED_ATTRS: return (int)sizeof(attribute_set_t);
        default: return -1;
    }
}

static int myjb_hide_attr_size_dir(uint32_t attr) {
    switch (attr) {
        case ATTR_DIR_ENTRYCOUNT: return 4;
        case ATTR_DIR_MOUNTSTATUS: return 4;
        case ATTR_DIR_ALLOCSIZE: return 8;
        case ATTR_DIR_IOBLOCKSIZE: return 4;
        case ATTR_DIR_DATALENGTH: return 8;
        default: return -1;
    }
}

static int myjb_hide_attr_size_file(uint32_t attr) {
    switch (attr) {
        case ATTR_FILE_LINKCOUNT: return 4;
        case ATTR_FILE_TOTALSIZE: return 8;
        case ATTR_FILE_ALLOCSIZE: return 8;
        case ATTR_FILE_IOBLOCKSIZE: return 4;
        case ATTR_FILE_CLUMPSIZE: return 4;
        case ATTR_FILE_DEVTYPE: return 4;
        case ATTR_FILE_FILETYPE: return 4;
        case ATTR_FILE_FORKCOUNT: return 4;
        case ATTR_FILE_FORKLIST: return (int)sizeof(attrreference_t);
        case ATTR_FILE_DATALENGTH: return 8;
        case ATTR_FILE_DATAALLOCSIZE: return 8;
        case ATTR_FILE_RSRCLENGTH: return 8;
        case ATTR_FILE_RSRCALLOCSIZE: return 8;
        default: return -1;
    }
}

static int myjb_hide_attr_size_fork(uint32_t attr) {
    switch (attr) {
        case ATTR_FORK_TOTALSIZE: return 8;
        case ATTR_FORK_ALLOCSIZE: return 8;
        default: return -1;
    }
}

static int myjb_hide_attr_size(uint32_t group, uint32_t attr) {
    switch (group) {
        case 0: return myjb_hide_attr_size_common(attr);
        case 1: return myjb_hide_attr_size_dir(attr);
        case 2: return myjb_hide_attr_size_file(attr);
        case 3: return myjb_hide_attr_size_fork(attr);
        default: return -1;
    }
}

static bool myjb_hide_walk_group(uint8_t **cursor, uint8_t *end, uint32_t mask, uint32_t group, char **name_out) {
    for (uint32_t bit = 0; bit < 32; bit++) {
        uint32_t attr = 1u << bit;
        if ((mask & attr) == 0) continue;

        int size = myjb_hide_attr_size(group, attr);
        if (size < 0) return false;
        if (*cursor + size > end) return false;

        if (group == 0 && attr == ATTR_CMN_NAME && name_out != NULL) {
            attrreference_t *ref = (attrreference_t *)*cursor;
            char *name = (char *)*cursor + ref->attr_dataoffset;
            if (ref->attr_dataoffset <= 0 || name + ref->attr_length > (char *)end) return false;
            *name_out = name;
        }
        *cursor += size;
    }
    return true;
}

typedef struct {
    uint32_t offset;
    uint32_t length;
    bool hidden;
} myjb_bulk_entry_t;

static int myjb_hide_filter_bulk(struct attrlist *alist, void *buffer, int size, const char *dir) {
    uint8_t *base = (uint8_t *)buffer;
    myjb_bulk_entry_t entries[MYJB_HIDE_MAX_BULK_ENTRIES];
    uint32_t count = 0;

    uint32_t requested_common = alist->commonattr;
    uint32_t requested_dir = alist->dirattr;
    uint32_t requested_file = alist->fileattr;
    uint32_t requested_fork = alist->forkattr;

    if (alist->volattr != 0) return size;

    int pos = 0;
    while (pos + 4 <= size) {
        uint8_t *entry = base + pos;
        uint32_t length = *(uint32_t *)entry;
        if (length < 4 || pos + (int)length > size) return size;
        if (count >= MYJB_HIDE_MAX_BULK_ENTRIES) return size;

        uint8_t *cursor = entry + 4;
        uint8_t *end = entry + length;

        uint32_t common = requested_common;
        uint32_t dirattr = requested_dir;
        uint32_t file = requested_file;
        uint32_t fork = requested_fork;

        if ((requested_common & ATTR_CMN_RETURNED_ATTRS) != 0) {
            if (cursor + sizeof(attribute_set_t) > end) return size;
            attribute_set_t returned = *(attribute_set_t *)cursor;
            cursor += sizeof(attribute_set_t);
            bool present = (returned.commonattr | returned.volattr | returned.dirattr | returned.fileattr | returned.forkattr) != 0;
            common = (present ? returned.commonattr : requested_common) & ~ATTR_CMN_RETURNED_ATTRS;
            dirattr = present ? returned.dirattr : requested_dir;
            file = present ? returned.fileattr : requested_file;
            fork = present ? returned.forkattr : requested_fork;
            if (present && returned.volattr != 0) return size;
        }

        char *name = NULL;
        if (!myjb_hide_walk_group(&cursor, end, common, 0, &name)) return size;
        if (!myjb_hide_walk_group(&cursor, end, dirattr, 1, NULL)) return size;
        if (!myjb_hide_walk_group(&cursor, end, file, 2, NULL)) return size;
        if (!myjb_hide_walk_group(&cursor, end, fork, 3, NULL)) return size;
        if (cursor > end) return size;
        if (name == NULL) return size;

        entries[count].offset = (uint32_t)pos;
        entries[count].length = length;
        entries[count].hidden = myjb_hide_entry_hidden(dir, name);
        if (entries[count].hidden) myjb_hide_log_dir_entry("getattrlistbulk", dir, name);
        count++;
        pos += (int)length;
    }

    int new_size = size;
    uint32_t shift = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t *entry = base + entries[i].offset;
        if (shift > 0) {
            memmove(entry - shift, entry, entries[i].length);
        }
        if (entries[i].hidden) {
            shift += entries[i].length;
        }
    }
    new_size -= (int)shift;
    return new_size;
}

static int myjb_hide_getattrlistbulk_hook(int fd, struct attrlist *alist, void *buffer, size_t size, uint64_t options) {
    int result = orig_getattrlistbulk(fd, alist, buffer, size, options);
    if (result <= 0 || alist == NULL || buffer == NULL) return result;
    if ((alist->commonattr & ATTR_CMN_NAME) == 0) return result;

    char dir[PATH_MAX] = {0};
    if (fcntl(fd, F_GETPATH, dir) != 0 || dir[0] != '/') return result;

    return myjb_hide_filter_bulk(alist, buffer, result, dir);
}

static void myjb_hide_fake_rootfs_flags(struct statfs *fs) {
    if (fs != NULL && fs->f_mntonname[0] == '/' && fs->f_mntonname[1] == '\0') {
        fs->f_flags |= MNT_RDONLY;
    }
}

static int myjb_hide_statfs_hook(const char *path, struct statfs *fs) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("statfs", path);

    int status = orig_statfs(path, fs);
    if (status == 0) myjb_hide_fake_rootfs_flags(fs);
    return status;
}

static int myjb_hide_statfs64_hook(const char *path, void *fs) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("statfs64", path);

    int status = orig_statfs64(path, fs);
    if (status == 0) myjb_hide_fake_rootfs_flags((struct statfs *)fs);
    return status;
}

static int myjb_hide_filter_direntries(int fd, char *buf, int result) {
    if (result <= 0) return result;

    char dir[PATH_MAX] = {0};
    if (fcntl(fd, F_GETPATH, dir) != 0 || dir[0] != '/') return result;

    int pos = 0;
    int shift = 0;
    while (pos + 18 <= result) {
        struct dirent *entry = (struct dirent *)(buf + pos);
        if (entry->d_reclen == 0 || pos + entry->d_reclen > result) break;
        if (shift > 0) {
            memmove(buf + pos - shift, buf + pos, entry->d_reclen);
        }
        if (myjb_hide_entry_hidden(dir, entry->d_name)) {
            myjb_hide_log_dir_entry("getdirentries", dir, entry->d_name);
            shift += entry->d_reclen;
        }
        pos += entry->d_reclen;
    }
    return result - shift;
}

static int myjb_hide_getdirentries_hook(int fd, char *buf, int nbytes, long *basep) {
    return myjb_hide_filter_direntries(fd, buf, orig_getdirentries(fd, buf, nbytes, basep));
}

static int myjb_hide_getdirentries64_hook(int fd, char *buf, int nbytes, long *basep) {
    return myjb_hide_filter_direntries(fd, buf, orig_getdirentries64(fd, buf, nbytes, basep));
}

static int myjb_hide_stat_inode64_hook(const char *path, struct stat *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("stat$INODE64", path);
    return orig_stat_inode64(path, st);
}

static int myjb_hide_lstat_inode64_hook(const char *path, struct stat *st) {
    if (myjb_hide_path_hidden(path)) return myjb_hide_block("lstat$INODE64", path);
    return orig_lstat_inode64(path, st);
}

static int myjb_hide_fstatat_inode64_hook(int fd, const char *path, struct stat *st, int flag) {
    if (myjb_hide_at_hidden(fd, path)) return myjb_hide_block("fstatat$INODE64", path);
    return orig_fstatat_inode64(fd, path, st, flag);
}

static uint32_t (*orig_image_count)(void) = NULL;
static const char *(*orig_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_image_header)(uint32_t) = NULL;
static intptr_t (*orig_image_slide)(uint32_t) = NULL;

uint32_t myjb_real_image_count(void) {
    if (orig_image_count != NULL) return orig_image_count();
    return _dyld_image_count();
}

const char *myjb_real_image_name(uint32_t index) {
    if (orig_image_name != NULL) return orig_image_name(index);
    return _dyld_get_image_name(index);
}

const struct mach_header *myjb_real_image_header(uint32_t index) {
    if (orig_image_header != NULL) return orig_image_header(index);
    return _dyld_get_image_header(index);
}

static bool myjb_hide_image_path_hidden(const char *name) {
    if (name == NULL) return false;
    if (myjb_hide_path_hidden(name)) return true;

    const char *base = name + myjb_hide_basename_offset(name);
    for (uint32_t i = 0; myjb_hide_image_names[i] != NULL; i++) {
        if (strcasecmp(base, myjb_hide_image_names[i]) == 0) return true;
    }
    if (strncasecmp(base, "myjb-", 5) == 0) return true;
    return false;
}

static inline int myjb_hide_visible_lookup(uint32_t index, uint32_t *real_out) {
    uint32_t real_count = myjb_real_image_count();
    uint32_t visible = 0;
    for (uint32_t i = 0; i < real_count; i++) {
        const char *name = myjb_real_image_name(i);
        if (myjb_hide_image_path_hidden(name)) continue;
        if (visible == index) {
            if (real_out != NULL) *real_out = i;
            return 0;
        }
        visible++;
    }
    return -1;
}

static uint32_t myjb_hide_image_count_hook(void) {
    uint32_t real_count = myjb_real_image_count();
    uint32_t visible = 0;
    for (uint32_t i = 0; i < real_count; i++) {
        const char *name = myjb_real_image_name(i);
        if (myjb_hide_image_path_hidden(name)) continue;
        visible++;
    }
    return visible;
}

static const char *myjb_hide_image_name_hook(uint32_t index) {
    uint32_t real = 0;
    if (myjb_hide_visible_lookup(index, &real) != 0) return NULL;
    return myjb_real_image_name(real);
}

static const struct mach_header *myjb_hide_image_header_hook(uint32_t index) {
    uint32_t real = 0;
    if (myjb_hide_visible_lookup(index, &real) != 0) return NULL;
    return myjb_real_image_header(real);
}

static intptr_t myjb_hide_image_slide_hook(uint32_t index) {
    uint32_t real = 0;
    if (myjb_hide_visible_lookup(index, &real) != 0) return 0;
    if (orig_image_slide != NULL) return orig_image_slide(real);
    return _dyld_get_image_vmaddr_slide(real);
}

static const struct dyld_all_image_infos *(*orig_get_all_image_infos)(void) = NULL;

static struct dyld_image_info g_fake_image_array[MYJB_HIDE_MAX_IMAGES];
static struct dyld_all_image_infos g_fake_image_infos;
static bool g_fake_image_infos_ready = false;

static void myjb_hide_build_fake_infos(const struct dyld_all_image_infos *real) {
    uint32_t visible = 0;
    if (real != NULL && real->infoArray != NULL && real->infoArrayCount <= MYJB_HIDE_MAX_IMAGES) {
        for (uint32_t i = 0; i < real->infoArrayCount && visible < MYJB_HIDE_MAX_IMAGES; i++) {
            const struct dyld_image_info *entry = &real->infoArray[i];
            if (entry->imageLoadAddress == NULL || entry->imageFilePath == NULL) continue;
            if (myjb_hide_image_path_hidden(entry->imageFilePath)) continue;
            g_fake_image_array[visible++] = *entry;
        }
    }

    if (!g_fake_image_infos_ready && real != NULL) {
        memcpy(&g_fake_image_infos, real, sizeof(g_fake_image_infos));
        g_fake_image_infos_ready = true;
    }
    g_fake_image_infos.infoArrayCount = visible;
    g_fake_image_infos.infoArray = g_fake_image_array;
}

static const struct dyld_all_image_infos *myjb_hide_get_all_image_infos_hook(void) {
    const struct dyld_all_image_infos *real = orig_get_all_image_infos();
    if (real == NULL || real->infoArray == NULL || real->infoArrayCount > MYJB_HIDE_MAX_IMAGES) return real;

    myjb_hide_build_fake_infos(real);
    return &g_fake_image_infos;
}

static void myjb_hide_apply_raw_image_infos(void) {
    static bool logged = false;
    static uint32_t refilter_logs = 0;
    static uint32_t last_real_count = 0;

    task_dyld_info_data_t info = {0};
    uint32_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&info, &count) != KERN_SUCCESS ||
        info.all_image_info_addr == 0) {
        if (!logged) {
            myjb_hide_log("myjb_hide: raw image infos: task_info failed");
            logged = true;
        }
        return;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)info.all_image_info_addr;
    if (infos->infoArray == NULL || infos->infoArrayCount == 0 ||
        infos->infoArrayCount > MYJB_HIDE_MAX_IMAGES) return;

    uint32_t real_count = infos->infoArrayCount;
    myjb_hide_build_fake_infos(infos);

    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    infos->infoArrayCount = g_fake_image_infos.infoArrayCount;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    infos->infoArray = g_fake_image_array;

    if (!logged) {
        myjb_hide_log("myjb_hide: raw image infos filtered %u/%u",
                      g_fake_image_infos.infoArrayCount, real_count);
        logged = true;
        last_real_count = real_count;
        return;
    }
    if (real_count != last_real_count && refilter_logs < 3) {
        myjb_hide_log("myjb_hide: raw image infos refiltered %u/%u",
                      g_fake_image_infos.infoArrayCount, real_count);
        refilter_logs++;
    }
    last_real_count = real_count;
}

static bool myjb_hide_caller_trusted(void *return_address) {
    Dl_info info = {0};
    if (return_address == NULL) return false;
    if (dladdr(return_address, &info) == 0 || info.dli_fname == NULL) return false;
    if (myjb_hide_image_path_hidden(info.dli_fname)) return true;
    return myjb_hide_path_hidden(info.dli_fname);
}

static void *(*orig_dlopen)(const char *, int) = NULL;
static int (*orig_dlopen_preflight)(const char *) = NULL;
static void *(*orig_dlsym)(void *, const char *) = NULL;

static void *myjb_hide_dlopen_hook(const char *path, int mode) {
    if (path != NULL && (myjb_hide_path_hidden(path) || myjb_hide_image_path_hidden(path))) {
        if (!myjb_hide_caller_trusted(__builtin_return_address(0))) {
            myjb_hide_log_blocked("dlopen", path);
            errno = ENOENT;
            return NULL;
        }
    }
    return orig_dlopen != NULL ? orig_dlopen(path, mode) : NULL;
}

static int myjb_hide_dlopen_preflight_hook(const char *path) {
    if (path != NULL && (myjb_hide_path_hidden(path) || myjb_hide_image_path_hidden(path))) {
        if (!myjb_hide_caller_trusted(__builtin_return_address(0))) {
            myjb_hide_log_blocked("dlopen_preflight", path);
            errno = ENOENT;
            return 0;
        }
    }
    return orig_dlopen_preflight != NULL ? orig_dlopen_preflight(path) : 0;
}

static void *myjb_hide_dlsym_hook(void *handle, const char *symbol) {
    void *result = orig_dlsym != NULL ? orig_dlsym(handle, symbol) : NULL;
    if (result == NULL || symbol == NULL) return result;

    Dl_info info = {0};
    if (dladdr(result, &info) == 0 || info.dli_fname == NULL) return result;
    if (!myjb_hide_image_path_hidden(info.dli_fname)) return result;
    if (myjb_hide_caller_trusted(__builtin_return_address(0))) return result;

    myjb_hide_log_blocked("dlsym", symbol);
    return NULL;
}

static uint32_t myjb_hide_stock_csflags(uint32_t flags) {
    flags &= ~(MYJB_CS_DEBUGGED | MYJB_CS_PLATFORM_BINARY | MYJB_CS_INVALID_ALLOWED | MYJB_CS_GET_TASK_ALLOW);
    flags |= MYJB_CS_HARD | MYJB_CS_KILL | MYJB_CS_RESTRICT | MYJB_CS_ENFORCEMENT | MYJB_CS_REQUIRE_LV;
    return flags;
}

static int (*orig_csops)(pid_t, unsigned int, void *, size_t) = NULL;
static int (*orig_csops_audittoken)(pid_t, unsigned int, void *, size_t, audit_token_t *) = NULL;

static int myjb_hide_csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int status = orig_csops(pid, ops, useraddr, usersize);
    if (status != 0 || ops != MYJB_CS_OPS_STATUS || useraddr == NULL || usersize != 4) return status;
    if (pid != 0 && pid != getpid()) return status;

    *(uint32_t *)useraddr = myjb_hide_stock_csflags(*(uint32_t *)useraddr);
    return status;
}

static int myjb_hide_csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token) {
    int status = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    if (status != 0 || ops != MYJB_CS_OPS_STATUS || useraddr == NULL || usersize != 4) return status;
    if (token == NULL || token->val[5] != (unsigned int)getpid()) return status;

    *(uint32_t *)useraddr = myjb_hide_stock_csflags(*(uint32_t *)useraddr);
    return status;
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t) = NULL;
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t) = NULL;

static int myjb_hide_sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int status = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    if (status != 0 || name == NULL || oldp == NULL || oldlenp == NULL) return status;
    if (namelen < 2 || name[0] != CTL_KERN || name[1] != KERN_PROCARGS2) return status;
    if (namelen >= 3 && name[2] != 0 && name[2] != getpid()) return status;

    myjb_hide_scrub_env_buffer(oldp, oldlenp);
    return status;
}

static int myjb_hide_sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int status = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (status != 0 || name == NULL || oldp == NULL || oldlenp == NULL) return status;
    if (strcmp(name, "kern.procargs2") != 0) return status;

    myjb_hide_scrub_env_buffer(oldp, oldlenp);
    return status;
}

static void myjb_hide_install_guard_hooks(void) {
    orig_csops = myjb_hide_install_hook("csops", (void *)myjb_hide_csops_hook);
    orig_csops_audittoken = myjb_hide_install_hook("csops_audittoken", (void *)myjb_hide_csops_audittoken_hook);
    orig_sysctl = myjb_hide_install_hook("sysctl", (void *)myjb_hide_sysctl_hook);
    orig_sysctlbyname = myjb_hide_install_hook("sysctlbyname", (void *)myjb_hide_sysctlbyname_hook);
    orig_dlopen = myjb_hide_install_hook("dlopen", (void *)myjb_hide_dlopen_hook);
    orig_dlopen_preflight = myjb_hide_install_hook("dlopen_preflight", (void *)myjb_hide_dlopen_preflight_hook);
    orig_dlsym = myjb_hide_install_hook("dlsym", (void *)myjb_hide_dlsym_hook);
}

static IMP g_orig_canOpenURL = NULL;
static IMP g_orig_openURL = NULL;
static IMP g_orig_openURL_options = NULL;

static void *g_objc_msgSend = NULL;
static void *g_objc_getClass = NULL;
static void *g_sel_registerName = NULL;
static void *g_class_getInstanceMethod = NULL;
static void *g_method_setImplementation = NULL;

static void myjb_hide_load_objc(void) {
    if (g_objc_msgSend != NULL) return;
    g_objc_msgSend = dlsym(RTLD_DEFAULT, "objc_msgSend");
    g_objc_getClass = dlsym(RTLD_DEFAULT, "objc_getClass");
    g_sel_registerName = dlsym(RTLD_DEFAULT, "sel_registerName");
    g_class_getInstanceMethod = dlsym(RTLD_DEFAULT, "class_getInstanceMethod");
    g_method_setImplementation = dlsym(RTLD_DEFAULT, "method_setImplementation");
}

static bool myjb_hide_url_scheme_hidden(id url) {
    if (url == NULL || g_objc_msgSend == NULL || g_sel_registerName == NULL) return false;

    SEL scheme_sel = ((SEL (*)(const char *))g_sel_registerName)("scheme");
    if (!((BOOL (*)(id, SEL, SEL))g_objc_msgSend)(url, ((SEL (*)(const char *))g_sel_registerName)("respondsToSelector:"), scheme_sel)) return false;

    id scheme = ((id (*)(id, SEL))g_objc_msgSend)(url, scheme_sel);
    if (scheme == NULL) return false;

    const char *value = ((const char *(*)(id, SEL))g_objc_msgSend)(scheme, ((SEL (*)(const char *))g_sel_registerName)("UTF8String"));
    if (value == NULL) return false;

    for (uint32_t i = 0; myjb_hide_url_schemes[i] != NULL; i++) {
        if (strcasecmp(value, myjb_hide_url_schemes[i]) == 0) return true;
    }
    return false;
}

static BOOL myjb_hide_canOpenURL_hook(id self, SEL cmd, id url) {
    if (myjb_hide_url_scheme_hidden(url)) return NO;
    return ((BOOL (*)(id, SEL, id))g_orig_canOpenURL)(self, cmd, url);
}

static BOOL myjb_hide_openURL_hook(id self, SEL cmd, id url) {
    if (myjb_hide_url_scheme_hidden(url)) return NO;
    return ((BOOL (*)(id, SEL, id))g_orig_openURL)(self, cmd, url);
}

static void myjb_hide_openURL_options_hook(id self, SEL cmd, id url, id options, id completion) {
    if (myjb_hide_url_scheme_hidden(url)) {
        if (completion != NULL) {
            ((void (^)(BOOL))completion)(NO);
        }
        return;
    }
    ((void (*)(id, SEL, id, id, id))g_orig_openURL_options)(self, cmd, url, options, completion);
}

static void myjb_hide_swizzle(Class cls, const char *selector, IMP replacement, IMP *original) {
    if (*original != NULL) return;
    if (g_class_getInstanceMethod == NULL || g_method_setImplementation == NULL || g_sel_registerName == NULL) return;
    Method method = ((Method (*)(Class, SEL))g_class_getInstanceMethod)(cls, ((SEL (*)(const char *))g_sel_registerName)(selector));
    if (method == NULL) return;
    *original = ((IMP (*)(Method, IMP))g_method_setImplementation)(method, replacement);
}

static void myjb_hide_uikit_added(const struct mach_header *header, intptr_t slide) {
    (void)header;
    (void)slide;

    myjb_hide_apply_raw_image_infos();

    myjb_hide_load_objc();
    if (g_objc_getClass == NULL) return;

    Class cls = ((Class (*)(const char *))g_objc_getClass)("UIApplication");
    if (cls == NULL) return;

    myjb_hide_swizzle(cls, "canOpenURL:", (IMP)myjb_hide_canOpenURL_hook, &g_orig_canOpenURL);
    myjb_hide_swizzle(cls, "openURL:", (IMP)myjb_hide_openURL_hook, &g_orig_openURL);
    myjb_hide_swizzle(cls, "openURL:options:completionHandler:", (IMP)myjb_hide_openURL_options_hook, &g_orig_openURL_options);
}

static void myjb_hide_install_file_hooks(void) {
    orig_open = myjb_hide_install_hook("open", (void *)myjb_hide_open_hook);
    orig_openat = myjb_hide_install_hook("openat", (void *)myjb_hide_openat_hook);
    orig_stat = myjb_hide_install_hook("stat", (void *)myjb_hide_stat_hook);
    orig_stat64 = myjb_hide_install_hook("stat64", (void *)myjb_hide_stat64_hook);
    orig_lstat = myjb_hide_install_hook("lstat", (void *)myjb_hide_lstat_hook);
    orig_lstat64 = myjb_hide_install_hook("lstat64", (void *)myjb_hide_lstat64_hook);
    orig_fstatat = myjb_hide_install_hook("fstatat", (void *)myjb_hide_fstatat_hook);
    orig_access = myjb_hide_install_hook("access", (void *)myjb_hide_access_hook);
    orig_faccessat = myjb_hide_install_hook("faccessat", (void *)myjb_hide_faccessat_hook);
    orig_readlink = myjb_hide_install_hook("readlink", (void *)myjb_hide_readlink_hook);
    orig_readlinkat = myjb_hide_install_hook("readlinkat", (void *)myjb_hide_readlinkat_hook);
    orig_realpath = myjb_hide_install_hook("realpath", (void *)myjb_hide_realpath_hook);
    orig_opendir = myjb_hide_install_hook("opendir", (void *)myjb_hide_opendir_hook);
    orig_readdir = myjb_hide_install_hook("readdir", (void *)myjb_hide_readdir_hook);
    orig_readdir_r = myjb_hide_install_hook("readdir_r", (void *)myjb_hide_readdir_r_hook);
    orig_fopen = myjb_hide_install_hook("fopen", (void *)myjb_hide_fopen_hook);
    orig_getattrlist = myjb_hide_install_hook("getattrlist", (void *)myjb_hide_getattrlist_hook);
    orig_getattrlistbulk = myjb_hide_install_hook("getattrlistbulk", (void *)myjb_hide_getattrlistbulk_hook);
    orig_statfs = myjb_hide_install_hook("statfs", (void *)myjb_hide_statfs_hook);
    orig_statfs64 = myjb_hide_install_hook("statfs64", (void *)myjb_hide_statfs64_hook);
    orig_getdirentries = myjb_hide_install_hook("getdirentries", (void *)myjb_hide_getdirentries_hook);
    orig_getdirentries64 = myjb_hide_install_hook("__getdirentries64", (void *)myjb_hide_getdirentries64_hook);
    if (orig_getdirentries64 == NULL) {
        orig_getdirentries64 = myjb_hide_install_hook("getdirentries64", (void *)myjb_hide_getdirentries64_hook);
    }
    orig_stat_inode64 = myjb_hide_install_hook("stat$INODE64", (void *)myjb_hide_stat_inode64_hook);
    orig_lstat_inode64 = myjb_hide_install_hook("lstat$INODE64", (void *)myjb_hide_lstat_inode64_hook);
    orig_fstatat_inode64 = myjb_hide_install_hook("fstatat$INODE64", (void *)myjb_hide_fstatat_inode64_hook);
}

static void myjb_hide_install_image_hooks(void) {
    orig_image_count = myjb_hide_install_hook("_dyld_image_count", (void *)myjb_hide_image_count_hook);
    orig_image_name = myjb_hide_install_hook("_dyld_get_image_name", (void *)myjb_hide_image_name_hook);
    orig_image_header = myjb_hide_install_hook("_dyld_get_image_header", (void *)myjb_hide_image_header_hook);
    orig_image_slide = myjb_hide_install_hook("_dyld_get_image_vmaddr_slide", (void *)myjb_hide_image_slide_hook);
    orig_get_all_image_infos = myjb_hide_install_hook("_dyld_get_all_image_infos", (void *)myjb_hide_get_all_image_infos_hook);
}

void myjb_hide_start(void) {
    if (g_hide_installed) return;
    g_hide_installed = true;

    openlog("myjb_hide", LOG_NDELAY, LOG_USER);

    char exec_path[PATH_MAX] = {0};
    uint32_t size = sizeof(exec_path);
    _NSGetExecutablePath(exec_path, &size);

    if (!myjb_hide_should_activate()) {
        if (strncmp(exec_path, "/var/containers/", 16) == 0 ||
            strncmp(exec_path, "/private/var/containers/", 24) == 0 ||
            strncmp(exec_path, "/Applications/", 14) == 0) {
            myjb_hide_log("myjb_hide: skip %s", exec_path);
        }
        return;
    }

    myjb_hide_load_env_keep();
    myjb_hide_log("myjb_hide: active in %s", exec_path);

    myjb_hide_scrub_environ();

    myjb_hide_install_file_hooks();
    myjb_hide_install_image_hooks();
    myjb_hide_apply_raw_image_infos();
    myjb_hide_install_guard_hooks();

    myjb_hide_log("myjb_hide: %u hook(s) installed", g_hook_table_count);

    _dyld_register_func_for_add_image(myjb_hide_uikit_added);
}
