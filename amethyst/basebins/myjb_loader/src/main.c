#include "basebin_util.h"
#include "basebin_jbserver.h"
#include "myjb_format.h"
#include "myjb_container.h"
#include "myjb_hide.h"
#include "myjb_test.h"
#include "monocypher.h"

#include <fnmatch.h>

#define MYJB_MAX_CONTAINERS 32
#define MYJB_MAX_LEGACY 32
#define MYJB_MAX_PAYLOAD_SIZE (64 * 1024 * 1024)
#define MYJB_MAX_KEYS 4

static const uint8_t myjb_embedded_pubkey[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

typedef struct {
    uint8_t key[32];
    const char *label;
} myjb_key_t;

typedef struct {
    char path[PATH_MAX];
    uint8_t *data;
    uint32_t size;
    myjb_container_t container;
} myjb_container_entry_t;

static myjb_container_entry_t myjb_containers[MYJB_MAX_CONTAINERS];
static uint32_t myjb_container_count = 0;
static char myjb_legacy_paths[MYJB_MAX_LEGACY][PATH_MAX];
static uint32_t myjb_legacy_count = 0;
static char myjb_seen_ids[MYJB_MAX_CONTAINERS][MYJB_TWEAK_ID_LEN];
static uint32_t myjb_seen_count = 0;

static const char *myjb_staging_dirs[] = {
    "/var/jb/usr/lib/myjb/run",
    "/var/mobile/Library/MyJB/run",
    "/tmp",
    NULL
};

static const char *myjb_container_dirs[] = {
    "/var/jb/usr/lib/myjb/containers",
    "/var/mobile/Library/MyJB/containers",
    NULL
};

static const char *myjb_legacy_dirs[] = {
    "/var/jb/Library/TweakInject",
    "/var/mobile/Library/TweakInject",
    NULL
};

static const char *myjb_engine_paths[] = {
    "/var/jb/usr/lib/libhooker.dylib",
    "/usr/lib/libhooker.dylib",
    "/var/jb/usr/lib/libsubstrate.dylib",
    "/usr/lib/libsubstrate.dylib",
    NULL
};

static void myjb_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);

    if (getenv("MYJB_DEBUG") != NULL) {
        FILE *file = fopen("/var/mobile/Library/MyJB/loader.log", "a");
        if (file != NULL) {
            va_start(args, fmt);
            vfprintf(file, fmt, args);
            va_end(args);
            fputc('\n', file);
            fclose(file);
        }
    }
}

static int myjb_read_exact(const char *path, uint8_t *out, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < size) {
        ssize_t rd = read(fd, out + done, size - done);
        if (rd <= 0) { close(fd); return -1; }
        done += (size_t)rd;
    }
    close(fd);
    return 0;
}

static void myjb_get_exec_path(char *out, size_t out_size) {
    out[0] = '\0';
    uint32_t size = (uint32_t)out_size;
    _NSGetExecutablePath(out, &size);
}

static uint32_t myjb_ios_version_code(void) {
    char version[64] = {0};
    size_t size = sizeof(version) - 1;
    if (sysctlbyname("kern.osproductversion", version, &size, NULL, 0) != 0) return 0;
    unsigned major = 0;
    unsigned minor = 0;
    sscanf(version, "%u.%u", &major, &minor);
    return (major * 100) + minor;
}

static void *myjb_find_base_hook(void) {
    uint32_t count = myjb_real_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = myjb_real_image_name(i);
        if (name == NULL) continue;
        if (strstr(name, "base_hook.dylib") == NULL) continue;
        return dlopen(name, RTLD_NOW);
    }
    return NULL;
}

static uint32_t myjb_collect_keys(myjb_key_t *keys) {
    static const char *key_files[] = {
        "/var/mobile/Library/MyJB/kdev",
        "/amethyst/.myjb_devkey",
        NULL
    };
    uint32_t count = 0;

    for (uint32_t i = 0; key_files[i] != NULL && count < MYJB_MAX_KEYS; i++) {
        if (myjb_read_exact(key_files[i], keys[count].key, 32) == 0) {
            keys[count].label = key_files[i];
            count++;
        }
    }

    void *base_hook = myjb_find_base_hook();
    if (base_hook != NULL) {
        uint8_t *session_key = dlsym(base_hook, "myjb_tweak_key");
        int *attested = dlsym(base_hook, "myjb_attested");
        if (session_key != NULL && attested != NULL && *attested != 0 && count < MYJB_MAX_KEYS) {
            memcpy(keys[count].key, session_key, 32);
            keys[count].label = "session-attest";
            count++;
        }
    }
    return count;
}

static bool myjb_id_seen(const char *tweak_id) {
    for (uint32_t i = 0; i < myjb_seen_count; i++) {
        if (strncmp(myjb_seen_ids[i], tweak_id, MYJB_TWEAK_ID_LEN) == 0) return true;
    }
    return false;
}

static void myjb_id_remember(const char *tweak_id) {
    if (myjb_seen_count >= MYJB_MAX_CONTAINERS) return;
    strlcpy(myjb_seen_ids[myjb_seen_count], tweak_id, MYJB_TWEAK_ID_LEN);
    myjb_seen_count++;
}

static uint32_t myjb_dir_collect(const char *dir_path, const char *extension,
                                 char paths[][PATH_MAX], uint32_t max) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) return 0;

    uint32_t count = 0;
    struct dirent *entry = NULL;
    while (count < max && (entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        const char *ext = strrchr(entry->d_name, '.');
        if (ext == NULL || strcmp(ext, extension) != 0) continue;

        char path[PATH_MAX] = {0};
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        struct stat st = {0};
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        strlcpy(paths[count], path, PATH_MAX);
        count++;
    }
    closedir(dir);

    for (uint32_t i = 1; i < count; i++) {
        char tmp[PATH_MAX] = {0};
        strlcpy(tmp, paths[i], PATH_MAX);
        uint32_t j = i;
        while (j > 0 && strcmp(paths[j - 1], tmp) > 0) {
            strlcpy(paths[j], paths[j - 1], PATH_MAX);
            j--;
        }
        strlcpy(paths[j], tmp, PATH_MAX);
    }
    return count;
}

static int myjb_stage_write(const uint8_t *data, uint32_t size, char *out_path, size_t out_size) {
    for (uint32_t i = 0; myjb_staging_dirs[i] != NULL; i++) {
        const char *dir = myjb_staging_dirs[i];
        mkdir(dir, 01777);
        chmod(dir, 01777);

        char path[PATH_MAX] = {0};
        snprintf(path, sizeof(path), "%s/myjb-%d-%08x.dylib", dir, getpid(), arc4random());
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd < 0) continue;

        int ok = 1;
        uint32_t done = 0;
        while (done < size) {
            ssize_t written = write(fd, data + done, size - done);
            if (written <= 0) { ok = 0; break; }
            done += (uint32_t)written;
        }
        close(fd);
        if (!ok) { unlink(path); continue; }

        strlcpy(out_path, path, out_size);
        return 0;
    }
    return -1;
}

static int myjb_load_payload(const uint8_t *data, uint32_t size, const char *desc, bool global) {
    if (data == NULL || size == 0) return -1;

    char path[PATH_MAX] = {0};
    if (myjb_stage_write(data, size, path, sizeof(path)) != 0) {
        myjb_log("myjb_loader: %s: cannot stage payload", desc);
        return -1;
    }

    jbserver_err_t err = jbserver_process_library(path);
    if (err != JBSERVER_ERR_SUCCESS) {
        myjb_log("myjb_loader: %s: trustcache/sign unavailable (%d), loading anyway", desc, err);
    }

    void *handle = dlopen(path, RTLD_NOW | (global ? RTLD_GLOBAL : 0));
    unlink(path);
    if (handle == NULL) {
        const char *error = dlerror();
        myjb_log("myjb_loader: %s: dlopen failed: %s", desc, error != NULL ? error : "unknown");
        return -1;
    }

    myjb_log("myjb_loader: %s: loaded", desc);
    return 0;
}

static void myjb_load_engine(void) {
    if (dlsym(RTLD_DEFAULT, "MSHookFunction") != NULL) return;

    for (uint32_t i = 0; myjb_engine_paths[i] != NULL; i++) {
        uint32_t size = 0;
        uint8_t *data = map_file(myjb_engine_paths[i], &size, false);
        if (data == NULL || size == 0) {
            if (data != NULL) unmap_file(data, size);
            continue;
        }
        int loaded = myjb_load_payload(data, size, "hook-engine", true);
        unmap_file(data, size);
        if (loaded == 0) return;
    }
}

static void myjb_scan_containers(const uint8_t pubkey[32]) {
    static char paths[MYJB_MAX_CONTAINERS][PATH_MAX];
    uint32_t ios = myjb_ios_version_code();
    char exec_path[PATH_MAX] = {0};
    myjb_get_exec_path(exec_path, sizeof(exec_path));

    for (uint32_t d = 0; myjb_container_dirs[d] != NULL; d++) {
        uint32_t path_count = myjb_dir_collect(myjb_container_dirs[d], ".myjb",
                                               paths, MYJB_MAX_CONTAINERS);
        for (uint32_t i = 0; i < path_count && myjb_container_count < MYJB_MAX_CONTAINERS; i++) {
            uint32_t size = 0;
            uint8_t *data = map_file(paths[i], &size, false);
            if (data == NULL || size == 0 || size > MYJB_MAX_PAYLOAD_SIZE) {
                if (data != NULL) unmap_file(data, size);
                continue;
            }

            myjb_container_entry_t *entry = &myjb_containers[myjb_container_count];
            if (myjb_container_parse(data, size, pubkey, &entry->container) != 0) {
                myjb_log("myjb_loader: %s: parse/verify failed", paths[i]);
                unmap_file(data, size);
                continue;
            }

            const myjb_manifest_t *manifest = &entry->container.manifest;
            if (manifest->min_ios != 0 && ios != 0 && ios < manifest->min_ios) {
                unmap_file(data, size);
                continue;
            }
            if (manifest->target_jb != MYJB_TARGET_JB_ANY &&
                manifest->target_jb != MYJB_TARGET_JB_CURRENT) {
                unmap_file(data, size);
                continue;
            }
            if (!myjb_container_matches_process(&entry->container, exec_path)) {
                unmap_file(data, size);
                continue;
            }
            if (myjb_id_seen(manifest->tweak_id)) {
                unmap_file(data, size);
                continue;
            }

            myjb_id_remember(manifest->tweak_id);
            strlcpy(entry->path, paths[i], sizeof(entry->path));
            entry->data = data;
            entry->size = size;
            myjb_container_count++;
        }
    }
}

static void myjb_load_containers(myjb_key_t *keys, uint32_t key_count) {
    for (uint32_t i = 0; i < myjb_container_count; i++) {
        myjb_container_entry_t *entry = &myjb_containers[i];
        uint64_t payload_size = entry->container.manifest.payload_size;
        const char *tweak_id = entry->container.manifest.tweak_id;

        if (payload_size == 0 || payload_size > MYJB_MAX_PAYLOAD_SIZE) continue;
        uint8_t *payload = malloc((size_t)payload_size);
        if (payload == NULL) continue;

        bool decrypted = false;
        for (uint32_t k = 0; k < key_count; k++) {
            if (myjb_container_decrypt(&entry->container, keys[k].key, payload) != 0) continue;
            decrypted = true;
            myjb_load_payload(payload, (uint32_t)payload_size, tweak_id, false);
            break;
        }

        if (!decrypted) {
            myjb_log("myjb_loader: %s: no available key could decrypt", tweak_id);
        }
        memset(payload, 0, (size_t)payload_size);
        free(payload);
    }

    for (uint32_t i = 0; i < myjb_container_count; i++) {
        unmap_file(myjb_containers[i].data, myjb_containers[i].size);
        myjb_containers[i].data = NULL;
    }
}

static void myjb_scan_legacy(void) {
    char paths[MYJB_MAX_LEGACY][PATH_MAX];
    for (uint32_t d = 0; myjb_legacy_dirs[d] != NULL && myjb_legacy_count < MYJB_MAX_LEGACY; d++) {
        uint32_t count = myjb_dir_collect(myjb_legacy_dirs[d], ".dylib", paths, MYJB_MAX_LEGACY);
        for (uint32_t i = 0; i < count && myjb_legacy_count < MYJB_MAX_LEGACY; i++) {
            strlcpy(myjb_legacy_paths[myjb_legacy_count], paths[i], PATH_MAX);
            myjb_legacy_count++;
        }
    }
}

static void myjb_load_legacy(void) {
    for (uint32_t i = 0; i < myjb_legacy_count; i++) {
        uint32_t size = 0;
        uint8_t *data = map_file(myjb_legacy_paths[i], &size, false);
        if (data == NULL || size == 0) {
            if (data != NULL) unmap_file(data, size);
            continue;
        }
        myjb_load_payload(data, size, myjb_legacy_paths[i], false);
        unmap_file(data, size);
    }
}

static void myjb_start(void) {
    if (getenv("MYJB_DISABLE") != NULL) return;
    if (access("/amethyst/.myjb_disabled", F_OK) == 0) return;

    uint8_t pubkey[32] = {0};
    memcpy(pubkey, myjb_embedded_pubkey, sizeof(pubkey));
    myjb_read_exact("/amethyst/.myjb_pubkey", pubkey, sizeof(pubkey));

    myjb_key_t keys[MYJB_MAX_KEYS] = {0};
    uint32_t key_count = myjb_collect_keys(keys);

    myjb_scan_containers(pubkey);

    bool legacy_enabled = (getenv("MYJB_LEGACY") != NULL) ||
                          (access("/amethyst/.myjb_legacy", F_OK) == 0);
    if (legacy_enabled) myjb_scan_legacy();

    if (myjb_container_count == 0 && myjb_legacy_count == 0) return;

    char exec_path[PATH_MAX] = {0};
    myjb_get_exec_path(exec_path, sizeof(exec_path));
    myjb_log("myjb_loader: %s: %u container(s), %u legacy, %u key(s)",
             exec_path, myjb_container_count, myjb_legacy_count, key_count);

    myjb_load_engine();
    if (myjb_container_count > 0) myjb_load_containers(keys, key_count);
    if (myjb_legacy_count > 0) myjb_load_legacy();

    crypto_wipe(keys, sizeof(keys));
}

__attribute__((constructor)) static void myjb_loader_init(int argc, char **argv, char **envp, char **apple) {
    (void)argc;
    (void)argv;
    (void)envp;
    basebin_init(apple);
    myjb_start();
    myjb_test_start();
    myjb_hide_start();
}
