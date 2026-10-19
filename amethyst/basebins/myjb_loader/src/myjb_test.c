#include "myjb_test.h"
#include "basebin_common.h"
#include "basebin_hook.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <syslog.h>
#include <unistd.h>

#define MYJB_TEST_MACHINE "iPhone14,2"
#define MYJB_TEST_HWMODEL "D63AP"
#define MYJB_TEST_SERIAL "F2LX9MYJB0K1"
#define MYJB_TEST_UUID "6D796A42-0000-4000-8000-4D594A420001"
#define MYJB_TEST_MEMSIZE 6442450944ULL
#define MYJB_TEST_NCPU 6

#define MYJB_TEST_FLAG "/var/mobile/Library/MyJB/spoof"
#define MYJB_TEST_FLAG_AMETHYST "/amethyst/.myjb_spoof"

enum {
    MYJB_TEST_HIT_UNAME = 1u << 0,
    MYJB_TEST_HIT_MACHINE = 1u << 1,
    MYJB_TEST_HIT_MODEL = 1u << 2,
    MYJB_TEST_HIT_MEMSIZE = 1u << 3,
    MYJB_TEST_HIT_NCPU = 1u << 4,
    MYJB_TEST_HIT_MG = 1u << 5,
    MYJB_TEST_HIT_IOKIT = 1u << 6,
};

static int g_test_state = -1;
static uint32_t g_test_hits = 0;
static bool g_test_started = false;

static void myjb_test_hit(uint32_t bit, const char *what, const char *value) {
    if ((g_test_hits & bit) != 0) return;
    g_test_hits |= bit;
    syslog(LOG_ERR, "[myjb_test] spoof %s -> %s", what, value);
}

static bool myjb_test_enabled(void) {
    if (g_test_state >= 0) return g_test_state != 0;

    const char *env = getenv("MYJB_SPOOF");
    bool requested = (env != NULL && strcmp(env, "0") != 0) ||
                     access(MYJB_TEST_FLAG, F_OK) == 0 ||
                     access(MYJB_TEST_FLAG_AMETHYST, F_OK) == 0;
    g_test_state = 0;
    if (!requested) return false;

    char exec_path[PATH_MAX] = {0};
    uint32_t size = sizeof(exec_path);
    _NSGetExecutablePath(exec_path, &size);
    if (strncmp(exec_path, "/var/containers/Bundle/Application/", 35) != 0 &&
        strncmp(exec_path, "/private/var/containers/Bundle/Application/", 43) != 0 &&
        strncmp(exec_path, "/Applications/", 14) != 0) {
        return false;
    }

    g_test_state = 1;
    return true;
}

static int myjb_test_copy_string(const char *value, void *oldp, size_t *oldlenp) {
    size_t need = strlen(value) + 1;
    if (oldp == NULL) {
        *oldlenp = need;
        return 0;
    }
    if (*oldlenp < need) {
        *oldlenp = need;
        return ENOMEM;
    }
    memcpy(oldp, value, need);
    *oldlenp = need;
    return 0;
}

static int myjb_test_copy_int(int value, void *oldp, size_t *oldlenp) {
    size_t need = sizeof(value);
    if (oldp == NULL) {
        *oldlenp = need;
        return 0;
    }
    if (*oldlenp < need) {
        *oldlenp = need;
        return ENOMEM;
    }
    memcpy(oldp, &value, need);
    *oldlenp = need;
    return 0;
}

static int myjb_test_copy_u64(uint64_t value, void *oldp, size_t *oldlenp) {
    size_t need = sizeof(value);
    if (oldp == NULL) {
        *oldlenp = need;
        return 0;
    }
    if (*oldlenp < need) {
        *oldlenp = need;
        return ENOMEM;
    }
    memcpy(oldp, &value, need);
    *oldlenp = need;
    return 0;
}

bool myjb_test_sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                           void *newp, size_t newlen, int *out_status) {
    (void)newlen;
    if (!myjb_test_enabled()) return false;
    if (name == NULL || oldlenp == NULL || newp != NULL) return false;
    if (namelen < 2 || name[0] != CTL_HW) return false;

    switch (name[1]) {
        case HW_MACHINE:
            myjb_test_hit(MYJB_TEST_HIT_MACHINE, "hw.machine", MYJB_TEST_MACHINE);
            *out_status = myjb_test_copy_string(MYJB_TEST_MACHINE, oldp, oldlenp);
            return true;
        case HW_MODEL:
            myjb_test_hit(MYJB_TEST_HIT_MODEL, "hw.model", MYJB_TEST_HWMODEL);
            *out_status = myjb_test_copy_string(MYJB_TEST_HWMODEL, oldp, oldlenp);
            return true;
        case HW_MEMSIZE:
            myjb_test_hit(MYJB_TEST_HIT_MEMSIZE, "hw.memsize", "6442450944");
            *out_status = myjb_test_copy_u64(MYJB_TEST_MEMSIZE, oldp, oldlenp);
            return true;
        case HW_NCPU:
            myjb_test_hit(MYJB_TEST_HIT_NCPU, "hw.ncpu", "6");
            *out_status = myjb_test_copy_int(MYJB_TEST_NCPU, oldp, oldlenp);
            return true;
        default:
            return false;
    }
}

bool myjb_test_sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp,
                                 void *newp, size_t newlen, int *out_status) {
    (void)newlen;
    if (!myjb_test_enabled()) return false;
    if (name == NULL || oldlenp == NULL || newp != NULL) return false;

    if (strcmp(name, "hw.machine") == 0) {
        myjb_test_hit(MYJB_TEST_HIT_MACHINE, "hw.machine", MYJB_TEST_MACHINE);
        *out_status = myjb_test_copy_string(MYJB_TEST_MACHINE, oldp, oldlenp);
        return true;
    }
    if (strcmp(name, "hw.model") == 0) {
        myjb_test_hit(MYJB_TEST_HIT_MODEL, "hw.model", MYJB_TEST_HWMODEL);
        *out_status = myjb_test_copy_string(MYJB_TEST_HWMODEL, oldp, oldlenp);
        return true;
    }
    if (strcmp(name, "hw.memsize") == 0) {
        myjb_test_hit(MYJB_TEST_HIT_MEMSIZE, "hw.memsize", "6442450944");
        *out_status = myjb_test_copy_u64(MYJB_TEST_MEMSIZE, oldp, oldlenp);
        return true;
    }
    if (strcmp(name, "hw.ncpu") == 0 || strcmp(name, "hw.physicalcpu") == 0 ||
        strcmp(name, "hw.logicalcpu") == 0) {
        myjb_test_hit(MYJB_TEST_HIT_NCPU, "hw.ncpu", "6");
        *out_status = myjb_test_copy_int(MYJB_TEST_NCPU, oldp, oldlenp);
        return true;
    }
    return false;
}

static int (*g_uname)(struct utsname *) = NULL;

static int myjb_test_uname(struct utsname *info) {
    int status = g_uname(info);
    if (status == 0 && info != NULL && myjb_test_enabled()) {
        strlcpy(info->machine, MYJB_TEST_MACHINE, sizeof(info->machine));
        myjb_test_hit(MYJB_TEST_HIT_UNAME, "uname.machine", MYJB_TEST_MACHINE);
    }
    return status;
}

static CFStringRef (*g_mg_get_string_answer)(CFStringRef) = NULL;

static CFStringRef myjb_test_mg_get_string_answer(CFStringRef key) {
    if (key != NULL && myjb_test_enabled()) {
        char name[128] = {0};
        if (CFStringGetCString(key, name, sizeof(name), kCFStringEncodingUTF8)) {
            if (strcmp(name, "ProductType") == 0) {
                myjb_test_hit(MYJB_TEST_HIT_MG, "MG.ProductType", MYJB_TEST_MACHINE);
                return CFStringCreateWithCString(kCFAllocatorDefault, MYJB_TEST_MACHINE,
                                                 kCFStringEncodingUTF8);
            }
            if (strcmp(name, "HWModel") == 0) {
                myjb_test_hit(MYJB_TEST_HIT_MG, "MG.HWModel", MYJB_TEST_HWMODEL);
                return CFStringCreateWithCString(kCFAllocatorDefault, MYJB_TEST_HWMODEL,
                                                 kCFStringEncodingUTF8);
            }
        }
    }
    return g_mg_get_string_answer(key);
}

static CFTypeRef (*g_io_registry_create)(io_registry_entry_t, CFStringRef, CFAllocatorRef,
                                         IOOptionBits) = NULL;

static CFTypeRef myjb_test_io_registry_create(io_registry_entry_t entry, CFStringRef key,
                                              CFAllocatorRef allocator, IOOptionBits options) {
    if (key != NULL && myjb_test_enabled()) {
        char name[128] = {0};
        if (CFStringGetCString(key, name, sizeof(name), kCFStringEncodingUTF8)) {
            if (strcmp(name, "IOPlatformSerialNumber") == 0) {
                myjb_test_hit(MYJB_TEST_HIT_IOKIT, "IOPlatformSerialNumber", MYJB_TEST_SERIAL);
                return CFStringCreateWithCString(allocator, MYJB_TEST_SERIAL,
                                                 kCFStringEncodingUTF8);
            }
            if (strcmp(name, "IOPlatformUUID") == 0) {
                myjb_test_hit(MYJB_TEST_HIT_IOKIT, "IOPlatformUUID", MYJB_TEST_UUID);
                return CFStringCreateWithCString(allocator, MYJB_TEST_UUID,
                                                 kCFStringEncodingUTF8);
            }
        }
    }
    return g_io_registry_create(entry, key, allocator, options);
}

static void *myjb_test_install_hook(const char *name, void *replacement) {
    void *target = dlsym(RTLD_DEFAULT, name);
    if (target == NULL) {
        syslog(LOG_ERR, "[myjb_test] hook %s: symbol not found", name);
        return NULL;
    }

    void *original = NULL;
    if (hook_function(target, replacement, &original) != 0) {
        syslog(LOG_ERR, "[myjb_test] hook %s: patch failed", name);
        return NULL;
    }

    syslog(LOG_ERR, "[myjb_test] hook %s: ok", name);
    return original;
}

void myjb_test_start(void) {
    if (g_test_started) return;
    g_test_started = true;
    if (!myjb_test_enabled()) return;

    openlog("myjb_test", LOG_NDELAY, LOG_USER);

    char exec_path[PATH_MAX] = {0};
    uint32_t size = sizeof(exec_path);
    _NSGetExecutablePath(exec_path, &size);
    syslog(LOG_ERR, "[myjb_test] active in %s: %s (%s) mem %llu cpu %d",
           exec_path, MYJB_TEST_MACHINE, MYJB_TEST_HWMODEL,
           (unsigned long long)MYJB_TEST_MEMSIZE, MYJB_TEST_NCPU);

    g_uname = (int (*)(struct utsname *))myjb_test_install_hook("uname", (void *)myjb_test_uname);

    if (dlsym(RTLD_DEFAULT, "MGGetStringAnswer") == NULL) {
        dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    }
    g_mg_get_string_answer = (CFStringRef (*)(CFStringRef))
        myjb_test_install_hook("MGGetStringAnswer", (void *)myjb_test_mg_get_string_answer);

    if (dlsym(RTLD_DEFAULT, "IORegistryEntryCreateCFProperty") == NULL) {
        dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
    }
    g_io_registry_create = (CFTypeRef (*)(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits))
        myjb_test_install_hook("IORegistryEntryCreateCFProperty",
                               (void *)myjb_test_io_registry_create);

    syslog(LOG_ERR, "[myjb_test] setup done (sysctl spoof via myjb_hide hooks)");
}
