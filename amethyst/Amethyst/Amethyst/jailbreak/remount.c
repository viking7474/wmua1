#include "jailbreak.h"
#include "utils.h"
#include "trustcache.h"
#include "install.h"
#include "remount.h"

static char *find_snapshot(void) {
    mach_port_t entry = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
    if (!MACH_PORT_VALID(entry)) return NULL;
    
    char bm_hash[128] = {0};
    uint8_t buf[48] = {0};
    uint32_t len = sizeof(buf);
    
    if (IORegistryEntryGetProperty(entry, "boot-manifest-hash", (void *)&buf[0], &len) != 0) {
        IOObjectRelease(entry);
        return NULL;
    }
    
    for (uint32_t i = 0; i < len; i++) {
        sprintf(&bm_hash[i*2], "%02X", buf[i]);
    }

    IOObjectRelease(entry);
    uint32_t snapshot_len = (uint32_t)(strlen(bm_hash) + strlen(SNAPSHOT_PREFIX) + 1);
    char *snapshot = calloc(1, snapshot_len+1);
    if (snapshot == NULL) return NULL;
    
    snprintf(snapshot, snapshot_len, "%s%s", SNAPSHOT_PREFIX, bm_hash);
    return snapshot;
}

static bool is_path_mountpoint(const char *path) {
    struct stat st = {0};
    if (access(path, R_OK) != 0) return false;
    if (lstat(path, &st) != 0) return false;
    if ((st.st_mode & S_IFMT) != S_IFDIR) return false;
    
    dev_t main_dev = st.st_dev;
    ino_t main_ino = st.st_ino;
    char *saved_wd = getcwd(NULL, 0);
    chdir(path);
    
    int status = lstat("..", &st);
    chdir(saved_wd);
    free(saved_wd);
    
    if (status != 0) return false;
    return (main_dev != st.st_dev) || (main_ino != st.st_ino);
}

static bool need_rename_snapshot(void) {
    __block bool status = false;
    run_with_cred(0, ^{
        int fd = open("/", O_RDONLY, 0);
        if (fd >= 0) {
            struct attrlist attr = {.commonattr = ATTR_BULK_REQUIRED};
            uint8_t buf[0x800] = {0};
            
            int count = fs_snapshot_list(fd, &attr, buf, 0x800, 0);
            close(fd);
            status = (count == -1);
        }
    });
    return status;
}

static int revert_snapshot(const char *path, const char *snapshot) {
    __block int status = -1;
    run_with_cred(0, ^{
        errno = 0;
        int fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
            status = errno;
            return;
        }
        
        errno = 0;
        status = fs_snapshot_revert(fd, snapshot, 0);
        close(fd);
        if (status != 0) status = errno;
    });
    return status;
}

static int rename_snapshot(const char *path, const char *old, const char *new) {
    __block int status = 0;
    run_with_cred(0, ^{
        errno = 0;
        int fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
            status = errno;
            return;
        }
        
        errno = 0;
        status = fs_snapshot_rename(fd, old, new, 0);
        close(fd);
        if (status != 0) status = errno;
    });
    return status;
}

static int mount_snapshot(const char *path, const char *at, const char *snapshot) {
    __block int status = 0;
    run_with_cred(0, ^{
        errno = 0;
        int fd = open(path, O_RDONLY, 0);
        if (fd < 0) {
            status = errno;
            return;
        }
        
        errno = 0;
        status = fs_snapshot_mount(fd, at, snapshot, 0);
        close(fd);
        if (status != 0) status = errno;
    });
    return status;
}

static int mount_at_path(char *dev, const char *path) {
    __block int status = 0;
    run_with_cred(0, ^{
        hfs_mount_args_t args = {0};
        args.fspec = dev;
        args.hfs_mask = 0x1;
        
        gettimeofday(NULL, &args.hfs_timezone);
        
        errno = 0;
        status = mount("apfs", path, 0, (void *)&args);
        if (status != 0) status = errno;
    });
    return status;
}

static uint64_t get_root_vnode(void) {
    uint64_t rootvnode = vnode_for_path("/");
    if (rootvnode != 0) return rootvnode;
    
    int fd = open("/sbin/launchd", O_RDONLY);
    if (fd < 0) return 0;
    uint64_t vnode = vnode_for_fd(fd);
    close(fd);
    
    if (vnode == 0) return 0;
    uint64_t sbin_vnode = kread64(vnode + koffsetof(vnode, v_parent));
    if (sbin_vnode == 0) return 0;
    return kread64(sbin_vnode + koffsetof(vnode, v_parent));
}

static uint64_t get_root_device(void) {
    uint64_t rootvnode = get_root_vnode();
    if (rootvnode == 0) return 0;

    uint64_t v_mount = kread64(rootvnode + koffsetof(vnode, v_mount));
    if (v_mount != 0) {
        uint64_t device = kread64(v_mount + koffsetof(mount, devvp));
        if (device != 0) return device;
    }
    return vnode_for_path(ROOT_DEVICE_PATH);
}

static uint64_t get_updated_mount(void) {
    uint64_t rootvnode = get_root_vnode();
    if (rootvnode == 0) return 0;
    
    uint64_t v_mount = kread64(rootvnode + koffsetof(vnode, v_mount));
    if (v_mount != 0) v_mount = kread64(v_mount + koffsetof(mount, mnt_next));

    while (v_mount != 0) {
        uint64_t device = kread64(v_mount + koffsetof(mount, devvp));
        uint64_t device_name_ptr = kread64(device + koffsetof(vnode, v_name));
        char device_name[20] = {0};
        
        kread_buf(device_name_ptr, device_name, 20);
        if (strcmp(device_name, "disk0s1s1") == 0) return v_mount;
        v_mount = kread64(v_mount + koffsetof(mount, mnt_next));
    }
    return 0;
}

remount_err_t restore_rootfs(void) {
    if (need_rename_snapshot()) return RESTORE_NEED_REBOOT;
    rmdir(MOUNT_POINT_PATH);
    sync();
    
    if (mkdir(MOUNT_POINT_PATH, 0755) != 0) return RESTORE_FAILURE;
    chown(MOUNT_POINT_PATH, 0, 0);
        
    const char *snapshot = find_snapshot();
    if (snapshot == NULL) return RESTORE_FAILURE;
    if (rename_snapshot("/", "orig-fs", snapshot) != 0) return RESTORE_FAILURE;
    if (revert_snapshot("/", snapshot) != 0) return RESTORE_FAILURE;
    if (mount_snapshot("/", MOUNT_POINT_PATH, snapshot) != 0) return RESTORE_FAILURE;
    
    DIR *dir = opendir("/Applications");
    struct dirent *entry = NULL;

    if (dir != NULL && access("/amethyst/jbutil", F_OK) == 0) {
        trustcache_add_binary("/amethyst/jbutil");
        while ((entry = readdir(dir)) != NULL) {
            char snapshot_path[PATH_MAX] = {0};
            snprintf(snapshot_path, PATH_MAX, "/var/rootfsmnt/Applications/%s", entry->d_name);
            if (access(snapshot_path, F_OK) == 0) continue;
            
            char app_path[PATH_MAX] = {0};
            snprintf(app_path, PATH_MAX, "/Applications/%s", entry->d_name);
            run_jbutil("--unregister-app", app_path, false);
        }
        
        closedir(dir);
        if (access("/var/binpack/Applications/loader.app", F_OK) == 0) {
            run_jbutil("--unregister-app", "/var/binpack/Applications/loader.app", false);
        }
        
        if (access("/Applications/Cydia.app", F_OK) == 0) {
            run_jbutil("--unregister-app", "/Applications/Cydia.app", false);
        }
    }

    run_with_cred(0, ^{
        unmount(MOUNT_POINT_PATH, MNT_FORCE);
        remove_at_path(MOUNT_POINT_PATH);
        sync();
    });
    
    restore_cleanup();
    return RESTORE_NEED_REBOOT;
}

remount_err_t remount_rootfs(void) {
    if (!is_path_mountpoint("/var/MobileSoftwareUpdate/mnt1")) {
        if (access("/var/MobileSoftwareUpdate/mnt1", F_OK) != 0) {
            run_with_cred(0, ^{
                mkdir("/var/MobileSoftwareUpdate", 0777);
                chown("/var/MobileSoftwareUpdate", 0, 0);
                mkdir("/var/MobileSoftwareUpdate/mnt1", 0777);
                chown("/var/MobileSoftwareUpdat/mnt1", 0, 0);
            });
        }
        if (!is_path_mountpoint("/var/MobileSoftwareUpdate/mnt1")) return OTA_IS_MOUNTED;
    }

    if (need_rename_snapshot()) {
        if (is_path_mountpoint(MOUNT_POINT_PATH)) {
            run_with_cred(0, ^{
                unmount(MOUNT_POINT_PATH, MNT_FORCE);
                remove_at_path(MOUNT_POINT_PATH);
                sync();
            });
        }

        remove_at_path(MOUNT_POINT_PATH);
        if (mkdir(MOUNT_POINT_PATH, 0755) != 0) return REMOUNT_FAILURE;
        chown(MOUNT_POINT_PATH, 0, 0);

        uint64_t root_device = get_root_device();
        if (root_device == 0) return REMOUNT_FAILURE;

        uint64_t specinfo = kread64(root_device + koffsetof(vnode, specinfo));
        kwrite32(specinfo + koffsetof(specinfo, flags), 0);
        if (mount_at_path(ROOT_DEVICE_PATH, MOUNT_POINT_PATH) != 0) return REMOUNT_FAILURE;
        
        char *snapshot = find_snapshot();
        if (snapshot == NULL) return REMOUNT_FAILURE;
        if (revert_snapshot(MOUNT_POINT_PATH, snapshot) != 0) return REMOUNT_FAILURE;
        
        root_device = get_root_device();
        if (root_device == 0) return REMOUNT_FAILURE;

        specinfo = kread64(root_device + koffsetof(vnode, specinfo));
        kwrite32(specinfo + koffsetof(specinfo, flags), 0);
        run_with_cred(0, ^{
            unmount(MOUNT_POINT_PATH, MNT_FORCE);
        });

        if (mount_at_path(ROOT_DEVICE_PATH, MOUNT_POINT_PATH) != 0) return REMOUNT_FAILURE;
        uint64_t updated_mount = get_updated_mount();
        if (updated_mount == 0) return REMOUNT_FAILURE;
    
        char name[PATH_MAX] = {0};
        uint64_t vnode = vnode_for_path(MOUNT_POINT_PATH);
        uint64_t v_mount = kread64(vnode + koffsetof(vnode, v_mount));
        uint64_t v_list = kread64(v_mount + koffsetof(mount, vnodelist));

        while (v_list != 0) {
            kread_buf(kread64(v_list + koffsetof(vnode, v_name)), name, 512);
            if (strcmp(snapshot, name) == 0) {
                uint64_t v_data = kread64(v_list + koffsetof(vnode, v_data));
                uint32_t flag = kread32(v_data + koffsetof(vnode, v_data_flag));
                kwrite32(v_data + koffsetof(vnode, v_data_flag), flag & ~0x40);
                break;
            }
            v_list = kread64(v_list + 0x20);
        }

        if (rename_snapshot(MOUNT_POINT_PATH, snapshot, "orig-fs") != 0) return REMOUNT_FAILURE;
        return REMOUNT_NEED_REBOOT;
    } else {
        uint64_t vnode = vnode_for_path("/");
        uint64_t v_mount = kread64(vnode + koffsetof(vnode, v_mount));
        uint32_t v_flag = kread32(v_mount + koffsetof(mount, flag));

        v_flag &= ~MNT_RDONLY;
        v_flag &= ~MNT_ROOTFS;
        kwrite32(v_mount + koffsetof(mount, flag), v_flag);
        
        char *path = strdup("/dev/disk0s1s1");
        int status = mount("apfs", "/", MNT_UPDATE, &path);
        free(path);
        if (status != 0) return REMOUNT_FAILURE;
        
        kwrite32(v_mount + koffsetof(mount, flag), v_flag | MNT_NOSUID | MNT_ROOTFS);
        close(open("/.amethyst", O_CREAT | O_RDWR, 0644));
        sync();
        
        remount_err_t err = (access("/.amethyst", F_OK) == 0) ? REMOUNT_SUCCESS : REMOUNT_FAILURE;
        remove("/.amethyst");
        return err;
    }
    return REMOUNT_FAILURE;
}
