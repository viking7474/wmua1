#ifndef remount_h
#define remount_h

#include <stdio.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/snapshot.h>
#include <sys/mount.h>
#include <mach/mach.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>
#include <paths.h>
#include <device/device_types.h>

#define SI_MOUNTEDON    0x0001
#define SI_ALIASED      0x0002

#define ROOT_DEVICE_PATH "/dev/disk0s1s1"
#define MOUNT_POINT_PATH "/var/rootfsmnt"
#define OTA_PATH "/var/MobileSoftwareUpdate/mnt1"
#define SNAPSHOT_PREFIX "com.apple.os.update-"

typedef enum {
    REMOUNT_SUCCESS = 0,
    REMOUNT_FAILURE,
    REMOUNT_NEED_REBOOT,
    RESTORE_NEED_REBOOT,
    RESTORE_FAILURE,
    OTA_IS_MOUNTED
} remount_err_t;

typedef struct {
    char *fspec;
    uid_t hfs_uid;
    gid_t hfs_gid;
    mode_t hfs_mask;
    u_int32_t hfs_encoding;
    struct timezone hfs_timezone;
    int flags;
    int journal_tbuffer_size;
    int journal_flags;
    int journal_disable;
} hfs_mount_args_t;

remount_err_t restore_rootfs(void);
remount_err_t remount_rootfs(void);

#endif /* remount_h */
