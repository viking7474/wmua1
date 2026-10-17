#ifndef jbutil_tnsv2_h
#define jbutil_tnsv2_h

#include "common.h"

#define CS_VALID                                0x00000001
#define CS_ADHOC                                0x00000002
#define CS_GET_TASK_ALLOW                       0x00000004
#define CS_INSTALLER                            0x00000008
#define CS_FORCED_LV                            0x00000010
#define CS_INVALID_ALLOWED                      0x00000020
#define CS_HARD                                 0x00000100
#define CS_KILL                                 0x00000200
#define CS_CHECK_EXPIRATION                     0x00000400
#define CS_RESTRICT                             0x00000800
#define CS_ENFORCEMENT                          0x00001000
#define CS_REQUIRE_LV                           0x00002000
#define CS_ENTITLEMENTS_VALIDATED               0x00004000
#define CS_NVRAM_UNRESTRICTED                   0x00008000
#define CS_RUNTIME                              0x00010000
#define CS_EXEC_SET_HARD                        0x00100000
#define CS_EXEC_SET_KILL                        0x00200000
#define CS_EXEC_SET_ENFORCEMENT                 0x00400000
#define CS_EXEC_INHERIT_SIP                     0x00800000
#define CS_KILLED                               0x01000000
#define CS_DYLD_PLATFORM                        0x02000000
#define CS_PLATFORM_BINARY                      0x04000000
#define CS_PLATFORM_PATH                        0x08000000
#define CS_DEBUGGED                             0x10000000
#define CS_SIGNED                               0x20000000
#define CS_DEV_CODE                             0x40000000
#define CS_DATAVAULT_CONTROLLER                 0x80000000
#define CS_EXECSEG_MAIN_BINARY                  0x00000001
#define CS_EXECSEG_ALLOW_UNSIGNED               0x00000010
#define CS_EXECSEG_DEBUGGER                     0x00000020
#define CS_EXECSEG_JIT                          0x00000040
#define CS_EXECSEG_SKIP_LV                      0x00000080
#define P_SUGID                                 0x00000100
#define VISSHADOW                               0x00008000

extern xpc_object_t xpc_create_from_plist(void *data, size_t size);

int tnsv2_startup(void);

#endif /* jbutil_tnsv2_h */
