#ifndef myjb_test_h
#define myjb_test_h

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

void myjb_test_start(void);

bool myjb_test_sysctl_hook(int *name, u_int namelen, void *oldp, size_t *oldlenp,
                           void *newp, size_t newlen, int *out_status);
bool myjb_test_sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp,
                                 void *newp, size_t newlen, int *out_status);

#endif /* myjb_test_h */
