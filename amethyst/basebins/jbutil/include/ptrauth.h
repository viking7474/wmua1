#ifndef jbutil_ptrauth_h
#define jbutil_ptrauth_h

#include "common.h"

#if defined(__arm64e__)
void *ptrauth_ia(void *ptr, void *ctx);
void *ptrauth_ib(void *ptr, void *ctx);
void *ptrauth_da(void *ptr, void *ctx);
void *ptrauth_db(void *ptr, void *ctx);
void *autha_xpaci(void *ptr, void *ctx);
void *autha_xpacd(void *ptr, void *ctx);
void *authb_xpaci(void *ptr, void *ctx);
void *authb_xpacd(void *ptr, void *ctx);
void *xpaci(void *ptr);
void *xpacd(void *ptr);
void *hash_discriminator(char *str);
#else
#define ptrauth_ia(ptr, __unused) ((void *)ptr)
#define ptrauth_ib(ptr, __unused) ((void *)ptr)
#define ptrauth_da(ptr, __unused) ((void *)ptr)
#define ptrauth_db(ptr, __unused) ((void *)ptr)
#define autha_xpaci(ptr, __unused) ((void *)ptr)
#define autha_xpacd(ptr, __unused) ((void *)ptr)
#define authb_xpaci(ptr, __unused) ((void *)ptr)
#define authb_xpacd(ptr, __unused) ((void *)ptr)
#define xpaci(ptr) ((void *)ptr)
#define xpacd(ptr) ((void *)ptr)
#define hash_discriminator(__unused) (0)
#endif

#endif /* jbutil_ptrauth_h */
