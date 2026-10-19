#include <dlfcn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void *(*myjb_dlopen_handler_t)(const char *, int, void *, bool *);
typedef int (*myjb_dlpre_handler_t)(const char *, void *, bool *);
typedef int (*myjb_dlsym_handler_t)(void *, const char *, void *);

__attribute__((visibility("default"))) myjb_dlopen_handler_t myjb_dlopen_handler = NULL;
__attribute__((visibility("default"))) myjb_dlpre_handler_t myjb_dlopen_preflight_handler = NULL;
__attribute__((visibility("default"))) myjb_dlsym_handler_t myjb_dlsym_handler = NULL;

__attribute__((visibility("default"))) void *myjb_real_dlsym = (void *)&dlsym;

static void *myjb_interpose_dlopen(const char *path, int mode) {
    myjb_dlopen_handler_t handler = myjb_dlopen_handler;
    if (handler != NULL) {
        bool handled = false;
        void *result = handler(path, mode, __builtin_return_address(0), &handled);
        if (handled) return result;
    }
    return dlopen(path, mode);
}

static int myjb_interpose_dlopen_preflight(const char *path) {
    myjb_dlpre_handler_t handler = myjb_dlopen_preflight_handler;
    if (handler != NULL) {
        bool handled = false;
        int result = handler(path, __builtin_return_address(0), &handled);
        if (handled) return result;
    }
    return dlopen_preflight(path);
}

__asm__(
    ".text\n"
    ".p2align 2\n"
    ".globl _myjb_interpose_dlsym\n"
    "_myjb_interpose_dlsym:\n"
    "  adrp x9, _myjb_dlsym_handler@GOTPAGE\n"
    "  ldr  x9, [x9, _myjb_dlsym_handler@GOTPAGEOFF]\n"
    "  ldr  x9, [x9]\n"
    "  cbz  x9, 2f\n"
    "  stp  x29, x30, [sp, #-32]!\n"
    "  mov  x29, sp\n"
    "  stp  x0, x1, [sp, #16]\n"
    "  mov  x2, x30\n"
    "  blr  x9\n"
    "  mov  w9, w0\n"
    "  ldp  x0, x1, [sp, #16]\n"
    "  ldp  x29, x30, [sp], #32\n"
    "  cbz  w9, 2f\n"
    "  mov  x0, #0\n"
    "  ret\n"
    "2:\n"
    "  adrp x9, _myjb_real_dlsym@GOTPAGE\n"
    "  ldr  x9, [x9, _myjb_real_dlsym@GOTPAGEOFF]\n"
    "  ldr  x9, [x9]\n"
    "  br   x9\n"
);

extern void myjb_interpose_dlsym(void);

struct myjb_interpose_tuple {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose"))) static const struct myjb_interpose_tuple myjb_interpose_tuples[] = {
    { (const void *)(unsigned long)&myjb_interpose_dlopen,
      (const void *)(unsigned long)&dlopen },
    { (const void *)(unsigned long)&myjb_interpose_dlopen_preflight,
      (const void *)(unsigned long)&dlopen_preflight },
    { (const void *)(unsigned long)&myjb_interpose_dlsym,
      (const void *)(unsigned long)&dlsym },
};
