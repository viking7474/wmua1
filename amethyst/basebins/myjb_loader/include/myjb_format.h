#ifndef myjb_format_h
#define myjb_format_h

#include <stdint.h>

#define MYJB_MAGIC "MYJB"
#define MYJB_FORMAT_VERSION 1
#define MYJB_ALGO_ID 1
#define MYJB_HEADER_SIZE 12
#define MYJB_MANIFEST_SIZE 712
#define MYJB_SIGNATURE_SIZE 64
#define MYJB_TAG_SIZE 16

#define MYJB_MAX_FILTERS 8
#define MYJB_FILTER_LEN 64
#define MYJB_TWEAK_ID_LEN 64
#define MYJB_VERSION_LEN 32

#define MYJB_TARGET_JB_ANY 0xFFFF
#define MYJB_TARGET_JB_CHECKM8 1
#define MYJB_TARGET_JB_AMETHYST 2
#define MYJB_TARGET_JB_TAURINE 3
#define MYJB_TARGET_JB_CURRENT MYJB_TARGET_JB_AMETHYST

#define MYJB_KDF_INFO_PREFIX "myjb-file-v1:"

typedef struct __attribute__((packed)) {
    uint32_t min_ios;
    uint16_t target_jb;
    uint16_t flags;
    uint8_t payload_hash[32];
    uint8_t salt[32];
    uint8_t nonce[24];
    uint64_t payload_size;
    char tweak_id[MYJB_TWEAK_ID_LEN];
    char version[MYJB_VERSION_LEN];
    char filters[MYJB_MAX_FILTERS][MYJB_FILTER_LEN];
} myjb_manifest_t;

_Static_assert(sizeof(myjb_manifest_t) == MYJB_MANIFEST_SIZE, "myjb manifest size drift");

#endif /* myjb_format_h */
