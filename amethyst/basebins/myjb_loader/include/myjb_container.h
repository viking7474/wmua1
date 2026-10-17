#ifndef myjb_container_h
#define myjb_container_h

#include <stdbool.h>
#include <stdint.h>

#include "myjb_format.h"

typedef struct {
    myjb_manifest_t manifest;
    uint8_t signature[MYJB_SIGNATURE_SIZE];
    const uint8_t *signed_area;
    uint32_t signed_area_size;
    const uint8_t *ciphertext;
    const uint8_t *tag;
} myjb_container_t;

int myjb_container_parse(const uint8_t *data, uint32_t size, const uint8_t pubkey[32],
                         myjb_container_t *out);
int myjb_container_decrypt(const myjb_container_t *container, const uint8_t k_root[32],
                           uint8_t *payload_out);
bool myjb_container_matches_process(const myjb_container_t *container, const char *exec_path);

#endif /* myjb_container_h */
