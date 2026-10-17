#include "myjb_container.h"

#include "myjb_crypto.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#include <fnmatch.h>
#include <string.h>

int myjb_container_parse(const uint8_t *data, uint32_t size, const uint8_t pubkey[32],
                         myjb_container_t *out) {
    if (data == NULL || out == NULL || pubkey == NULL) return -1;
    if (size < MYJB_HEADER_SIZE + MYJB_MANIFEST_SIZE + MYJB_SIGNATURE_SIZE + MYJB_TAG_SIZE) return -1;
    if (memcmp(data, MYJB_MAGIC, 4) != 0) return -1;
    if (data[4] != MYJB_FORMAT_VERSION) return -1;
    if (data[5] != MYJB_ALGO_ID) return -1;

    uint32_t manifest_size = 0;
    memcpy(&manifest_size, data + 8, sizeof(manifest_size));
    if (manifest_size != MYJB_MANIFEST_SIZE) return -1;

    uint32_t signed_area_size = MYJB_HEADER_SIZE + manifest_size;
    const uint8_t *signature = data + signed_area_size;

    memcpy(&out->manifest, data + MYJB_HEADER_SIZE, sizeof(out->manifest));

    uint64_t expected = (uint64_t)signed_area_size + MYJB_SIGNATURE_SIZE
                      + out->manifest.payload_size + MYJB_TAG_SIZE;
    if (expected != size) return -1;

    if (crypto_ed25519_check(signature, pubkey, data, signed_area_size) != 0) return -1;

    memcpy(out->signature, signature, MYJB_SIGNATURE_SIZE);
    out->signed_area = data;
    out->signed_area_size = signed_area_size;
    out->ciphertext = data + signed_area_size + MYJB_SIGNATURE_SIZE;
    out->tag = out->ciphertext + out->manifest.payload_size;
    return 0;
}

int myjb_container_decrypt(const myjb_container_t *container, const uint8_t k_root[32],
                           uint8_t *payload_out) {
    if (container == NULL || k_root == NULL || payload_out == NULL) return -1;
    if (container->manifest.payload_size == 0) return -1;

    uint8_t key[32] = {0};
    uint8_t info[sizeof(MYJB_KDF_INFO_PREFIX) + MYJB_TWEAK_ID_LEN] = {0};
    size_t prefix_len = strlen(MYJB_KDF_INFO_PREFIX);
    memcpy(info, MYJB_KDF_INFO_PREFIX, prefix_len);
    size_t id_len = strnlen(container->manifest.tweak_id, MYJB_TWEAK_ID_LEN);
    memcpy(info + prefix_len, container->manifest.tweak_id, id_len);

    myjb_hkdf_sha256(k_root, 32,
                     container->manifest.salt, sizeof(container->manifest.salt),
                     info, prefix_len + id_len,
                     key, sizeof(key));

    int ret = crypto_aead_unlock(payload_out, container->tag, key, container->manifest.nonce,
                                 container->signed_area, container->signed_area_size,
                                 container->ciphertext, (size_t)container->manifest.payload_size);
    if (ret == 0) {
        uint8_t hash[32] = {0};
        myjb_sha256(payload_out, (size_t)container->manifest.payload_size, hash);
        if (memcmp(hash, container->manifest.payload_hash, sizeof(hash)) != 0) ret = -1;
        crypto_wipe(hash, sizeof(hash));
    }

    crypto_wipe(key, sizeof(key));
    crypto_wipe(info, sizeof(info));
    return (ret == 0) ? 0 : -1;
}

bool myjb_container_matches_process(const myjb_container_t *container, const char *exec_path) {
    if (container == NULL) return false;
    if (exec_path == NULL || exec_path[0] == '\0') return true;

    const char *base = strrchr(exec_path, '/');
    base = (base != NULL) ? base + 1 : exec_path;

    bool any_filter = false;
    for (uint32_t i = 0; i < MYJB_MAX_FILTERS; i++) {
        const char *raw = container->manifest.filters[i];
        if (raw[0] == '\0') continue;
        char filter[MYJB_FILTER_LEN + 1] = {0};
        memcpy(filter, raw, MYJB_FILTER_LEN);
        any_filter = true;
        if (fnmatch(filter, exec_path, 0) == 0) return true;
        if (fnmatch(filter, base, 0) == 0) return true;
    }
    return !any_filter;
}
