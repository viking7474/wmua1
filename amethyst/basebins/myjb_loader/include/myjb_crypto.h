#ifndef myjb_crypto_h
#define myjb_crypto_h

#include <stddef.h>
#include <stdint.h>

void myjb_sha256(const uint8_t *data, size_t size, uint8_t out[32]);
void myjb_hkdf_sha256(const uint8_t *ikm, size_t ikm_size,
                      const uint8_t *salt, size_t salt_size,
                      const uint8_t *info, size_t info_size,
                      uint8_t *out, size_t out_size);

#endif /* myjb_crypto_h */
