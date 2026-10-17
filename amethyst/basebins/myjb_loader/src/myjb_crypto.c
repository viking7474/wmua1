#include "myjb_crypto.h"

#include <CommonCrypto/CommonHMAC.h>
#include <string.h>

void myjb_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
    CC_SHA256(data, (CC_LONG)size, out);
}

void myjb_hkdf_sha256(const uint8_t *ikm, size_t ikm_size,
                      const uint8_t *salt, size_t salt_size,
                      const uint8_t *info, size_t info_size,
                      uint8_t *out, size_t out_size) {
    uint8_t prk[32] = {0};
    if (salt == NULL || salt_size == 0) {
        uint8_t zero_salt[32] = {0};
        CCHmac(kCCHmacAlgSHA256, zero_salt, sizeof(zero_salt), ikm, ikm_size, prk);
    } else {
        CCHmac(kCCHmacAlgSHA256, salt, salt_size, ikm, ikm_size, prk);
    }

    uint8_t t[32] = {0};
    size_t t_size = 0;
    size_t done = 0;
    uint8_t counter = 1;

    while (done < out_size && counter != 0) {
        CCHmacContext ctx;
        CCHmacInit(&ctx, kCCHmacAlgSHA256, prk, sizeof(prk));
        if (t_size > 0) CCHmacUpdate(&ctx, t, t_size);
        if (info != NULL && info_size > 0) CCHmacUpdate(&ctx, info, info_size);
        CCHmacUpdate(&ctx, &counter, 1);
        CCHmacFinal(&ctx, t);
        t_size = sizeof(t);

        size_t take = out_size - done;
        if (take > sizeof(t)) take = sizeof(t);
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }

    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
}
