#include "crypto.h"
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <string.h>

void secure_memzero(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) {
        *p++ = 0;
    }
}

bool hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) {
        return false;
    }
    return mbedtls_md_hmac(md, key, key_len, data, data_len, out) == 0;
}

bool derive_device_root_key(const uint8_t *master_secret, size_t master_secret_len,
                            const uint8_t *device_uid, size_t device_uid_len,
                            uint8_t out[32]) {
    static const uint8_t info[] = "rp2350-token-root-v1";
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (!md) {
        return false;
    }

    // HKDF(secret=master, salt=device_uid) gives deterministic but per-device unique keys.
    return mbedtls_hkdf(md,
                        device_uid, device_uid_len,
                        master_secret, master_secret_len,
                        info, sizeof(info) - 1,
                        out, 32) == 0;
}

bool derive_domain_key(const uint8_t root_key[32], uint8_t domain, uint8_t out[32]) {
    static const uint8_t label_prefix[] = "rp2350-token-domain:";
    uint8_t label[sizeof(label_prefix) + 1];

    memcpy(label, label_prefix, sizeof(label_prefix));
    label[sizeof(label_prefix)] = domain;
    bool ok = hmac_sha256(root_key, 32, label, sizeof(label), out);
    secure_memzero(label, sizeof(label));
    return ok;
}
