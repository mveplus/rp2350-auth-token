#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

void derive_domain_key(const uint8_t root_key[32], uint8_t domain, uint8_t out[32]);

#endif
