#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Derive a per-device root key from a provisioning secret and public device UID.
bool derive_device_root_key(const uint8_t *master_secret, size_t master_secret_len,
                            const uint8_t *device_uid, size_t device_uid_len,
                            uint8_t out[32]);

// Derive domain-scoped signing key from device root key.
bool derive_domain_key(const uint8_t root_key[32], uint8_t domain, uint8_t out[32]);

// HMAC-SHA256 wrapper over mbedTLS.
bool hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[32]);

#endif
