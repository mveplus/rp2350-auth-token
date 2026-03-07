/* Workaround for some mbedtls source files using INT_MAX without limits.h. */
#include <limits.h>

/* Embedded target: do not rely on Unix platform entropy APIs. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* Required for MBEDTLS_PLATFORM_MS_TIME_ALT. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_HAVE_TIME

/* pico_mbedtls provides mbedtls_ms_time() alternative. */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* Required by mbedTLS v3 headers. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/* Minimal algorithms needed for this token flow. */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_HKDF_C
