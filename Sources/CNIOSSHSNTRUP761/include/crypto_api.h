/* Shim replacing openssh-portable's crypto_api.h for the vendored
 * sntrup761.c: exactly the declarations that file consumes, nothing
 * else. Upstream maps crypto_hash_sha512 to libcrypto and randombytes
 * to arc4random_buf; here both map to self-contained implementations
 * in shims.c so the target has no dependency beyond libc.
 *
 * This header is also the target's public interface: NIOSSH calls the
 * three crypto_kem_sntrup761_* entry points, and the test suite calls
 * crypto_hash_sha512 directly to pin it against FIPS 180-4 vectors.
 */
#ifndef CNIOSSH_SNTRUP761_CRYPTO_API_H
#define CNIOSSH_SNTRUP761_CRYPTO_API_H

#include "includes.h"

#include <stdint.h>
#include <stdlib.h>

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

/* Fills `buf` with cryptographically secure random bytes, or aborts:
 * key generation must never proceed on weak randomness. */
void cnio_sntrup761_randombytes(void *buf, size_t buf_len);
#define randombytes(buf, buf_len) cnio_sntrup761_randombytes((buf), (buf_len))

#define crypto_hash_sha512_BYTES 64U

int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen);

#define crypto_kem_sntrup761_PUBLICKEYBYTES 1158
#define crypto_kem_sntrup761_SECRETKEYBYTES 1763
#define crypto_kem_sntrup761_CIPHERTEXTBYTES 1039
#define crypto_kem_sntrup761_BYTES 32

int crypto_kem_sntrup761_enc(unsigned char *cstr, unsigned char *k,
    const unsigned char *pk);
int crypto_kem_sntrup761_dec(unsigned char *k,
    const unsigned char *cstr, const unsigned char *sk);
int crypto_kem_sntrup761_keypair(unsigned char *pk, unsigned char *sk);

#endif /* CNIOSSH_SNTRUP761_CRYPTO_API_H */
