/* Support code the vendored sntrup761.c expects its host to provide.
 * In openssh-portable these live in kexsntrup761x25519.c (the
 * optblockers) and crypto_api.h (randombytes -> arc4random_buf,
 * crypto_hash_sha512 -> libcrypto). Here they are self-contained so
 * the target depends on nothing but libc, on both Darwin and Linux.
 */

#include "crypto_api.h"

#include <stdlib.h>
#include <string.h>

#if !defined(__APPLE__)
#include <unistd.h>
#endif

/* Optimisation blockers for the constant-time integer helpers in
 * sntrup761.c. Their entire purpose is to be opaque to the optimiser:
 * they must be volatile globals, defined out-of-line, and always zero.
 * openssh-portable defines the identical three in kexsntrup761x25519.c. */
volatile crypto_int16 crypto_int16_optblocker = 0;
volatile crypto_int32 crypto_int32_optblocker = 0;
volatile crypto_int64 crypto_int64_optblocker = 0;

/* On Darwin, arc4random_buf: cryptographically secure, kernel-seeded,
 * available on every Apple platform including iOS (which has no
 * <sys/random.h>), no length cap — and it is exactly what upstream's
 * crypto_api.h maps randombytes to. On Linux, getentropy: present since
 * glibc 2.25 (the swift:6.2 / Ubuntu 22.04 toolchain image ships 2.35)
 * but capped at 256 bytes per call, and sntrup761 key generation asks
 * for ~3 KB in one call, so chunk it. Failure aborts: returning
 * unrandom key material would be far worse than crashing, and
 * getentropy only fails on catastrophically misconfigured systems.
 */
void
cnio_sntrup761_randombytes(void *buf, size_t buf_len)
{
#if defined(__APPLE__)
    arc4random_buf(buf, buf_len);
#else
    unsigned char *out = buf;

    while (buf_len > 0) {
        size_t chunk = buf_len > 256 ? 256 : buf_len;
        if (getentropy(out, chunk) != 0)
            abort();
        out += chunk;
        buf_len -= chunk;
    }
#endif
}

/* SHA-512, straight from FIPS 180-4. sntrup761 uses it only on
 * KEX-sized inputs (at most ~1.2 KB), so a plain portable
 * implementation is the right trade: no libcrypto dependency, and
 * small enough to audit against the standard in one sitting. The test
 * suite pins it to the FIPS 180-4 / RFC 6234 known-answer vectors.
 */

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static inline uint64_t
rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t
load_be64(const unsigned char *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
        ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
        ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
        ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static inline void
store_be64(unsigned char *p, uint64_t v)
{
    p[0] = (unsigned char)(v >> 56);
    p[1] = (unsigned char)(v >> 48);
    p[2] = (unsigned char)(v >> 40);
    p[3] = (unsigned char)(v >> 32);
    p[4] = (unsigned char)(v >> 24);
    p[5] = (unsigned char)(v >> 16);
    p[6] = (unsigned char)(v >> 8);
    p[7] = (unsigned char)v;
}

static void
sha512_compress(uint64_t state[8], const unsigned char block[128])
{
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = load_be64(block + 8 * i);
    for (i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t temp1 = h + s1 + ch + sha512_k[i] + w[i];
        uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = s0 + maj;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
    };
    unsigned char block[128];
    unsigned long long remaining = inlen;
    int i;

    while (remaining >= 128) {
        sha512_compress(state, in);
        in += 128;
        remaining -= 128;
    }

    /* Final block(s): message tail, 0x80, zero pad, 128-bit bit length.
     * inlen is bounded far below 2^61 here, so the high word is zero. */
    memset(block, 0, sizeof(block));
    memcpy(block, in, (size_t)remaining);
    block[remaining] = 0x80;
    if (remaining >= 112) {
        sha512_compress(state, block);
        memset(block, 0, sizeof(block));
    }
    store_be64(block + 120, inlen << 3);
    sha512_compress(state, block);

    for (i = 0; i < 8; i++)
        store_be64(out + 8 * i, state[i]);

    return 0;
}
