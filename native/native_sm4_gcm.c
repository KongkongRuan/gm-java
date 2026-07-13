/**
 * SM4-GCM native acceleration (Windows/Linux x86_64)
 *
 * 1. CLMUL/PCLMULQDQ GHASH：128-bit carry-less multiply + fast reduction.
 *    一次性 JNI 调用处理完整 GHASH 输入，避免逐块 JNI 开销。
 *
 * Build (Windows, MinGW-w64):
 *   gcc -shared -O3 -fPIC -march=x86-64 -mpclmul -msse2 -I%JDK%\include -I%JDK%\include\win32
 *       -o ../src/main/resources/native/win-x86_64/sm4gcm.dll native_sm4_gcm.c
 */

#ifdef TEST
#include <stdio.h>
#include <stdlib.h>
#define JNIEXPORT
#define JNICALL
#define JNIEnv void
#define jclass void*
#define jbyteArray void*
#define jsize size_t
#else
#include <jni.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#include <cpuid.h>
#define GM_HAS_PCLMUL 1
#else
#define GM_HAS_PCLMUL 0
#endif

/* ================================================================
 * Section 1 — GHASH multiplication in GCM byte/bit order
 *
 * GCM interprets 128-bit block X = x_0 x_1 ... x_127 as polynomial
 * X(x) = x_0*x^127 + x_1*x^126 + ... + x_127
 * where x_0 is the most significant bit of byte 0.
 *
 * Reduction polynomial: R(x) = x^128 + x^7 + x^2 + x + 1
 * ================================================================ */

/* Reflect bits within each byte. This converts between Java GHASH byte order
 * (byte MSB = x^0 coefficient) and PCLMULQDQ memory order
 * (byte LSB = x^0 coefficient). Byte order stays big-endian. */
static inline uint8_t reflect_byte(uint8_t b) {
    b = (uint8_t)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
    b = (uint8_t)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
    b = (uint8_t)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
    return b;
}

static inline void reflect128(const uint8_t in[16], uint8_t out[16]) {
    for (int i = 0; i < 16; i++) out[i] = reflect_byte(in[i]);
}

/* Reference multiplication in the reflected convention used by Java GHASH:
 * byte MSB = x^0 coefficient, byte LSB = x^7 coefficient within that byte.
 * Reduction polynomial R = x^128 + x^7 + x^2 + x + 1 => reflected constant 0xE1. */
static void ghash_mul_ref(const uint8_t X_[16], const uint8_t Y_[16], uint8_t Z[16]) {
    uint8_t V[16];
    memcpy(V, Y_, 16);
    memset(Z, 0, 16);
    for (int i = 0; i < 128; i++) {
        /* bit i corresponds to x^i coefficient; located at byte i/8, bit 7-(i%8) */
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        if ((X_[byte_idx] >> bit_idx) & 1) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }
        /* V = V * x mod R : shift right (toward higher powers) */
        uint8_t carry = V[15] & 1;  /* x^127 falls off */
        for (int j = 15; j > 0; j--) {
            V[j] = (uint8_t)((V[j] >> 1) | (V[j - 1] << 7));
        }
        V[0] >>= 1;
        if (carry) V[0] ^= 0xE1;    /* x^128 ≡ x^7 + x^2 + x + 1 */
    }
}

/* ================================================================
 * Section 2 — CLMUL GHASH (PCLMULQDQ)
 *
 * Strategy:
 *   - Reflect inputs so PCLMULQDQ native bit order matches GCM semantics.
 *   - Multiply and reduce in reflected domain.
 *   - Reflect output back to GCM byte order.
 *
 * Reflected reduction polynomial lower 128 bits:
 *   x^128 + x^7 + x^2 + x + 1  => reflected: 1 + x^121 + x^126 + x^127
 *   represented as [hi=0xC200000000000000, lo=0x0000000000000001]
 * ================================================================ */

#if GM_HAS_PCLMUL

static inline void clmul_mul_full(const __m128i a, const __m128i b,
                                  __m128i *lo_out, __m128i *hi_out) {
    __m128i t0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t1 = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x01),
                               _mm_clmulepi64_si128(a, b, 0x10));
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x11);
    *lo_out = _mm_xor_si128(t0, _mm_slli_si128(t1, 8));
    *hi_out = _mm_xor_si128(t2, _mm_srli_si128(t1, 8));
}

/* Scalar 128x128 carry-less multiply in PCLMUL convention (bit 0 = x^0). */
static void scalar_clmul_prod(const uint8_t A[16], const uint8_t B[16], uint8_t prod[32]) {
    memset(prod, 0, 32);
    for (int i = 0; i < 128; i++) {
        int ab = i / 8, abit = i % 8;
        if ((A[ab] >> abit) & 1) {
            for (int j = 0; j < 128; j++) {
                int bb = j / 8, bbit = j % 8;
                if ((B[bb] >> bbit) & 1) {
                    int p = i + j;
                    prod[p / 8] ^= (uint8_t)(1 << (p % 8));
                }
            }
        }
    }
}

/* Reduction in reflected domain by x^128 + x^7 + x^2 + x + 1.
 * Intel algorithm (reflected). Input: 256-bit [X1:X0]. Output: 128-bit. */
static inline __m128i clmul_reduce(__m128i X1, __m128i X0) {
    /* Fast SSE reduction in PCLMUL convention (bit 0 = x^0).
     * result = X0 + X1*x^128 ≡ X0 + X1*POLY where POLY = x^7+x^2+x+1.
     * X1*POLY may overflow by up to 7 bits; reduce the overflow again. */
    const __m128i POLY = _mm_set_epi64x(0x0000000000000000ULL, 0x0000000000000087ULL);

    __m128i t_lo, t_hi;
    clmul_mul_full(X1, POLY, &t_lo, &t_hi);   /* T = X1 * POLY, up to 135 bits */

    __m128i o_lo, o_hi;
    clmul_mul_full(t_hi, POLY, &o_lo, &o_hi); /* reduce overflow bits */

    __m128i res = _mm_xor_si128(_mm_xor_si128(X0, t_lo), o_lo);
    return res;
}

static void ghash_mul_clmul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) {
    uint8_t Xr[16], Yr[16];
    reflect128(X, Xr);
    reflect128(Y, Yr);

    __m128i a, b;
    memcpy(&a, Xr, 16);
    memcpy(&b, Yr, 16);

    __m128i lo, hi;
    clmul_mul_full(a, b, &lo, &hi);
    __m128i res = clmul_reduce(hi, lo);

    uint8_t Rr[16];
    memcpy(Rr, &res, 16);
    reflect128(Rr, Z);
}

#endif /* GM_HAS_PCLMUL */

/* ================================================================
 * Section 3 — GHASH block / bytes
 * ================================================================ */

static inline void ghash_step(uint8_t Y[16], const uint8_t X[16], const uint8_t H[16]) {
    uint8_t T[16];
    for (int i = 0; i < 16; i++) T[i] = Y[i] ^ X[i];
#if GM_HAS_PCLMUL
    ghash_mul_clmul(T, H, Y);
#else
    ghash_mul_ref(T, H, Y);
#endif
}

static void ghash_bytes(const uint8_t *in, size_t len, const uint8_t H[16], uint8_t out[16]) {
    memset(out, 0, 16);
    for (size_t i = 0; i < len; i += 16) {
        ghash_step(out, in + i, H);
    }
}

/* ================================================================
 * Section 4 — Standalone verification harness (compile with -DTEST)
 * ================================================================ */
#ifdef TEST
static int test_mul(void) {
    int failures = 0;
    uint8_t X[16], Y[16], Zref[16], Zclmul[16];
    unsigned int seed = 12345;
    int t;
    /* First simple case: X = 1 (byte 0 MSB = x^0), Y = 1 */
    memset(X, 0, 16); X[0] = 0x80;
    memset(Y, 0, 16); Y[0] = 0x80;
    ghash_mul_ref(X, Y, Zref);
    ghash_mul_clmul(X, Y, Zclmul);
    if (memcmp(Zref, Zclmul, 16) != 0) {
        printf("CLMUL mismatch simple case\n");
        for (int k = 0; k < 16; k++) printf("%02x", Zref[k]); printf(" (ref)\n");
        for (int k = 0; k < 16; k++) printf("%02x", Zclmul[k]); printf(" (clmul)\n");
        failures++;
    }

    for (t = 0; t < 10000; t++) {
        for (int i = 0; i < 16; i++) {
            seed = seed * 1103515245 + 12345;
            X[i] = (uint8_t)(seed >> 16);
            seed = seed * 1103515245 + 12345;
            Y[i] = (uint8_t)(seed >> 16);
        }
        ghash_mul_ref(X, Y, Zref);
#if GM_HAS_PCLMUL
        ghash_mul_clmul(X, Y, Zclmul);
        if (memcmp(Zref, Zclmul, 16) != 0) {
            printf("CLMUL mismatch at test %d\n", t);
            for (int k = 0; k < 16; k++) printf("%02x", X[k]); printf(" *\n");
            for (int k = 0; k < 16; k++) printf("%02x", Y[k]); printf(" =\n");
            for (int k = 0; k < 16; k++) printf("%02x", Zref[k]); printf(" (ref)\n");
            for (int k = 0; k < 16; k++) printf("%02x", Zclmul[k]); printf(" (clmul)\n");
            failures++;
            if (failures > 5) break;
        }
#endif
    }
    if (failures == 0) printf("All %d multiplication tests passed.\n", t);
    return failures;
}

static int test_prod(void) {
    int failures = 0;
    uint8_t A[16], B[16], prod_scalar[32];
    unsigned int seed = 54321;
    for (int t = 0; t < 1000; t++) {
        for (int i = 0; i < 16; i++) {
            seed = seed * 1103515245 + 12345;
            A[i] = (uint8_t)(seed >> 16);
            seed = seed * 1103515245 + 12345;
            B[i] = (uint8_t)(seed >> 16);
        }
        scalar_clmul_prod(A, B, prod_scalar);
        __m128i a, b;
        memcpy(&a, A, 16);
        memcpy(&b, B, 16);
        __m128i lo, hi;
        clmul_mul_full(a, b, &lo, &hi);
        uint8_t prod_clmul[32];
        memcpy(prod_clmul, &lo, 16);
        memcpy(prod_clmul + 16, &hi, 16);
        if (memcmp(prod_scalar, prod_clmul, 32) != 0) {
            printf("Product mismatch at %d\n", t);
            failures++;
            if (failures > 5) break;
        }
    }
    if (failures == 0) printf("All 1000 product tests passed.\n");
    return failures;
}

int main(void) {
    int f = test_prod();
    f += test_mul();
    return f;
}
#endif

/* ================================================================
 * Section 5 — SM4 core (T-table)
 * ================================================================ */

static const uint32_t SM4_FK[4] = { 0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu };
static const uint32_t SM4_CK[32] = {
    0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
    0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
    0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
    0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
    0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
    0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
    0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
    0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u
};

#include "sm4_t_tables.c"

static inline uint32_t sm4_t(uint32_t A) {
    return SM4_T0[(A >> 24) & 0xFF] ^ SM4_T1[(A >> 16) & 0xFF]
         ^ SM4_T2[(A >> 8)  & 0xFF] ^ SM4_T3[A & 0xFF];
}

static inline uint32_t sm4_tprime(uint32_t A) {
    uint32_t s0 = SM4_SBOX[(A >> 24) & 0xFF];
    uint32_t s1 = SM4_SBOX[(A >> 16) & 0xFF];
    uint32_t s2 = SM4_SBOX[(A >> 8)  & 0xFF];
    uint32_t s3 = SM4_SBOX[A & 0xFF];
    uint32_t B = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3;
    return B ^ ((B << 13) | (B >> 19)) ^ ((B << 23) | (B >> 9));
}

static inline uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8)
         | ((v & 0x0000FF00u) << 8)  | ((v & 0x000000FFu) << 24);
}

static void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];
    K[0] = bswap32(*(uint32_t *)(key + 0)) ^ SM4_FK[0];
    K[1] = bswap32(*(uint32_t *)(key + 4)) ^ SM4_FK[1];
    K[2] = bswap32(*(uint32_t *)(key + 8)) ^ SM4_FK[2];
    K[3] = bswap32(*(uint32_t *)(key + 12)) ^ SM4_FK[3];
    for (int i = 0; i < 32; i++) {
        K[i + 4] = K[i] ^ sm4_tprime(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ (uint32_t)SM4_CK[i]);
        rk[i] = K[i + 4];
    }
}

static void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[36];
    X[0] = bswap32(*(uint32_t *)(in + 0));
    X[1] = bswap32(*(uint32_t *)(in + 4));
    X[2] = bswap32(*(uint32_t *)(in + 8));
    X[3] = bswap32(*(uint32_t *)(in + 12));
    for (int i = 0; i < 32; i++) {
        X[i + 4] = X[i] ^ sm4_t(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    }
    *(uint32_t *)(out + 0)  = bswap32(X[35]);
    *(uint32_t *)(out + 4)  = bswap32(X[34]);
    *(uint32_t *)(out + 8)  = bswap32(X[33]);
    *(uint32_t *)(out + 12) = bswap32(X[32]);
}

static void sm4_ctr(const uint8_t *in, uint8_t *out, size_t len,
                    const uint8_t iv[16], const uint32_t rk[32]) {
    uint8_t counter[16];
    memcpy(counter, iv, 16);
    size_t off = 0;
    while (off < len) {
        uint8_t ks[16];
        sm4_encrypt_block(counter, ks, rk);
        size_t chunk = len - off;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++) out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
        /* increment big-endian counter */
        for (int i = 15; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
        off += chunk;
    }
}

/* ================================================================
 * Section 6 — Full SM4-GCM in C
 * ================================================================ */

static void gcm_compute_j0(const uint8_t *iv, size_t iv_len, const uint32_t rk[32], uint8_t J0[16]) {
    if (iv_len == 12) {
        memcpy(J0, iv, 12);
        J0[12] = J0[13] = J0[14] = 0;
        J0[15] = 1;
    } else {
        size_t s = (16 - (iv_len % 16)) % 16;
        size_t total = iv_len + s + 8;
        uint8_t *buf = (uint8_t *)calloc(total, 1);
        memcpy(buf, iv, iv_len);
        uint64_t len_bits = (uint64_t)iv_len * 8;
        for (int i = 0; i < 8; i++) buf[total - 1 - i] = (uint8_t)(len_bits >> (8 * i));
        uint8_t H[16];
        uint8_t zero[16] = {0};
        sm4_encrypt_block(zero, H, rk);
        ghash_bytes(buf, total, H, J0);
        free(buf);
    }
}

static void sm4_gcm_encrypt(const uint8_t *pt, uint8_t *ct, size_t len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t key[16], const uint8_t iv[16], size_t iv_len,
                            uint8_t tag[16]) {
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    uint8_t H[16], J0[16];
    uint8_t zero[16] = {0};
    sm4_encrypt_block(zero, H, rk);
    gcm_compute_j0(iv, iv_len, rk, J0);

    uint8_t incJ0[16];
    memcpy(incJ0, J0, 16);
    for (int i = 15; i >= 0; i--) {
        if (++incJ0[i] != 0) break;
    }
    sm4_ctr(pt, ct, len, incJ0, rk);

    size_t ceil_c = (len + 15) / 16;
    size_t ceil_a = (aad_len + 15) / 16;
    size_t u = ceil_c * 16 - len;
    size_t v = ceil_a * 16 - aad_len;
    size_t ghash_len = ceil_a * 16 + v + ceil_c * 16 + u + 16;
    uint8_t *ghash_in = (uint8_t *)calloc(ghash_len, 1);
    size_t pos = 0;
    memcpy(ghash_in + pos, aad, aad_len); pos += ceil_a * 16;
    pos += v;
    memcpy(ghash_in + pos, ct, len); pos += ceil_c * 16;
    pos += u;
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t c_bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) ghash_in[pos + 7 - i] = (uint8_t)(aad_bits >> (8 * i));
    for (int i = 0; i < 8; i++) ghash_in[pos + 15 - i] = (uint8_t)(c_bits >> (8 * i));

    uint8_t S[16];
    ghash_bytes(ghash_in, ghash_len, H, S);
    free(ghash_in);

    uint8_t encS[16];
    sm4_encrypt_block(J0, encS, rk);
    for (int i = 0; i < 16; i++) tag[i] = encS[i] ^ S[i];
}

/* ================================================================
 * Section 7 — JNI wrappers
 * ================================================================ */
#ifndef TEST

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_SM4GCMNative_ghash(
    JNIEnv *env, jclass clz, jbyteArray inArr, jbyteArray HArr, jbyteArray outArr) {
    jsize len = (*env)->GetArrayLength(env, inArr);
    uint8_t *in = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, inArr, NULL);
    uint8_t H[16], out[16];
    (*env)->GetByteArrayRegion(env, HArr, 0, 16, (jbyte *)H);
    ghash_bytes(in, (size_t)len, H, out);
    (*env)->ReleasePrimitiveArrayCritical(env, inArr, in, JNI_ABORT);
    (*env)->SetByteArrayRegion(env, outArr, 0, 16, (jbyte *)out);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_SM4GCMNative_gcmEncrypt(
    JNIEnv *env, jclass clz,
    jbyteArray keyArr, jbyteArray ivArr,
    jbyteArray aadArr, jint aadLen,
    jbyteArray ptArr, jint ptLen,
    jbyteArray ctArr, jbyteArray tagArr) {
    uint8_t key[16], tag[16];
    (*env)->GetByteArrayRegion(env, keyArr, 0, 16, (jbyte *)key);

    jsize ivLen = (*env)->GetArrayLength(env, ivArr);
    uint8_t *iv = (uint8_t *)malloc((size_t)ivLen);
    (*env)->GetByteArrayRegion(env, ivArr, 0, ivLen, (jbyte *)iv);

    uint8_t *aad = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, aadArr, NULL);
    uint8_t *pt = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, ptArr, NULL);
    uint8_t *ct = (uint8_t *)(*env)->GetPrimitiveArrayCritical(env, ctArr, NULL);

    sm4_gcm_encrypt(pt, ct, (size_t)ptLen, aad, (size_t)aadLen, key, iv, (size_t)ivLen, tag);

    free(iv);
    (*env)->ReleasePrimitiveArrayCritical(env, aadArr, aad, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, ptArr, pt, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, ctArr, ct, 0);
    (*env)->SetByteArrayRegion(env, tagArr, 0, 16, (jbyte *)tag);
}

#endif /* !TEST */
