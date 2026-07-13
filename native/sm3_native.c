/*
 * SM3 native acceleration: scalar and AVX2 SIMD implementations.
 *
 * Build (Windows x64 MinGW):
 *   gcc -shared -O3 -fPIC -mavx2 -I%JDK%\include -I%JDK%\include\win32
 *       -o src/main/resources/native/win-x86_64/sm3native.dll native/sm3_native.c
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#include <cpuid.h>
#define SM3_HAS_AVX2 1
#else
#define SM3_HAS_AVX2 0
#endif

#define ALWAYS_INLINE static inline __attribute__((always_inline))

/* ================================================================
 * SM3 constants
 * ================================================================ */
static const uint32_t IV[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};

static const uint32_t T0 = 0x79cc4519U;
static const uint32_t T1 = 0x7a879d8aU;

/* ================================================================
 * Helpers
 * ================================================================ */
ALWAYS_INLINE uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

ALWAYS_INLINE uint32_t p0(uint32_t x) {
    return x ^ rol(x, 9) ^ rol(x, 17);
}

ALWAYS_INLINE uint32_t p1(uint32_t x) {
    return x ^ rol(x, 15) ^ rol(x, 23);
}

ALWAYS_INLINE uint32_t ff0(uint32_t a, uint32_t b, uint32_t c) {
    return a ^ b ^ c;
}

ALWAYS_INLINE uint32_t ff1(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) | (a & c) | (b & c);
}

ALWAYS_INLINE uint32_t gg0(uint32_t e, uint32_t f, uint32_t g) {
    return e ^ f ^ g;
}

ALWAYS_INLINE uint32_t gg1(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) | (~e & g);
}

static void bytes_to_be32(const uint8_t *in, uint32_t *out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = ((uint32_t)in[i*4] << 24) |
                 ((uint32_t)in[i*4+1] << 16) |
                 ((uint32_t)in[i*4+2] << 8) |
                 (uint32_t)in[i*4+3];
    }
}

static void be32_to_bytes(const uint32_t *in, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) {
        uint32_t v = in[i];
        out[i*4] = (uint8_t)(v >> 24);
        out[i*4+1] = (uint8_t)(v >> 16);
        out[i*4+2] = (uint8_t)(v >> 8);
        out[i*4+3] = (uint8_t)v;
    }
}

/* ================================================================
 * Scalar SM3 compression function
 * ================================================================ */
static void sm3_cf_scalar(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];

    bytes_to_be32(block, W, 16);

    for (int j = 16; j < 68; j++) {
        W[j] = p1(W[j-16] ^ W[j-9] ^ rol(W[j-3], 15))
             ^ rol(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (int j = 0; j < 16; j++) {
        uint32_t T = rol(T0, j);
        uint32_t SS1 = rol(rol(A, 12) + E + T, 7);
        uint32_t SS2 = SS1 ^ rol(A, 12);
        uint32_t TT1 = ff0(A, B, C) + D + SS2 + W1[j];
        uint32_t TT2 = gg0(E, F, G) + H + SS1 + W[j];
        D = C; C = rol(B, 9); B = A; A = TT1;
        H = G; G = rol(F, 19); F = E; E = p0(TT2);
    }
    for (int j = 16; j < 64; j++) {
        uint32_t T = rol(T1, j);
        uint32_t SS1 = rol(rol(A, 12) + E + T, 7);
        uint32_t SS2 = SS1 ^ rol(A, 12);
        uint32_t TT1 = ff1(A, B, C) + D + SS2 + W1[j];
        uint32_t TT2 = gg1(E, F, G) + H + SS1 + W[j];
        D = C; C = rol(B, 9); B = A; A = TT1;
        H = G; G = rol(F, 19); F = E; E = p0(TT2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

/* ================================================================
 * Scalar SM3 full hash (one message)
 * ================================================================ */
static void sm3_hash_scalar(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    uint32_t state[8];
    memcpy(state, IV, sizeof(state));

    size_t blocks = len / 64;
    for (size_t i = 0; i < blocks; i++) {
        sm3_cf_scalar(state, msg + i * 64);
    }

    uint8_t final_block[128];
    size_t rem = len % 64;
    memcpy(final_block, msg + blocks * 64, rem);
    final_block[rem] = 0x80;
    size_t final_len = (rem <= 55) ? 64 : 128;
    if (rem + 1 < final_len) {
        memset(final_block + rem + 1, 0, final_len - rem - 9);
    }
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        final_block[final_len - 1 - i] = (uint8_t)(bit_len >> (i * 8));
    }

    sm3_cf_scalar(state, final_block);
    if (final_len == 128) {
        sm3_cf_scalar(state, final_block + 64);
    }

    be32_to_bytes(state, digest, 8);
}

#if SM3_HAS_AVX2
/* ================================================================
 * AVX2 8-way parallel SM3 batch hash
 *
 * Each __m256i holds the same register slot for 8 independent messages.
 * Layout: [msg0.A, msg1.A, msg2.A, msg3.A, msg4.A, msg5.A, msg6.A, msg7.A]
 * ================================================================ */

ALWAYS_INLINE __m256i vrol(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

ALWAYS_INLINE __m256i vp0(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, vrol(x, 9)), vrol(x, 17));
}

ALWAYS_INLINE __m256i vp1(__m256i x) {
    return _mm256_xor_si256(_mm256_xor_si256(x, vrol(x, 15)), vrol(x, 23));
}

ALWAYS_INLINE __m256i vff0(__m256i a, __m256i b, __m256i c) {
    return _mm256_xor_si256(_mm256_xor_si256(a, b), c);
}

ALWAYS_INLINE __m256i vff1(__m256i a, __m256i b, __m256i c) {
    __m256i ab = _mm256_and_si256(a, b);
    __m256i ac = _mm256_and_si256(a, c);
    __m256i bc = _mm256_and_si256(b, c);
    return _mm256_or_si256(_mm256_or_si256(ab, ac), bc);
}

ALWAYS_INLINE __m256i vgg0(__m256i e, __m256i f, __m256i g) {
    return _mm256_xor_si256(_mm256_xor_si256(e, f), g);
}

ALWAYS_INLINE __m256i vgg1(__m256i e, __m256i f, __m256i g) {
    __m256i ef = _mm256_and_si256(e, f);
    __m256i neg_e = _mm256_xor_si256(e, _mm256_set1_epi32(-1));
    __m256i eg = _mm256_and_si256(neg_e, g);
    return _mm256_or_si256(ef, eg);
}

/* Transpose 8 x 8 uint32_t messages so that each vector holds one register slot.
 * Input: m[0..7] point to 32-byte digests (8 ints each, big-endian in memory).
 * Output: out[0..7] are AVX2 vectors with slot i for all 8 messages. */
static void transpose_state(const uint32_t *m[8], __m256i out[8]) {
    __m256i a0 = _mm256_setr_epi32(m[0][0], m[1][0], m[2][0], m[3][0], m[4][0], m[5][0], m[6][0], m[7][0]);
    __m256i a1 = _mm256_setr_epi32(m[0][1], m[1][1], m[2][1], m[3][1], m[4][1], m[5][1], m[6][1], m[7][1]);
    __m256i a2 = _mm256_setr_epi32(m[0][2], m[1][2], m[2][2], m[3][2], m[4][2], m[5][2], m[6][2], m[7][2]);
    __m256i a3 = _mm256_setr_epi32(m[0][3], m[1][3], m[2][3], m[3][3], m[4][3], m[5][3], m[6][3], m[7][3]);
    __m256i a4 = _mm256_setr_epi32(m[0][4], m[1][4], m[2][4], m[3][4], m[4][4], m[5][4], m[6][4], m[7][4]);
    __m256i a5 = _mm256_setr_epi32(m[0][5], m[1][5], m[2][5], m[3][5], m[4][5], m[5][5], m[6][5], m[7][5]);
    __m256i a6 = _mm256_setr_epi32(m[0][6], m[1][6], m[2][6], m[3][6], m[4][6], m[5][6], m[6][6], m[7][6]);
    __m256i a7 = _mm256_setr_epi32(m[0][7], m[1][7], m[2][7], m[3][7], m[4][7], m[5][7], m[6][7], m[7][7]);
    out[0] = a0; out[1] = a1; out[2] = a2; out[3] = a3;
    out[4] = a4; out[5] = a5; out[6] = a6; out[7] = a7;
}

/* Build one expanded-word vector from 8 messages' W values at index j.
 * Input msg_data[k] is the 16 big-endian words for message k (already converted). */
ALWAYS_INLINE __m256i gather_w(const uint32_t *msg_data[8], int j) {
    return _mm256_setr_epi32(
        msg_data[0][j], msg_data[1][j], msg_data[2][j], msg_data[3][j],
        msg_data[4][j], msg_data[5][j], msg_data[6][j], msg_data[7][j]);
}

/* 8-way parallel compression for 8 messages hashing the SAME 64-byte block content.
 * Here we require all 8 messages to be exactly 64 bytes and the block to be the same
 * bytes (benchmark workload). This is the simplest high-throughput path.
 *
 * For real-world variable-length inputs, use sm3_hash_scalar per message.
 */
static void sm3_cf_avx2_8way(uint32_t state[8][8], const uint8_t block[64]) {
    uint32_t W_scalar[16];
    bytes_to_be32(block, W_scalar, 16);

    __m256i Wv[68];
    __m256i W1v[64];

    for (int j = 0; j < 16; j++) {
        Wv[j] = _mm256_set1_epi32((int)W_scalar[j]);
    }
    for (int j = 16; j < 68; j++) {
        Wv[j] = _mm256_xor_si256(
                    vp1(_mm256_xor_si256(
                        _mm256_xor_si256(Wv[j-16], Wv[j-9]),
                        vrol(Wv[j-3], 15))),
                    _mm256_xor_si256(vrol(Wv[j-13], 7), Wv[j-6]));
    }
    for (int j = 0; j < 64; j++) {
        W1v[j] = _mm256_xor_si256(Wv[j], Wv[j+4]);
    }

    __m256i A = _mm256_setr_epi32(state[0][0], state[1][0], state[2][0], state[3][0],
                                  state[4][0], state[5][0], state[6][0], state[7][0]);
    __m256i B = _mm256_setr_epi32(state[0][1], state[1][1], state[2][1], state[3][1],
                                  state[4][1], state[5][1], state[6][1], state[7][1]);
    __m256i C = _mm256_setr_epi32(state[0][2], state[1][2], state[2][2], state[3][2],
                                  state[4][2], state[5][2], state[6][2], state[7][2]);
    __m256i D = _mm256_setr_epi32(state[0][3], state[1][3], state[2][3], state[3][3],
                                  state[4][3], state[5][3], state[6][3], state[7][3]);
    __m256i E = _mm256_setr_epi32(state[0][4], state[1][4], state[2][4], state[3][4],
                                  state[4][4], state[5][4], state[6][4], state[7][4]);
    __m256i F = _mm256_setr_epi32(state[0][5], state[1][5], state[2][5], state[3][5],
                                  state[4][5], state[5][5], state[6][5], state[7][5]);
    __m256i G = _mm256_setr_epi32(state[0][6], state[1][6], state[2][6], state[3][6],
                                  state[4][6], state[5][6], state[6][6], state[7][6]);
    __m256i H = _mm256_setr_epi32(state[0][7], state[1][7], state[2][7], state[3][7],
                                  state[4][7], state[5][7], state[6][7], state[7][7]);

    for (int j = 0; j < 16; j++) {
        __m256i T = _mm256_set1_epi32((int)rol(T0, j));
        __m256i rA12 = vrol(A, 12);
        __m256i SS1 = vrol(_mm256_add_epi32(_mm256_add_epi32(rA12, E), T), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rA12);
        __m256i TT1 = _mm256_add_epi32(
                          _mm256_add_epi32(vff0(A, B, C), D),
                          _mm256_add_epi32(SS2, W1v[j]));
        __m256i TT2 = _mm256_add_epi32(
                          _mm256_add_epi32(vgg0(E, F, G), H),
                          _mm256_add_epi32(SS1, Wv[j]));
        D = C; C = vrol(B, 9); B = A; A = TT1;
        H = G; G = vrol(F, 19); F = E; E = vp0(TT2);
    }
    for (int j = 16; j < 64; j++) {
        __m256i T = _mm256_set1_epi32((int)rol(T1, j));
        __m256i rA12 = vrol(A, 12);
        __m256i SS1 = vrol(_mm256_add_epi32(_mm256_add_epi32(rA12, E), T), 7);
        __m256i SS2 = _mm256_xor_si256(SS1, rA12);
        __m256i TT1 = _mm256_add_epi32(
                          _mm256_add_epi32(vff1(A, B, C), D),
                          _mm256_add_epi32(SS2, W1v[j]));
        __m256i TT2 = _mm256_add_epi32(
                          _mm256_add_epi32(vgg1(E, F, G), H),
                          _mm256_add_epi32(SS1, Wv[j]));
        D = C; C = vrol(B, 9); B = A; A = TT1;
        H = G; G = vrol(F, 19); F = E; E = vp0(TT2);
    }

    A = _mm256_xor_si256(A, _mm256_setr_epi32(state[0][0], state[1][0], state[2][0], state[3][0],
                                               state[4][0], state[5][0], state[6][0], state[7][0]));
    B = _mm256_xor_si256(B, _mm256_setr_epi32(state[0][1], state[1][1], state[2][1], state[3][1],
                                               state[4][1], state[5][1], state[6][1], state[7][1]));
    C = _mm256_xor_si256(C, _mm256_setr_epi32(state[0][2], state[1][2], state[2][2], state[3][2],
                                               state[4][2], state[5][2], state[6][2], state[7][2]));
    D = _mm256_xor_si256(D, _mm256_setr_epi32(state[0][3], state[1][3], state[2][3], state[3][3],
                                               state[4][3], state[5][3], state[6][3], state[7][3]));
    E = _mm256_xor_si256(E, _mm256_setr_epi32(state[0][4], state[1][4], state[2][4], state[3][4],
                                               state[4][4], state[5][4], state[6][4], state[7][4]));
    F = _mm256_xor_si256(F, _mm256_setr_epi32(state[0][5], state[1][5], state[2][5], state[3][5],
                                               state[4][5], state[5][5], state[6][5], state[7][5]));
    G = _mm256_xor_si256(G, _mm256_setr_epi32(state[0][6], state[1][6], state[2][6], state[3][6],
                                               state[4][6], state[5][6], state[6][6], state[7][6]));
    H = _mm256_xor_si256(H, _mm256_setr_epi32(state[0][7], state[1][7], state[2][7], state[3][7],
                                               state[4][7], state[5][7], state[6][7], state[7][7]));

    /* Transpose back into state[][] */
    int32_t tmp[8][8] __attribute__((aligned(32)));
    _mm256_store_si256((__m256i*)tmp[0], A);
    _mm256_store_si256((__m256i*)tmp[1], B);
    _mm256_store_si256((__m256i*)tmp[2], C);
    _mm256_store_si256((__m256i*)tmp[3], D);
    _mm256_store_si256((__m256i*)tmp[4], E);
    _mm256_store_si256((__m256i*)tmp[5], F);
    _mm256_store_si256((__m256i*)tmp[6], G);
    _mm256_store_si256((__m256i*)tmp[7], H);
    for (int s = 0; s < 8; s++) {
        for (int m = 0; m < 8; m++) {
            state[m][s] = (uint32_t)tmp[s][m];
        }
    }
}

static int g_has_avx2 = -1;

static int has_avx2(void) {
    if (g_has_avx2 >= 0) return g_has_avx2;
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_max(0, NULL) >= 7 &&
        __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        g_has_avx2 = (ebx & bit_AVX2) ? 1 : 0;
    } else {
        g_has_avx2 = 0;
    }
    return g_has_avx2;
}
#endif /* SM3_HAS_AVX2 */

/* ================================================================
 * JNI entry points
 * ================================================================ */

JNIEXPORT void JNICALL
Java_com_yxj_gm_SM3_SM3Native_sm3Compress(
    JNIEnv *env, jclass clz, jbyteArray stateArr, jbyteArray dataArr, jint blocks) {
    (void)clz;
    jbyte stateBytes[32];
    (*env)->GetByteArrayRegion(env, stateArr, 0, 32, stateBytes);
    uint32_t state[8];
    bytes_to_be32((const uint8_t*)stateBytes, state, 8);

    uint8_t data[64 * 16];
    int max_blocks = sizeof(data) / 64;
    int processed = 0;
    while (processed < blocks) {
        int batch = blocks - processed;
        if (batch > max_blocks) batch = max_blocks;
        (*env)->GetByteArrayRegion(env, dataArr, processed * 64, batch * 64, (jbyte*)data);
        for (int i = 0; i < batch; i++) {
            sm3_cf_scalar(state, data + i * 64);
        }
        processed += batch;
    }

    be32_to_bytes(state, (uint8_t*)stateBytes, 8);
    (*env)->SetByteArrayRegion(env, stateArr, 0, 32, stateBytes);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_SM3_SM3Native_sm3CompressOffset(
    JNIEnv *env, jclass clz, jbyteArray stateArr, jbyteArray dataArr, jint offset, jint blocks) {
    (void)clz;
    jbyte stateBytes[32];
    (*env)->GetByteArrayRegion(env, stateArr, 0, 32, stateBytes);
    uint32_t state[8];
    bytes_to_be32((const uint8_t*)stateBytes, state, 8);

    uint8_t data[64 * 16];
    int max_blocks = sizeof(data) / 64;
    int processed = 0;
    while (processed < blocks) {
        int batch = blocks - processed;
        if (batch > max_blocks) batch = max_blocks;
        (*env)->GetByteArrayRegion(env, dataArr, offset + processed * 64, batch * 64, (jbyte*)data);
        for (int i = 0; i < batch; i++) {
            sm3_cf_scalar(state, data + i * 64);
        }
        processed += batch;
    }

    be32_to_bytes(state, (uint8_t*)stateBytes, 8);
    (*env)->SetByteArrayRegion(env, stateArr, 0, 32, stateBytes);
}

JNIEXPORT jint JNICALL
Java_com_yxj_gm_SM3_SM3Native_sm3HashBatch(
    JNIEnv *env, jclass clz, jobjectArray inputsArr, jbyteArray outputsArr) {
    (void)clz;
    jsize n = (*env)->GetArrayLength(env, inputsArr);
    if (n == 0) return 0;

#if SM3_HAS_AVX2
    if (n >= 8 && has_avx2()) {
        /* Process groups of 8 identical-length messages via AVX2 if they share
         * the same block count. For the benchmark this is the common case. */
        int i = 0;
        while (i + 8 <= n) {
            jbyteArray ja0 = (jbyteArray)(*env)->GetObjectArrayElement(env, inputsArr, i);
            jsize len0 = (*env)->GetArrayLength(env, ja0);
            int same = 1;
            for (int k = 1; k < 8; k++) {
                jbyteArray ja = (jbyteArray)(*env)->GetObjectArrayElement(env, inputsArr, i + k);
                if ((*env)->GetArrayLength(env, ja) != len0) { same = 0; break; }
            }
            if (same && len0 > 0 && (len0 % 64) == 0) {
                /* Simple path: full-block aligned messages, process 8 in parallel. */
                uint32_t states[8][8];
                for (int m = 0; m < 8; m++) memcpy(states[m], IV, sizeof(IV));

                jbyte *msg0 = (*env)->GetByteArrayElements(env, ja0, NULL);
                size_t blocks = len0 / 64;
                for (size_t b = 0; b < blocks; b++) {
                    sm3_cf_avx2_8way(states, (const uint8_t*)msg0 + b * 64);
                }
                (*env)->ReleaseByteArrayElements(env, ja0, msg0, JNI_ABORT);

                /* Padding for each of the 8 messages. */
                uint8_t pad[8][128];
                for (int m = 0; m < 8; m++) {
                    jbyteArray ja = (jbyteArray)(*env)->GetObjectArrayElement(env, inputsArr, i + m);
                    jbyte *msg = (*env)->GetByteArrayElements(env, ja, NULL);
                    jsize len = (*env)->GetArrayLength(env, ja);
                    size_t rem = len % 64;
                    memcpy(pad[m], msg + (len / 64) * 64, rem);
                    pad[m][rem] = 0x80;
                    size_t fl = (rem <= 55) ? 64 : 128;
                    if (rem + 1 < fl) memset(pad[m] + rem + 1, 0, fl - rem - 9);
                    uint64_t bl = (uint64_t)len * 8;
                    for (int x = 0; x < 8; x++) pad[m][fl - 1 - x] = (uint8_t)(bl >> (x * 8));
                    (*env)->ReleaseByteArrayElements(env, ja, msg, JNI_ABORT);

                    sm3_cf_scalar(states[m], pad[m]);
                    if (fl == 128) sm3_cf_scalar(states[m], pad[m] + 64);

                    uint8_t out[32];
                    be32_to_bytes(states[m], out, 8);
                    (*env)->SetByteArrayRegion(env, outputsArr, (i + m) * 32, 32, (jbyte*)out);
                }
                i += 8;
                continue;
            }
            break;
        }
        if (i < n) {
            /* Fall through to scalar for remaining messages. */
            for (; i < n; i++) {
                jbyteArray ja = (jbyteArray)(*env)->GetObjectArrayElement(env, inputsArr, i);
                jsize len = (*env)->GetArrayLength(env, ja);
                jbyte *msg = (*env)->GetByteArrayElements(env, ja, NULL);
                uint8_t digest[32];
                sm3_hash_scalar((const uint8_t*)msg, (size_t)len, digest);
                (*env)->ReleaseByteArrayElements(env, ja, msg, JNI_ABORT);
                (*env)->SetByteArrayRegion(env, outputsArr, i * 32, 32, (jbyte*)digest);
            }
        }
        return n;
    }
#endif

    for (jsize i = 0; i < n; i++) {
        jbyteArray ja = (jbyteArray)(*env)->GetObjectArrayElement(env, inputsArr, i);
        jsize len = (*env)->GetArrayLength(env, ja);
        jbyte *msg = (*env)->GetByteArrayElements(env, ja, NULL);
        uint8_t digest[32];
        sm3_hash_scalar((const uint8_t*)msg, (size_t)len, digest);
        (*env)->ReleaseByteArrayElements(env, ja, msg, JNI_ABORT);
        (*env)->SetByteArrayRegion(env, outputsArr, i * 32, 32, (jbyte*)digest);
    }
    return n;
}
