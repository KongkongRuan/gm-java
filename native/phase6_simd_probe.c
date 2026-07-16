/* Phase 6 feasibility probe.
 *
 * Three measurements that bound what SIMD multi-message verification could
 * win on this machine:
 *
 * A. Dependent Montgomery mul chain (current single-message latency).
 * B. Four independent interleaved scalar Montgomery muls. A batch verify
 *    API could do this with zero new field code; the OOO engine overlaps
 *    the four carry chains, converting the latency-bound single op into a
 *    throughput-bound one. This is the headroom SIMD must beat, not A.
 * C. Raw vpmuludq (32x32->64 lane multiply) throughput. An AVX2 four-way
 *    256-bit field mul needs 64 of these plus carry-fix vector ops, so its
 *    port budget lands near B rather than near 4x A.
 *
 * Build: gcc -O3 -mbmi2 -madx -mavx2 -I<jdk>/include -I<jdk>/include/win32
 */
#include <immintrin.h>
#include <stdio.h>
#include "native_mul.c"

#if defined(_WIN32)
#include <windows.h>
static double now_seconds(void) {
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)frequency.QuadPart;
}
#else
#include <time.h>
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
#endif

static volatile uint64_t sink64;
static volatile uint64_t sink_vec[4];

int main(void) {
    const uint64_t rounds = 2000000;
    felem a0 = {UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
                UINT64_C(0x0f1e2d3c4b5a6978), UINT64_C(0x6a09e667f3bcc908)};
    felem a1 = {UINT64_C(0x1123456789abcdef), UINT64_C(0x1edcba9876543210),
                UINT64_C(0x1f1e2d3c4b5a6978), UINT64_C(0x7a09e667f3bcc908)};
    felem a2 = {UINT64_C(0x2123456789abcdef), UINT64_C(0x2edcba9876543210),
                UINT64_C(0x2f1e2d3c4b5a6978), UINT64_C(0x8a09e667f3bcc908)};
    felem a3 = {UINT64_C(0x3123456789abcdef), UINT64_C(0x3edcba9876543210),
                UINT64_C(0x3f1e2d3c4b5a6978), UINT64_C(0x9a09e667f3bcc908)};
    felem r0, r1, r2, r3;
    double start, elapsed;

    /* A: dependent chain, same pattern as benchmark_mont. */
    start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        mont_mul_bmi2_adx(a0, a0, r0);
        felem_copy(a0, r0);
    }
    elapsed = now_seconds() - start;
    sink64 ^= a0[0];
    double a_ns = elapsed * 1e9 / (double)rounds;
    printf("A dependent scalar mont_mul: %.2f ns/op\n", a_ns);

    /* B: four independent scalar muls per iteration. */
    start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        mont_mul_bmi2_adx(a0, a0, r0);
        mont_mul_bmi2_adx(a1, a1, r1);
        mont_mul_bmi2_adx(a2, a2, r2);
        mont_mul_bmi2_adx(a3, a3, r3);
        felem_copy(a0, r0);
        felem_copy(a1, r1);
        felem_copy(a2, r2);
        felem_copy(a3, r3);
    }
    elapsed = now_seconds() - start;
    sink64 ^= a0[0] ^ a1[0] ^ a2[0] ^ a3[0];
    double b_ns = elapsed * 1e9 / (double)(rounds * 4);
    printf("B 4-way interleaved scalar:  %.2f ns/msg (%.1f%% of A)\n",
           b_ns, b_ns * 100.0 / a_ns);

    /* C: raw vpmuludq throughput, 8 independent accumulators. */
    __m256i v0 = _mm256_set1_epi64x(0x0f1e2d3c4b5a6978LL);
    __m256i v1 = _mm256_set1_epi64x(0x1f1e2d3c4b5a6978LL);
    __m256i v2 = _mm256_set1_epi64x(0x2f1e2d3c4b5a6978LL);
    __m256i v3 = _mm256_set1_epi64x(0x3f1e2d3c4b5a6978LL);
    __m256i v4 = _mm256_set1_epi64x(0x4f1e2d3c4b5a6978LL);
    __m256i v5 = _mm256_set1_epi64x(0x5f1e2d3c4b5a6978LL);
    __m256i v6 = _mm256_set1_epi64x(0x6f1e2d3c4b5a6978LL);
    __m256i v7 = _mm256_set1_epi64x(0x7f1e2d3c4b5a6978LL);
    const __m256i w = _mm256_set1_epi64x(0x0123456789abcdefLL);
    start = now_seconds();
    for (uint64_t i = 0; i < rounds * 4; ++i) {
        v0 = _mm256_add_epi64(v0, _mm256_mul_epu32(v0, w));
        v1 = _mm256_add_epi64(v1, _mm256_mul_epu32(v1, w));
        v2 = _mm256_add_epi64(v2, _mm256_mul_epu32(v2, w));
        v3 = _mm256_add_epi64(v3, _mm256_mul_epu32(v3, w));
        v4 = _mm256_add_epi64(v4, _mm256_mul_epu32(v4, w));
        v5 = _mm256_add_epi64(v5, _mm256_mul_epu32(v5, w));
        v6 = _mm256_add_epi64(v6, _mm256_mul_epu32(v6, w));
        v7 = _mm256_add_epi64(v7, _mm256_mul_epu32(v7, w));
    }
    elapsed = now_seconds() - start;
    {
        __m256i x = _mm256_xor_si256(_mm256_xor_si256(v0, v1),
                                     _mm256_xor_si256(v2, v3));
        x = _mm256_xor_si256(x, _mm256_xor_si256(
                _mm256_xor_si256(v4, v5), _mm256_xor_si256(v6, v7)));
        _mm256_storeu_si256((__m256i *)sink_vec, x);
    }
    printf("C vpmuludq ymm:              %.3f ns/instr (4 lane-products each)\n",
           elapsed * 1e9 / (double)(rounds * 32));
    return 0;
}
