#include <inttypes.h>
#include <stdio.h>
#include <time.h>

/* Keep the test in the same translation unit so it can exercise each
 * runtime-dispatch candidate directly without adding test-only JNI APIs. */
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
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}
#endif

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t next_random(void) {
    uint64_t x = rng_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng_state = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

static int felem_compare(const felem a, const felem b) {
    for (int i = 3; i >= 0; --i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void canonicalize(felem a) {
    if (felem_compare(a, P64) >= 0) {
        uint64_t borrow = 0;
        for (int i = 0; i < 4; ++i) {
            uint64_t pi = P64[i];
            uint64_t t = pi + borrow;
            uint64_t carry = t < pi;
            uint64_t next = a[i] < t;
            a[i] -= t;
            borrow = carry | next;
        }
    }
}

static void random_felem(felem a) {
    for (int i = 0; i < 4; ++i) a[i] = next_random();
    canonicalize(a);
}

static void print_felem(const char *label, const felem a) {
    printf("%s=%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n",
           label, a[3], a[2], a[1], a[0]);
}

#if GM_HAS_X86_RUNTIME_DISPATCH && HAS_INT128
static int cpu_has_bmi2_adx(void) {
    unsigned int eax, ebx, ecx, edx;
    return __get_cpuid_max(0, NULL) >= 7 &&
           __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) &&
           (ebx & bit_BMI2) != 0 && (ebx & bit_ADX) != 0;
}

static int check_pair(const felem a, const felem b, uint64_t index) {
    felem expected, actual, alias_a, alias_b;
    mont_mul_generic(a, b, expected);
    const felem_mul_impl candidates[] = {mont_mul_bmi2, mont_mul_bmi2_adx};
    const char *names[] = {"bmi2", "bmi2_adx"};
    for (size_t i = 0; i < 2; ++i) {
        candidates[i](a, b, actual);
        if (memcmp(expected, actual, sizeof(felem)) != 0) {
            printf("FAIL: Montgomery %s mismatch at case %" PRIu64 "\n",
                   names[i], index);
            print_felem("a", a);
            print_felem("b", b);
            print_felem("generic", expected);
            print_felem(names[i], actual);
            return 0;
        }
    }

    felem_copy(alias_a, a);
    mont_mul_bmi2_adx(alias_a, b, alias_a);
    if (memcmp(expected, alias_a, sizeof(felem)) != 0) {
        printf("FAIL: output aliases a at case %" PRIu64 "\n", index);
        return 0;
    }

    felem_copy(alias_b, b);
    mont_mul_bmi2_adx(a, alias_b, alias_b);
    if (memcmp(expected, alias_b, sizeof(felem)) != 0) {
        printf("FAIL: output aliases b at case %" PRIu64 "\n", index);
        return 0;
    }
    return 1;
}

static int test_montgomery(uint64_t random_cases) {
    const felem edge[] = {
        {0, 0, 0, 0},
        {1, 0, 0, 0},
        {UINT64_MAX, 0, 0, 0},
        {UINT64_MAX, UINT64_MAX, 0, 0},
        {UINT64_MAX, UINT64_MAX, UINT64_MAX, 0},
        {UINT64_MAX - 1, UINT64_C(0xffffffff00000000), UINT64_MAX,
         UINT64_C(0xfffffffeffffffff)},
        {UINT64_C(0x0000000000000001), UINT64_C(0x00000000ffffffff), 0,
         UINT64_C(0x0000000100000000)},
        {UINT64_C(0x0000000200000003), UINT64_C(0x00000002ffffffff),
         UINT64_C(0x0000000100000001), UINT64_C(0x0000000400000002)},
        {UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555),
         UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_C(0x5555555555555555)},
        {UINT64_C(0x5555555555555555), UINT64_C(0xaaaaaaaaaaaaaaaa),
         UINT64_C(0x5555555555555555), UINT64_C(0xaaaaaaaaaaaaaaaa)}
    };
    uint64_t index = 0;
    for (size_t i = 0; i < sizeof(edge) / sizeof(edge[0]); ++i) {
        for (size_t j = 0; j < sizeof(edge) / sizeof(edge[0]); ++j) {
            if (!check_pair(edge[i], edge[j], index++)) return 0;
        }
    }

    for (uint64_t i = 0; i < random_cases; ++i) {
        felem a, b;
        random_felem(a);
        random_felem(b);
        if (!check_pair(a, b, index++)) return 0;
    }
    printf("PASS: Montgomery differential (%" PRIu64 " cases plus alias checks)\n",
           index);
    return 1;
}

static void random_u32(uint32_t out[8]) {
    for (int i = 0; i < 8; i += 2) {
        uint64_t value = next_random();
        out[i] = (uint32_t)value;
        out[i + 1] = (uint32_t)(value >> 32);
    }
}

static void reset_point_caches(void) {
    g_base_ready = 0;
    memset(g_base_table, 0, sizeof(g_base_table));
    memset(g_gx_mont, 0, sizeof(g_gx_mont));
    memset(g_gy_mont, 0, sizeof(g_gy_mont));
    memset(&g_pcache, 0, sizeof(g_pcache));
}

static int test_shamir(unsigned int cases) {
    for (unsigned int i = 0; i < cases; ++i) {
        uint32_t private_k[8], s[8], t[8];
        uint32_t pub_x[8], pub_y[8];
        uint32_t expected_x[8], expected_y[8], actual_x[8], actual_y[8];
        random_u32(private_k);
        random_u32(s);
        random_u32(t);
        private_k[0] |= 1;

        g_mont_mul_impl = mont_mul_generic;
        reset_point_caches();
        fixed_base_mul(private_k, pub_x, pub_y);
        shamir_mul(s, pub_x, pub_y, t, expected_x, expected_y);

        g_mont_mul_impl = mont_mul_bmi2;
        reset_point_caches();
        shamir_mul(s, pub_x, pub_y, t, actual_x, actual_y);
        if (memcmp(expected_x, actual_x, sizeof(expected_x)) != 0 ||
            memcmp(expected_y, actual_y, sizeof(expected_y)) != 0) {
            printf("FAIL: BMI2 Shamir differential at case %u\n", i);
            return 0;
        }

        g_mont_mul_impl = mont_mul_bmi2_adx;
        reset_point_caches();
        shamir_mul(s, pub_x, pub_y, t, actual_x, actual_y);
        if (memcmp(expected_x, actual_x, sizeof(expected_x)) != 0 ||
            memcmp(expected_y, actual_y, sizeof(expected_y)) != 0) {
            printf("FAIL: BMI2+ADX Shamir differential at case %u\n", i);
            return 0;
        }
    }
    g_mont_mul_impl = mont_mul_generic;
    reset_point_caches();
    printf("PASS: Shamir differential (%u generated public keys, "
           "generic/bmi2/bmi2_adx)\n", cases);
    return 1;
}

/* ---- wNAF reconstruction test (no CPU-feature dependency) --------------
 * Reconstructs sum(wnaf[i] * 2^i) with a 12-limb accumulator and compares
 * against the original scalar. Guards the wnaf_encode carry-propagation
 * path (negative digits produce a +1 carry that must not be dropped). */

static void acc_add_shifted(uint32_t acc[12], int bit, uint32_t val) {
    int limb = bit >> 5, off = bit & 31;
    uint64_t sh = (uint64_t)val << off;
    uint32_t v[2] = {(uint32_t)sh, (uint32_t)(sh >> 32)};
    uint64_t cc = 0;
    for (int i = 0; i < 2; i++) {
        cc += (uint64_t)acc[limb + i] + v[i];
        acc[limb + i] = (uint32_t)cc;
        cc >>= 32;
    }
    for (int i = limb + 2; cc && i < 12; i++) {
        cc += acc[i];
        acc[i] = (uint32_t)cc;
        cc >>= 32;
    }
}

static void acc_sub_shifted(uint32_t acc[12], int bit, uint32_t val) {
    int limb = bit >> 5, off = bit & 31;
    uint64_t sh = (uint64_t)val << off;
    uint32_t v[2] = {(uint32_t)sh, (uint32_t)(sh >> 32)};
    int64_t bw = 0;
    for (int i = 0; i < 2; i++) {
        bw += (int64_t)(uint64_t)acc[limb + i] - v[i];
        acc[limb + i] = (uint32_t)bw;
        bw >>= 32;
    }
    for (int i = limb + 2; bw && i < 12; i++) {
        bw += (int64_t)(uint64_t)acc[i];
        acc[i] = (uint32_t)bw;
        bw >>= 32;
    }
}

static int wnaf_check_scalar(const uint32_t k[8], int w, const char *label,
                             uint64_t index) {
    int wnaf[260];
    int len = wnaf_encode(k, w, wnaf, 258);
    uint32_t acc[12] = {0};
    for (int i = 0; i < len; i++) {
        if (wnaf[i] > 0) acc_add_shifted(acc, i, (uint32_t)wnaf[i]);
        else if (wnaf[i] < 0) acc_sub_shifted(acc, i, (uint32_t)(-wnaf[i]));
    }
    if (memcmp(acc, k, 32) != 0 || acc[8] || acc[9] || acc[10] || acc[11]) {
        printf("FAIL: wNAF(w=%d) reconstruction mismatch at %s case %"
               PRIu64 "\n", w, label, index);
        return 0;
    }
    return 1;
}

static int test_wnaf_reconstruction(uint64_t random_cases) {
    uint32_t n32[8];
    u64_to_u32(N_ORD, n32);
    uint32_t n_minus_1[8], n_minus_2[8];
    memcpy(n_minus_1, n32, 32);
    memcpy(n_minus_2, n32, 32);
    /* n is odd: n-1 only flips limb 0; n-2 never borrows either */
    n_minus_1[0] -= 1;
    n_minus_2[0] -= 2;

    uint32_t zero[8] = {0};
    uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint32_t all_ones[8] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                            0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
    uint32_t bit255[8] = {0, 0, 0, 0, 0, 0, 0, 0x80000000u};
    uint32_t alt_aa[8] = {0xAAAAAAAAu, 0xAAAAAAAAu, 0xAAAAAAAAu, 0xAAAAAAAAu,
                          0xAAAAAAAAu, 0xAAAAAAAAu, 0xAAAAAAAAu, 0xAAAAAAAAu};
    uint32_t alt_55[8] = {0x55555555u, 0x55555555u, 0x55555555u, 0x55555555u,
                          0x55555555u, 0x55555555u, 0x55555555u, 0x55555555u};
    uint32_t ones64[8] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0, 0, 0, 0, 0, 0};
    uint32_t ones128[8] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                           0, 0, 0, 0};
    uint32_t ones192[8] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                           0xFFFFFFFFu, 0xFFFFFFFFu, 0, 0};
    uint32_t ones252[8] = {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                           0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x0FFFFFFFu};

    const uint32_t *edges[] = {zero, one, n_minus_1, n_minus_2, all_ones,
                               bit255, alt_aa, alt_55, ones64, ones128,
                               ones192, ones252};
    const char *names[] = {"0", "1", "n-1", "n-2", "2^256-1", "2^255",
                           "0xAA..", "0x55..", "2^64-1", "2^128-1",
                           "2^192-1", "2^252-1"};
    const int widths[] = {7, 6};

    for (int wi = 0; wi < 2; wi++) {
        for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); i++) {
            if (!wnaf_check_scalar(edges[i], widths[wi], names[i], i))
                return 0;
        }
        for (uint64_t i = 0; i < random_cases; i++) {
            uint32_t k[8];
            random_u32(k);
            if (!wnaf_check_scalar(k, widths[wi], "random", i))
                return 0;
        }
    }
    printf("PASS: wNAF reconstruction (%zu edge + %" PRIu64
           " random scalars, w=7/6)\n",
           sizeof(edges) / sizeof(edges[0]), random_cases);
    return 1;
}

static volatile uint64_t benchmark_sink;

/* ---- Phase 1 projective verify: differential & synthetic tests ---------- */

static int felem_lt_n(const felem a) {
    for (int i = 3; i >= 0; --i) {
        if (a[i] < N_ORD[i]) return 1;
        if (a[i] > N_ORD[i]) return 0;
    }
    return 0; /* a == n is not < n */
}

static void random_modn(felem out) {
    do {
        for (int i = 0; i < 4; ++i) out[i] = next_random();
    } while (!felem_lt_n(out));
}

/* out = x - n, plain 256-bit subtraction, requires x >= n */
static void sub_n(const felem x, felem out) {
    uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t xi = x[i], ni = N_ORD[i];
        out[i] = xi - ni - borrow;
        borrow = (xi < ni) || (borrow && xi == ni);
    }
}

/* a^(n-2) mod n via Montgomery square-and-multiply (test helper) */
static void test_modn_inv(const uint32_t a[8], uint32_t inv[8]) {
    felem a_f, acc, base, out;
    u32_to_u64(a, a_f);
    to_mont_n(a_f, base);
    felem_copy(acc, MONT_ONE_N);
    for (int i = 0; i < 256; ++i) {
        if ((N_MINUS_2_U32[i >> 5] >> (i & 31)) & 1u) modn_mul(acc, base, acc);
        modn_mul(base, base, base);
    }
    from_mont_n(acc, out);
    u64_to_u32(out, inv);
}

/* Exact replica of the pre-Phase-1 verify_core_impl (affine path), kept as
 * the differential oracle for the projective comparison. */
static int old_verify_reference(const jbyte *e32, const jbyte *r32,
                                const jbyte *s32, const jbyte *pubXY64) {
    uint32_t e_u[8], r_u[8], s_u[8], px_u[8], py_u[8];
    be_to_u32(e32, e_u); be_to_u32(r32, r_u); be_to_u32(s32, s_u);
    be_to_u32(pubXY64, px_u); be_to_u32(pubXY64 + 32, py_u);

    felem r_f, s_f, t_f;
    u32_to_u64(r_u, r_f); u32_to_u64(s_u, s_f);
    modn_add(r_f, s_f, t_f);
    if (felem_is_zero(t_f)) return 0;

    uint32_t t_u[8]; u64_to_u32(t_f, t_u);
    uint32_t rx_u[8], ry_u[8];
    shamir_mul(s_u, px_u, py_u, t_u, rx_u, ry_u);

    felem e_f, x1_f, R_f;
    u32_to_u64(e_u, e_f); u32_to_u64(rx_u, x1_f);
    modn_add(e_f, x1_f, R_f);

    felem r_check; u32_to_u64(r_u, r_check);
    return (R_f[0] == r_check[0]) && (R_f[1] == r_check[1]) &&
           (R_f[2] == r_check[2]) && (R_f[3] == r_check[3]);
}

static void random_scalar_u32(uint32_t k[8]) {
    do { random_u32(k); } while (!is_valid_scalar(k));
}

/* End-to-end differential: valid signatures must be accepted by both paths,
 * tampered signatures must agree. Random e/r/s tuples cannot reach the
 * x0 + n second candidate (p - n is 128 bits), so that branch is covered
 * by test_verify_jac_synthetic instead. */
static int test_verify_jac_e2e(uint64_t cases) {
    enum { NKEYS = 2 };
    uint32_t d[NKEYS][8], dinv[NKEYS][8];
    jbyte pub[NKEYS][64];
    for (int i = 0; i < NKEYS; ++i) {
        random_scalar_u32(d[i]);
        uint32_t dp1[8];
        memcpy(dp1, d[i], 32);
        uint64_t c = 1; /* d <= n-2, so d + 1 cannot overflow */
        for (int j = 0; j < 8 && c; ++j) {
            c += dp1[j];
            dp1[j] = (uint32_t)c;
            c >>= 32;
        }
        test_modn_inv(dp1, dinv[i]);
        uint32_t px[8], py[8];
        fixed_base_mul(d[i], px, py);
        u32_to_be(px, pub[i]);
        u32_to_be(py, pub[i] + 32);
    }

    const felem_mul_impl impls[] = {mont_mul_generic, mont_mul_bmi2,
                                    mont_mul_bmi2_adx};
    const felem_mul_impl nimpls[] = {modn_mul_generic, modn_mul_bmi2,
                                     modn_mul_bmi2_adx};
    uint64_t accepted = 0, rejected = 0;

    for (uint64_t i = 0; i < cases; ++i) {
        int ki = (int)((i / 512) % NKEYS); /* keep the pubkey cache mostly hot */
        g_mont_mul_impl = impls[i % 3];
        g_modn_mul_impl = nimpls[i % 3];

        jbyte e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
        uint32_t k[8];
        random_scalar_u32(k);
        for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
        u32_to_be(k, k_be);
        u32_to_be(d[ki], d_be);
        u32_to_be(dinv[ki], dinv_be);
        if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) { --i; continue; }

        int old_r = old_verify_reference(e, rs, rs + 32, pub[ki]);
        int new_r = verify_core_impl(e, rs, rs + 32, pub[ki]);
        if (old_r != 1 || new_r != 1) {
            printf("FAIL: valid signature rejected at case %" PRIu64
                   " (old=%d new=%d)\n", i, old_r, new_r);
            return 0;
        }
        ++accepted;

        jbyte e_bad[32], rs_bad[64];
        memcpy(e_bad, e, 32);
        memcpy(rs_bad, rs, 64);
        rs_bad[next_random() % 64] ^= (jbyte)(1u << (next_random() % 8));
        if (next_random() % 4 == 0)
            e_bad[next_random() % 32] ^= (jbyte)(1u << (next_random() % 8));
        old_r = old_verify_reference(e_bad, rs_bad, rs_bad + 32, pub[ki]);
        new_r = verify_core_impl(e_bad, rs_bad, rs_bad + 32, pub[ki]);
        if (old_r != new_r) {
            printf("FAIL: tampered differential mismatch at case %" PRIu64
                   " (old=%d new=%d)\n", i, old_r, new_r);
            return 0;
        }
        if (new_r) ++accepted; else ++rejected;
    }
    g_mont_mul_impl = mont_mul_generic;
    g_modn_mul_impl = modn_mul_generic;
    printf("PASS: verify e2e differential (%" PRIu64 " valid + %" PRIu64
           " tampered, accepted=%" PRIu64 " rejected=%" PRIu64 ")\n",
           cases, cases, accepted, rejected);
    return 1;
}

/* Build X = x1 * Z^2 (Montgomery) and check verify_jac_x against it; when
 * expect == 1 the single-bit-flipped X must be rejected. */
static int synth_case(const felem x1, const felem Z, const felem e_f,
                      const felem r_f, int expect, const char *label,
                      uint64_t idx) {
    felem x1m, Z2, X;
    to_mont(x1, x1m);
    mont_sqr(Z, Z2);
    mont_mul(x1m, Z2, X);
    int got = verify_jac_x(X, Z, e_f, r_f);
    if (got != expect) {
        printf("FAIL: synthetic %s at case %" PRIu64 " (expect=%d got=%d)\n",
               label, idx, expect, got);
        print_felem("x1", x1);
        print_felem("Z", Z);
        print_felem("e", e_f);
        print_felem("r", r_f);
        return 0;
    }
    if (expect == 1) {
        felem Xbad;
        felem_copy(Xbad, X);
        Xbad[0] ^= 1;
        if (verify_jac_x(Xbad, Z, e_f, r_f) != 0) {
            printf("FAIL: synthetic %s negative at case %" PRIu64 "\n",
                   label, idx);
            return 0;
        }
    }
    return 1;
}

/* Field-level synthetic coverage for the branches random e2e cannot reach:
 * the x0 + n candidate (P(x1 in [n, p)) ~ 2^-129 by chance), e >= n
 * reduction, and the Z == 0 legacy path. */
static int test_verify_jac_synthetic(uint64_t cases) {
    const felem zero = {0, 0, 0, 0};
    g_mont_mul_impl = mont_mul_bmi2_adx;

    for (uint64_t i = 0; i < cases; ++i) {
        felem Z, r_f, x0, x1, e_f;
        do { random_felem(Z); } while (felem_is_zero(Z));
        random_modn(r_f);
        const char *label;
        if (i & 1) {
            random_modn(x1); /* branch A: x1 < n, first candidate */
            felem_copy(x0, x1);
            label = "branchA";
        } else {
            /* branch B: x1 = n + v with v < 2^127 < p - n, so x1 in [n, p)
             * and only the x0 + n candidate can match */
            felem v = {next_random(),
                       next_random() & UINT64_C(0x7FFFFFFFFFFFFFFF), 0, 0};
            uint64_t carry = 0;
            for (int j = 0; j < 4; ++j) {
                uint64_t s = N_ORD[j] + v[j] + carry;
                carry = (s < N_ORD[j]) || (carry && s == N_ORD[j]);
                x1[j] = s;
            }
            if (carry || felem_compare(x1, P64) >= 0) { --i; continue; }
            sub_n(x1, x0);
            label = "branchB(x0+n)";
        }
        modn_sub(r_f, x0, e_f); /* e = (r - x0) mod n */
        if (!synth_case(x1, Z, e_f, r_f, 1, label, i)) return 0;
    }

    /* Deterministic edges. */
    felem Z, r_f, e_f, x0, x1;
    do { random_felem(Z); } while (felem_is_zero(Z));
    random_modn(r_f);

    /* Z == 0: legacy x1 = 0 semantics, (e + 0) mod n == r */
    if (verify_jac_x(Z, zero, r_f, r_f) != 1) {
        printf("FAIL: edge Z==0 e==r must accept\n");
        return 0;
    }
    random_modn(e_f);
    if (felem_compare(e_f, r_f) == 0) e_f[0] ^= 1;
    if (verify_jac_x(Z, zero, e_f, r_f) != 0) {
        printf("FAIL: edge Z==0 e!=r must reject\n");
        return 0;
    }
    /* Z == 0 with e = r + n (e >= n): legacy modn_add reduces once, accept */
    const felem r_small = {0x12345678, 0, 0, 0};
    felem e_big;
    {
        uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t s = r_small[j] + N_ORD[j] + carry;
            carry = (s < r_small[j]) || (carry && s == r_small[j]);
            e_big[j] = s;
        }
    }
    if (verify_jac_x(Z, zero, e_big, r_small) != 1) {
        printf("FAIL: edge Z==0 e=r+n must accept (legacy semantics)\n");
        return 0;
    }

    /* e = 2^256 - 1 (>= n): exercises the e-reduction before x0 */
    {
        const felem e_all = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX};
        felem e_red, x1a;
        sub_n(e_all, e_red);
        modn_sub(r_f, e_red, x0);
        felem_copy(x1a, x0);
        if (!synth_case(x1a, Z, e_all, r_f, 1, "e=2^256-1", 0)) return 0;
    }

    /* x0 == 0 (e == r): X = 0 must accept */
    if (!synth_case(zero, Z, r_f, r_f, 1, "x0==0", 0)) return 0;

    /* x0 + n == p: second candidate invalid, first candidate accepts */
    sub_n(P64, x0);
    felem_copy(x1, x0);
    modn_sub(r_f, x0, e_f);
    if (!synth_case(x1, Z, e_f, r_f, 1, "x0+n==p", 0)) return 0;

    /* x0 + n == p - 1: second candidate accepts with x1 = p - 1 */
    {
        felem xm1;
        felem_copy(xm1, P64);
        xm1[0] -= 1;
        sub_n(xm1, x0);
        modn_sub(r_f, x0, e_f);
        if (!synth_case(xm1, Z, e_f, r_f, 1, "x0+n==p-1", 0)) return 0;
    }

    /* x0 + n == 2^256 (carry out): second candidate rejected via carry */
    {
        felem xc;
        uint64_t carry = 1;
        for (int j = 0; j < 4; ++j) {
            uint64_t t = ~N_ORD[j] + carry;
            carry = (carry && t == 0) ? 1 : 0;
            xc[j] = t;
        }
        if (!felem_lt_n(xc)) {
            printf("FAIL: edge setup 2^256-n < n violated\n");
            return 0;
        }
        modn_sub(r_f, xc, e_f);
        if (!synth_case(xc, Z, e_f, r_f, 1, "x0+n==2^256", 0)) return 0;
    }

    /* x0 + n in [p, 2^256): second candidate must be rejected, not reduced
     * mod p. X is built from x1wrap = x0 + n - p; a buggy mod-p candidate
     * would wrongly accept. */
    {
        felem xw, Xw, x1m, Z2;
        sub_n(P64, x0);
        x0[0] += 0x12345; /* no carry: low limb of p-n is 0xAC440BF6C62ABEDC */
        modn_sub(r_f, x0, e_f);
        felem_copy(xw, zero);
        xw[0] = 0x12345;
        to_mont(xw, x1m);
        mont_sqr(Z, Z2);
        mont_mul(x1m, Z2, Xw);
        if (verify_jac_x(Xw, Z, e_f, r_f) != 0) {
            printf("FAIL: edge x0+n>=p must reject (mod-p reduction bug?)\n");
            return 0;
        }
    }

    printf("PASS: verify synthetic (%" PRIu64
           " constructed cases incl. x0+n branch, plus 8 edge groups)\n",
           cases);
    return 1;
}

/* ---- Comb-per-pubkey verify with adaptive promotion ---------------------
 * verify_core_impl is the adaptive router (wNAF below the promotion
 * threshold, comb at/after it). verify_core_comb forces the comb path,
 * verify_core_wnaf forces the wNAF path; old_verify_reference is the
 * affine oracle. Tests are three-way wherever practical. */

/* Point-level differential: [s]G + [t]P via two comb muls + jac_add must
 * equal the wNAF Shamir oracle exactly (affine coordinates). */
static int test_comb_point_differential(uint64_t cases) {
    uint32_t d[8], px[8], py[8];
    random_scalar_u32(d);
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();
    fixed_base_mul(d, px, py);
    ensure_comb_table();
    pcache_ensure(px, py);
    { /* force the per-key comb table build for this test */
        felem mx, my; u32_to_mont(px, mx); u32_to_mont(py, my);
        build_comb_table_for(mx, my, g_pcache.comb);
        g_pcache.comb_valid = 1;
    }

    uint32_t n32[8]; u64_to_u32(N_ORD, n32);
    uint32_t nm1[8]; memcpy(nm1, n32, 32); nm1[0] -= 1;
    uint32_t allf[8]; memset(allf, 0xFF, 32);
    uint32_t zero[8] = {0};
    uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    const uint32_t *edges[] = {zero, one, nm1, allf, n32};

    uint64_t total = 0;
    for (uint64_t i = 0; i < cases + 25; ++i) {
        uint32_t s[8], t[8];
        if (i < 25) { /* 5x5 grid of {0, 1, n-1, 2^256-1, n} for (s,t) */
            memcpy(s, edges[i / 5], 32);
            memcpy(t, edges[i % 5], 32);
        } else {
            random_u32(s);
            random_u32(t);
        }
        uint32_t ex[8], ey[8];
        shamir_mul(s, px, py, t, ex, ey);

        felem X1,Y1,Z1, X2,Y2,Z2, X3,Y3,Z3, rxm, rym;
        comb_mul_projective(g_comb_table, s, X1, Y1, Z1);
        comb_mul_projective(g_pcache.comb, t, X2, Y2, Z2);
        jac_add(X1,Y1,Z1, X2,Y2,Z2, X3,Y3,Z3);
        jac_to_affine(X3,Y3,Z3, rxm, rym);
        uint32_t ax[8], ay[8];
        mont_to_u32(rxm, ax); mont_to_u32(rym, ay);
        if (memcmp(ex, ax, 32) != 0 || memcmp(ey, ay, 32) != 0) {
            printf("FAIL: comb point differential at case %" PRIu64 "\n", i);
            return 0;
        }
        ++total;
    }
    printf("PASS: comb point differential (%" PRIu64
           " cases incl. 25 scalar edges)\n", total);
    return 1;
}

/* Craft (e, r) so that (e, r, s) MUST be accepted for pub, with the
 * verify-derived t = (r + s) mod n equal to t_req. x of [s]G + [t]P comes
 * from the affine oracle; the point at infinity yields x = 0, i.e. e == r,
 * which is exactly the Z == 0 accept branch of verify_jac_x. Requires
 * s, t < n; returns 0 if the derived r == 0 (caller picks other s/t). */
static int make_accept(const uint32_t s[8], const uint32_t t[8],
                       const jbyte pub[64], jbyte e[32], jbyte r_be[32]) {
    uint32_t px[8], py[8], x[8], y[8];
    be_to_u32(pub, px); be_to_u32(pub + 32, py);
    shamir_mul(s, px, py, t, x, y);

    felem sf, tf, rf;
    u32_to_u64(s, sf); u32_to_u64(t, tf);
    modn_sub(tf, sf, rf);              /* r = (t - s) mod n */
    if (felem_is_zero(rf)) return 0;

    felem xf; u32_to_u64(x, xf);
    if (!felem_lt_n(xf)) sub_n(xf, xf); /* x < p may be >= n */
    felem ef;
    modn_sub(rf, xf, ef);              /* e = (r - x) mod n */

    uint32_t r32[8], e32[8];
    u64_to_u32(rf, r32); u64_to_u32(ef, e32);
    u32_to_be(r32, r_be); u32_to_be(e32, e);
    return 1;
}

static int check_comb_accept(const uint32_t s[8], const uint32_t t[8],
                             const jbyte pub[64], const char *label) {
    jbyte e[32], rb[32], sb[32];
    if (!make_accept(s, t, pub, e, rb)) {
        printf("FAIL: comb edge %s produced degenerate r\n", label);
        return 0;
    }
    u32_to_be(s, sb);
    int ref = old_verify_reference(e, rb, sb, pub);
    int router = verify_core_impl(e, rb, sb, pub);
    int comb = verify_core_comb(e, rb, sb, pub);
    if (ref != 1 || router != 1 || comb != 1) {
        printf("FAIL: comb edge accept %s (ref=%d router=%d comb=%d)\n",
               label, ref, router, comb);
        return 0;
    }
    return 1;
}

static int check_comb_agree(const jbyte e[32], const jbyte r[32],
                            const jbyte s[32], const jbyte pub[64],
                            const char *label) {
    int ref = old_verify_reference(e, r, s, pub);
    int router = verify_core_impl(e, r, s, pub);
    int comb = verify_core_comb(e, r, s, pub);
    if (ref != router || ref != comb) {
        printf("FAIL: comb edge agree %s (ref=%d router=%d comb=%d)\n",
               label, ref, router, comb);
        return 0;
    }
    return 1;
}

/* Deterministic edge coverage for the comb verify path: s == 0 (comb
 * accumulator never starts, Z == 0 passthrough in jac_add), point at
 * infinity as the final sum (Z == 0 accept branch), r/s at 1 and n-1,
 * t == 0 early exit, s == t == 0, and e = 2^256-1. */
static int test_verify_comb_edges(void) {
    uint32_t n32[8]; u64_to_u32(N_ORD, n32);
    uint32_t nm1[8]; memcpy(nm1, n32, 32); nm1[0] -= 1;
    uint32_t zero[8] = {0};
    uint32_t one[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint32_t two[8] = {2, 0, 0, 0, 0, 0, 0, 0};

    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();

    /* K1: random key. KG: d == 1, i.e. P == G (enables the infinity sum). */
    uint32_t d[8], px[8], py[8];
    random_scalar_u32(d);
    fixed_base_mul(d, px, py);
    jbyte pub1[64], pubG[64];
    u32_to_be(px, pub1); u32_to_be(py, pub1 + 32);
    u32_to_be(GX32, pubG); u32_to_be(GY32, pubG + 32);

    uint32_t s_r[8], t_r[8], s_r2[8], sp1[8];
    random_scalar_u32(s_r);
    random_scalar_u32(t_r);
    random_scalar_u32(s_r2);
    memcpy(sp1, s_r2, 32); /* s_r2 <= n-2, so +1 stays < n */
    {
        uint64_t c = 1;
        for (int j = 0; j < 8 && c; ++j) {
            c += sp1[j]; sp1[j] = (uint32_t)c; c >>= 32;
        }
    }

    /* Crafted accepts: all three paths must return 1. */
    if (!check_comb_accept(zero, t_r, pub1, "s==0")) return 0;
    if (!check_comb_accept(one, t_r, pub1, "s==1")) return 0;
    if (!check_comb_accept(nm1, two, pub1, "s==n-1 (r==3)")) return 0;
    if (!check_comb_accept(s_r2, sp1, pub1, "r==1")) return 0;
    if (!check_comb_accept(two, one, pub1, "r==n-1")) return 0;
    if (!check_comb_accept(s_r, t_r, pub1, "random s,t")) return 0;
    if (!check_comb_accept(zero, t_r, pubG, "s==0, P==G")) return 0;
    if (!check_comb_accept(nm1, one, pubG, "sum==O (Z==0 accept)")) return 0;

    /* Agreement cases (identical result on all three paths). */
    jbyte e[32], rb[32], sb[32];
    uint32_t r_u[8];
    felem sf, rf;
    /* t == 0 early exit: r = n - s, three s variants */
    const uint32_t *s_vars[] = {one, nm1, s_r};
    const char *s_names[] = {"t==0 (s=1)", "t==0 (s=n-1)", "t==0 (s=rand)"};
    for (int v = 0; v < 3; ++v) {
        u32_to_u64(s_vars[v], sf);
        modn_sub(N_ORD, sf, rf);      /* r = n - s, in [1, n-1] */
        u64_to_u32(rf, r_u);
        u32_to_be(r_u, rb);
        u32_to_be(s_vars[v], sb);
        for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
        if (!check_comb_agree(e, rb, sb, pub1, s_names[v])) return 0;
    }
    /* s == t == 0: s = 0, r = 0 forces t = (r + s) mod n == 0 */
    memset(rb, 0, 32); memset(sb, 0, 32);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    if (!check_comb_agree(e, rb, sb, pub1, "s==t==0")) return 0;
    /* e == 2^256 - 1 (>= n): take a crafted accept, then corrupt e */
    if (!make_accept(one, t_r, pub1, e, rb)) {
        printf("FAIL: comb edge e=2^256-1 setup degenerate\n");
        return 0;
    }
    memset(e, 0xFF, 32);
    u32_to_be(one, sb);
    if (!check_comb_agree(e, rb, sb, pub1, "e==2^256-1")) return 0;
    /* Pure garbage tuple */
    for (int j = 0; j < 32; ++j) {
        e[j] = (jbyte)next_random();
        rb[j] = (jbyte)next_random();
        sb[j] = (jbyte)next_random();
    }
    if (!check_comb_agree(e, rb, sb, pub1, "garbage tuple")) return 0;

    printf("PASS: verify comb edge cases (8 accept groups, 6 agree groups)\n");
    return 1;
}

/* Adaptive promotion logic: same key GM_COMB_PROMOTE_THRESHOLD times must
 * switch to the comb path exactly at the threshold-th call (observed via
 * the test-visible g_pcache.comb_valid / g_pcache.hits hooks), results
 * identical to the affine oracle throughout; alternating keys must never
 * promote. */
static int test_comb_promotion(void) {
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();

    /* Key A + a valid signature under it. */
    uint32_t d[8], dinv[8], px[8], py[8], k[8];
    jbyte pubA[64], pubB[64], e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
    random_scalar_u32(d);
    uint32_t dp1[8];
    memcpy(dp1, d, 32);
    uint64_t c = 1;
    for (int j = 0; j < 8 && c; ++j) { c += dp1[j]; dp1[j] = (uint32_t)c; c >>= 32; }
    test_modn_inv(dp1, dinv);
    fixed_base_mul(d, px, py);
    u32_to_be(px, pubA); u32_to_be(py, pubA + 32);
    random_scalar_u32(k);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    u32_to_be(k, k_be); u32_to_be(d, d_be); u32_to_be(dinv, dinv_be);
    if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) {
        printf("FAIL: promotion setup could not sign\n");
        return 0;
    }
    /* Key B: any distinct key. */
    uint32_t d2[8], px2[8], py2[8];
    do { random_scalar_u32(d2); } while (memcmp(d2, d, 32) == 0);
    fixed_base_mul(d2, px2, py2);
    u32_to_be(px2, pubB); u32_to_be(py2, pubB + 32);

    const unsigned T = GM_COMB_PROMOTE_THRESHOLD;

    /* Phase 1: same key A for T+2 verifies; comb from call T onward. */
    reset_point_caches();
    for (unsigned i = 1; i <= T + 2; ++i) {
        int ref = old_verify_reference(e, rs, rs + 32, pubA);
        int r = verify_core_impl(e, rs, rs + 32, pubA);
        if (ref != 1 || r != 1) {
            printf("FAIL: promotion phase1 result at call %u (ref=%d r=%d)\n",
                   i, ref, r);
            return 0;
        }
        int expect_comb = (i >= T) ? 1 : 0;
        if (g_pcache.comb_valid != expect_comb) {
            printf("FAIL: promotion phase1 comb_valid=%d at call %u "
                   "(expect %d)\n", g_pcache.comb_valid, i, expect_comb);
            return 0;
        }
        if (g_pcache.hits != i) {
            printf("FAIL: promotion phase1 hits=%u at call %u\n",
                   g_pcache.hits, i);
            return 0;
        }
    }

    /* Phase 2: alternate A/B for 2T verifies; must never promote. */
    reset_point_caches();
    for (unsigned i = 0; i < 2 * T; ++i) {
        const jbyte *pub = (i & 1) ? pubB : pubA;
        int ref = old_verify_reference(e, rs, rs + 32, pub);
        int r = verify_core_impl(e, rs, rs + 32, pub);
        if (ref != r) {
            printf("FAIL: promotion phase2 result mismatch at %u "
                   "(ref=%d r=%d)\n", i, ref, r);
            return 0;
        }
        if (g_pcache.comb_valid) {
            printf("FAIL: promotion phase2 promoted at call %u\n", i);
            return 0;
        }
        if (g_pcache.hits != 1) {
            printf("FAIL: promotion phase2 hits=%u at call %u "
                   "(counter not reset on key change)\n", g_pcache.hits, i);
            return 0;
        }
    }

    /* Phase 3: settle back on A; promotes exactly at the T-th call. */
    for (unsigned i = 1; i <= T; ++i) {
        int r = verify_core_impl(e, rs, rs + 32, pubA);
        if (r != 1) {
            printf("FAIL: promotion phase3 result at call %u\n", i);
            return 0;
        }
        int expect_comb = (i >= T) ? 1 : 0;
        if (g_pcache.comb_valid != expect_comb) {
            printf("FAIL: promotion phase3 comb_valid=%d at call %u "
                   "(expect %d)\n", g_pcache.comb_valid, i, expect_comb);
            return 0;
        }
    }

    printf("PASS: comb promotion (threshold=%u: comb from call %u, "
           "%u alternating verifies never promote)\n", T, T, 2 * T);
    return 1;
}

/* Mass differential: valid signatures must be accepted by all three
 * paths, tampered signatures must agree. Mirrors test_verify_jac_e2e. */
static int test_verify_comb_e2e(uint64_t cases) {
    enum { NKEYS = 2 };
    uint32_t d[NKEYS][8], dinv[NKEYS][8];
    jbyte pub[NKEYS][64];
    for (int i = 0; i < NKEYS; ++i) {
        random_scalar_u32(d[i]);
        uint32_t dp1[8];
        memcpy(dp1, d[i], 32);
        uint64_t c = 1; /* d <= n-2, so d + 1 cannot overflow */
        for (int j = 0; j < 8 && c; ++j) {
            c += dp1[j];
            dp1[j] = (uint32_t)c;
            c >>= 32;
        }
        test_modn_inv(dp1, dinv[i]);
        uint32_t px[8], py[8];
        fixed_base_mul(d[i], px, py);
        u32_to_be(px, pub[i]);
        u32_to_be(py, pub[i] + 32);
    }

    const felem_mul_impl impls[] = {mont_mul_generic, mont_mul_bmi2,
                                    mont_mul_bmi2_adx};
    const felem_mul_impl nimpls[] = {modn_mul_generic, modn_mul_bmi2,
                                     modn_mul_bmi2_adx};
    uint64_t accepted = 0, rejected = 0;

    for (uint64_t i = 0; i < cases; ++i) {
        int ki = (int)((i / 512) % NKEYS); /* key windows: router promotes */
        g_mont_mul_impl = impls[i % 3];
        g_modn_mul_impl = nimpls[i % 3];

        jbyte e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
        uint32_t k[8];
        random_scalar_u32(k);
        for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
        u32_to_be(k, k_be);
        u32_to_be(d[ki], d_be);
        u32_to_be(dinv[ki], dinv_be);
        if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) { --i; continue; }

        int ref_r = old_verify_reference(e, rs, rs + 32, pub[ki]);
        int router_r = verify_core_impl(e, rs, rs + 32, pub[ki]);
        int comb_r = verify_core_comb(e, rs, rs + 32, pub[ki]);
        if (ref_r != 1 || router_r != 1 || comb_r != 1) {
            printf("FAIL: valid signature rejected at case %" PRIu64
                   " (ref=%d router=%d comb=%d)\n", i, ref_r, router_r,
                   comb_r);
            return 0;
        }
        ++accepted;

        jbyte e_bad[32], rs_bad[64];
        memcpy(e_bad, e, 32);
        memcpy(rs_bad, rs, 64);
        rs_bad[next_random() % 64] ^= (jbyte)(1u << (next_random() % 8));
        if (next_random() % 4 == 0)
            e_bad[next_random() % 32] ^= (jbyte)(1u << (next_random() % 8));
        ref_r = old_verify_reference(e_bad, rs_bad, rs_bad + 32, pub[ki]);
        router_r = verify_core_impl(e_bad, rs_bad, rs_bad + 32, pub[ki]);
        comb_r = verify_core_comb(e_bad, rs_bad, rs_bad + 32, pub[ki]);
        if (ref_r != router_r || ref_r != comb_r) {
            printf("FAIL: tampered differential mismatch at case %" PRIu64
                   " (ref=%d router=%d comb=%d)\n", i, ref_r, router_r,
                   comb_r);
            return 0;
        }
        if (router_r) ++accepted; else ++rejected;
    }
    g_mont_mul_impl = mont_mul_generic;
    g_modn_mul_impl = modn_mul_generic;
    printf("PASS: verify comb differential (%" PRIu64 " valid + %" PRIu64
           " tampered, accepted=%" PRIu64 " rejected=%" PRIu64 ")\n",
           cases, cases, accepted, rejected);
    return 1;
}

static volatile uint64_t benchmark_sink;

static double benchmark_mont(felem_mul_impl impl, uint64_t rounds) {
    felem a = {
        UINT64_C(0x0123456789abcdef), UINT64_C(0xfedcba9876543210),
        UINT64_C(0x0f1e2d3c4b5a6978), UINT64_C(0x6a09e667f3bcc908)
    };
    felem r;
    double start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        impl(a, a, r);
        felem_copy(a, r);
    }
    double elapsed = now_seconds() - start;
    benchmark_sink ^= a[0];
    return elapsed;
}

static void run_benchmark(uint64_t rounds) {
    benchmark_mont(mont_mul_generic, rounds / 20 + 1);
    benchmark_mont(mont_mul_bmi2, rounds / 20 + 1);
    benchmark_mont(mont_mul_bmi2_adx, rounds / 20 + 1);
    double generic = benchmark_mont(mont_mul_generic, rounds);
    double bmi2 = benchmark_mont(mont_mul_bmi2, rounds);
    double adx = benchmark_mont(mont_mul_bmi2_adx, rounds);
    printf("BENCH: generic %.2f ns/op, bmi2 %.2f ns/op, "
           "bmi2_adx %.2f ns/op\n",
           generic * 1e9 / (double)rounds,
           bmi2 * 1e9 / (double)rounds,
           adx * 1e9 / (double)rounds);
}

static double benchmark_shamir_path(uint64_t rounds,
                                    const uint32_t s[8],
                                    const uint32_t pub_x[8],
                                    const uint32_t pub_y[8],
                                    const uint32_t t[8]) {
    uint32_t out_x[8], out_y[8];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    reset_point_caches();
    shamir_mul(s, pub_x, pub_y, t, out_x, out_y);

    double start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        shamir_mul(s, pub_x, pub_y, t, out_x, out_y);
    }
    double elapsed = now_seconds() - start;
    benchmark_sink ^= out_x[0] ^ out_y[0];
    return elapsed;
}

static void run_shamir_benchmark(uint64_t rounds) {
    uint32_t private_k[8], s[8], t[8], pub_x[8], pub_y[8];
    random_u32(private_k);
    random_u32(s);
    random_u32(t);
    private_k[0] |= 1;
    g_mont_mul_impl = mont_mul_bmi2_adx;
    reset_point_caches();
    fixed_base_mul(private_k, pub_x, pub_y);

    benchmark_shamir_path(20, s, pub_x, pub_y, t);
    double elapsed = benchmark_shamir_path(rounds, s, pub_x, pub_y, t);
    printf("BENCH: Shamir %.2f us/op\n",
           elapsed * 1e6 / (double)rounds);
}

/* Same-binary A/B: projective verify_core_impl vs the affine oracle.
 * This is the direct native hot-path metric for the Phase 1 gate. */
static void run_verify_benchmark(uint64_t rounds) {
    uint32_t d[8], dinv[8], px[8], py[8];
    jbyte pub[64], e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();
    random_scalar_u32(d);
    uint32_t dp1[8];
    memcpy(dp1, d, 32);
    uint64_t c = 1;
    for (int j = 0; j < 8 && c; ++j) { c += dp1[j]; dp1[j] = (uint32_t)c; c >>= 32; }
    test_modn_inv(dp1, dinv);
    fixed_base_mul(d, px, py);
    u32_to_be(px, pub);
    u32_to_be(py, pub + 32);
    uint32_t k[8];
    random_scalar_u32(k);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    u32_to_be(k, k_be);
    u32_to_be(d, d_be);
    u32_to_be(dinv, dinv_be);
    if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) {
        puts("SKIP: verify benchmark could not create a signature");
        return;
    }

    int sink = 0;
    verify_core_impl(e, rs, rs + 32, pub);
    double s1 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_impl(e, rs, rs + 32, pub);
    double t1 = now_seconds() - s1;

    old_verify_reference(e, rs, rs + 32, pub);
    double s2 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= old_verify_reference(e, rs, rs + 32, pub);
    double t2 = now_seconds() - s2;
    benchmark_sink ^= (uint64_t)sink;

    double new_us = t1 * 1e6 / (double)rounds;
    double old_us = t2 * 1e6 / (double)rounds;
    printf("BENCH: verify projective %.2f us/op, affine-oracle %.2f us/op"
           " (saved %.2f us, %.1f%%)\n",
           new_us, old_us, old_us - new_us,
           (old_us - new_us) * 100.0 / old_us);
}

/* Three-way hot-path A/B, same signature, pubkey caches warm:
 * verify_core_impl (adaptive router; same key promotes to comb within
 * the first GM_COMB_PROMOTE_THRESHOLD rounds), verify_core_comb (forced
 * comb), verify_core_wnaf (forced wNAF oracle). */
static void run_verify_comb_benchmark(uint64_t rounds) {
    uint32_t d[8], dinv[8], px[8], py[8];
    jbyte pub[64], e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();
    random_scalar_u32(d);
    uint32_t dp1[8];
    memcpy(dp1, d, 32);
    uint64_t c = 1;
    for (int j = 0; j < 8 && c; ++j) { c += dp1[j]; dp1[j] = (uint32_t)c; c >>= 32; }
    test_modn_inv(dp1, dinv);
    fixed_base_mul(d, px, py);
    u32_to_be(px, pub);
    u32_to_be(py, pub + 32);
    uint32_t k[8];
    random_scalar_u32(k);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    u32_to_be(k, k_be);
    u32_to_be(d, d_be);
    u32_to_be(dinv, dinv_be);
    if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) {
        puts("SKIP: comb verify benchmark could not create a signature");
        return;
    }

    int sink = 0;
    verify_core_impl(e, rs, rs + 32, pub); /* warms + promotes */
    verify_core_comb(e, rs, rs + 32, pub);
    verify_core_wnaf(e, rs, rs + 32, pub);

    double s1 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_impl(e, rs, rs + 32, pub);
    double t1 = now_seconds() - s1;

    double s2 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_comb(e, rs, rs + 32, pub);
    double t2 = now_seconds() - s2;

    double s3 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_wnaf(e, rs, rs + 32, pub);
    double t3 = now_seconds() - s3;
    benchmark_sink ^= (uint64_t)sink;

    double router_us = t1 * 1e6 / (double)rounds;
    double comb_us = t2 * 1e6 / (double)rounds;
    double wnaf_us = t3 * 1e6 / (double)rounds;
    printf("BENCH: verify hot router-promoted %.2f us/op, comb-direct %.2f"
           " us/op, wNAF-oracle %.2f us/op (router saved %.2f us, %.1f%%"
           " vs wNAF)\n",
           router_us, comb_us, wnaf_us, wnaf_us - router_us,
           (wnaf_us - router_us) * 100.0 / wnaf_us);
}

/* Integrated cold-path A/B: a full verify with the per-key cache
 * invalidated before every call (simulates a key change), vs warm.
 * router cold == wNAF rebuild path (below threshold, never promotes);
 * comb-direct cold rebuilds the 255-entry comb table on every call. */
static void run_verify_comb_cold_benchmark(uint64_t rounds) {
    uint32_t d[8], dinv[8], px[8], py[8];
    jbyte pub[64], e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();
    random_scalar_u32(d);
    uint32_t dp1[8];
    memcpy(dp1, d, 32);
    uint64_t c = 1;
    for (int j = 0; j < 8 && c; ++j) { c += dp1[j]; dp1[j] = (uint32_t)c; c >>= 32; }
    test_modn_inv(dp1, dinv);
    fixed_base_mul(d, px, py);
    u32_to_be(px, pub);
    u32_to_be(py, pub + 32);
    uint32_t k[8];
    random_scalar_u32(k);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    u32_to_be(k, k_be);
    u32_to_be(d, d_be);
    u32_to_be(dinv, dinv_be);
    if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) {
        puts("SKIP: comb cold benchmark could not create a signature");
        return;
    }

    int sink = 0;
    double t;
    verify_core_impl(e, rs, rs + 32, pub); /* warm + promote */
    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_impl(e, rs, rs + 32, pub);
    double router_warm = now_seconds() - t;

    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        g_pcache.valid = 0; /* key-change path: wNAF rebuild, no promotion */
        sink ^= verify_core_impl(e, rs, rs + 32, pub);
    }
    double router_cold = now_seconds() - t;

    verify_core_comb(e, rs, rs + 32, pub); /* warm comb cache */
    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_comb(e, rs, rs + 32, pub);
    double comb_warm = now_seconds() - t;

    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        g_pcache.comb_valid = 0; /* force comb table rebuild */
        sink ^= verify_core_comb(e, rs, rs + 32, pub);
    }
    double comb_cold = now_seconds() - t;

    verify_core_wnaf(e, rs, rs + 32, pub); /* warm wNAF cache */
    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        sink ^= verify_core_wnaf(e, rs, rs + 32, pub);
    double wnaf_warm = now_seconds() - t;

    t = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        g_pcache.valid = 0; /* force 16-entry wNAF table rebuild */
        sink ^= verify_core_wnaf(e, rs, rs + 32, pub);
    }
    double wnaf_cold = now_seconds() - t;
    benchmark_sink ^= (uint64_t)sink;

    printf("BENCH: verify cold-path router warm=%.2f cold=%.2f; comb-direct"
           " warm=%.2f cold(build)=%.2f; wNAF warm=%.2f cold(build)=%.2f us\n",
           router_warm * 1e6 / (double)rounds,
           router_cold * 1e6 / (double)rounds,
           comb_warm * 1e6 / (double)rounds,
           comb_cold * 1e6 / (double)rounds,
           wnaf_warm * 1e6 / (double)rounds,
           wnaf_cold * 1e6 / (double)rounds);
}

static double benchmark_key_pattern(const uint32_t *s,
                                    uint32_t pub_x[][8], uint32_t pub_y[][8],
                                    const uint32_t *t, int key_count,
                                    uint64_t rounds, int force_miss) {
    uint32_t out_x[8], out_y[8];
    g_pcache.valid = 0;
    for (int i = 0; i < key_count; ++i)
        shamir_mul(s, pub_x[i], pub_y[i], t, out_x, out_y);

    double start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        if (force_miss) g_pcache.valid = 0;
        int key = (int)(i % (uint64_t)key_count);
        shamir_mul(s, pub_x[key], pub_y[key], t, out_x, out_y);
    }
    double elapsed = now_seconds() - start;
    benchmark_sink ^= out_x[0] ^ out_y[0];
    return elapsed * 1e6 / (double)rounds;
}

static double benchmark_first_call(const uint32_t *s,
                                   const uint32_t pub_x[8],
                                   const uint32_t pub_y[8],
                                   const uint32_t *t, uint64_t rounds) {
    uint32_t out_x[8], out_y[8];
    double elapsed = 0;
    for (uint64_t i = 0; i < rounds; ++i) {
        reset_point_caches();
        double start = now_seconds();
        shamir_mul(s, pub_x, pub_y, t, out_x, out_y);
        elapsed += now_seconds() - start;
    }
    benchmark_sink ^= out_x[0] ^ out_y[0];
    return elapsed * 1e6 / (double)rounds;
}

/* Time the verify tail (felem_inv / jac_to_affine) so the modular-inverse
 * share of a verify can be measured instead of only estimated by op count. */
static void run_tail_benchmark(uint64_t rounds) {
    felem X, Y, Z, zi, rx, ry;
    random_felem(X);
    random_felem(Y);
    do { random_felem(Z); } while (felem_is_zero(Z));
    g_mont_mul_impl = mont_mul_bmi2_adx;

    felem_inv(Z, zi);
    double s1 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) felem_inv(Z, zi);
    double t1 = now_seconds() - s1;
    benchmark_sink ^= zi[0];

    jac_to_affine(X, Y, Z, rx, ry);
    double s2 = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) jac_to_affine(X, Y, Z, rx, ry);
    double t2 = now_seconds() - s2;
    benchmark_sink ^= rx[0] ^ ry[0];

    printf("BENCH: felem_inv %.2f ns/op, jac_to_affine %.2f ns/op\n",
           t1 * 1e9 / (double)rounds, t2 * 1e9 / (double)rounds);
}

/* Per-key comb table build cost (~7x32 doublings + 255 mixed adds +
 * batch inversion): the one-time promotion cost of the comb verify path. */
static void run_pubcomb_build_benchmark(uint64_t rounds) {
    uint32_t private_k[8], pub_x[8], pub_y[8];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    reset_point_caches();
    random_u32(private_k);
    private_k[0] |= 1;
    fixed_base_mul(private_k, pub_x, pub_y);
    felem mx, my;
    u32_to_mont(pub_x, mx);
    u32_to_mont(pub_y, my);
    build_comb_table_for(mx, my, g_pcache.comb); /* warm/sanity */
    double start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i)
        build_comb_table_for(mx, my, g_pcache.comb);
    double elapsed = now_seconds() - start;
    benchmark_sink ^= (uint64_t)g_pcache.comb[0].x[0];
    printf("BENCH: pubkey comb build %.2f us/op\n",
           elapsed * 1e6 / (double)rounds);
}

/* Key-pattern timing over a verify entry point (router or forced wNAF),
 * so the adaptive-promotion overhead on cold patterns is measured
 * apples-to-apples. force_miss clears the single-entry cache each round
 * (key-change path, never promotes). */
typedef int (*verify_fn)(const jbyte *, const jbyte *, const jbyte *,
                         const jbyte *);

static double benchmark_verify_pattern(verify_fn fn,
                                       const jbyte e[32], const jbyte rs[64],
                                       jbyte pub[][64], int key_count,
                                       uint64_t rounds, int force_miss) {
    int sink = 0;
    g_pcache.valid = 0;
    for (int i = 0; i < key_count; ++i)
        sink ^= fn(e, rs, rs + 32, pub[i]);

    double start = now_seconds();
    for (uint64_t i = 0; i < rounds; ++i) {
        if (force_miss) g_pcache.valid = 0;
        sink ^= fn(e, rs, rs + 32, pub[i % (uint64_t)key_count]);
    }
    double elapsed = now_seconds() - start;
    benchmark_sink ^= (uint64_t)sink;
    return elapsed * 1e6 / (double)rounds;
}

static double benchmark_verify_first_call(verify_fn fn, const jbyte e[32],
                                          const jbyte rs[64],
                                          const jbyte pub[64],
                                          uint64_t rounds) {
    int sink = 0;
    double elapsed = 0;
    for (uint64_t i = 0; i < rounds; ++i) {
        reset_point_caches();
        double start = now_seconds();
        sink ^= fn(e, rs, rs + 32, pub);
        elapsed += now_seconds() - start;
    }
    benchmark_sink ^= (uint64_t)sink;
    return elapsed * 1e6 / (double)rounds;
}

static void run_key_pattern_benchmark(uint64_t rounds) {
    enum { MAX_KEYS = 100 };
    uint32_t pub_x[MAX_KEYS][8], pub_y[MAX_KEYS][8];
    jbyte pubs[MAX_KEYS][64];
    uint32_t private_k[8], s[8], t[8];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    g_modn_mul_impl = modn_mul_bmi2_adx;
    reset_point_caches();
    random_u32(s);
    random_u32(t);
    uint32_t d0[8], dinv0[8];
    for (int i = 0; i < MAX_KEYS; ++i) {
        random_u32(private_k);
        private_k[0] |= 1;
        if (i == 0) {
            uint32_t dp1[8];
            memcpy(d0, private_k, 32);
            memcpy(dp1, d0, 32);
            uint64_t c = 1;
            for (int j = 0; j < 8 && c; ++j) {
                c += dp1[j]; dp1[j] = (uint32_t)c; c >>= 32;
            }
            test_modn_inv(dp1, dinv0);
        }
        fixed_base_mul(private_k, pub_x[i], pub_y[i]);
        u32_to_be(pub_x[i], pubs[i]);
        u32_to_be(pub_y[i], pubs[i] + 32);
    }
    /* A valid signature under key 0 for the verify-pattern lines. */
    jbyte e[32], k_be[32], d_be[32], dinv_be[32], rs[64];
    uint32_t kk[8];
    random_scalar_u32(kk);
    for (int j = 0; j < 32; ++j) e[j] = (jbyte)next_random();
    u32_to_be(kk, k_be);
    u32_to_be(d0, d_be);
    u32_to_be(dinv0, dinv_be);
    if (!sign_core_impl(e, d_be, dinv_be, k_be, rs)) {
        puts("SKIP: key-pattern benchmark could not create a signature");
        return;
    }

    /* wNAF scalar-mul primitive line (unchanged, baseline-comparable). */
    printf("BENCH: first-call=%.2f us, key cache warm=%.2f us, forced-miss=%.2f us",
           benchmark_first_call(s, pub_x[0], pub_y[0], t, 100),
           benchmark_key_pattern(s, pub_x, pub_y, t, 1, rounds, 0),
           benchmark_key_pattern(s, pub_x, pub_y, t, 1, rounds, 1));
    for (int keys = 2; keys <= MAX_KEYS; keys *= 5) {
        printf(", rotate-%d=%.2f us", keys,
               benchmark_key_pattern(s, pub_x, pub_y, t, keys, rounds, 0));
        if (keys == 50) keys = 20;
    }
    putchar('\n');

    /* Full-verify lines through the adaptive router and the forced-wNAF
     * oracle. Router "warm" promotes (same key) and shows the comb number;
     * forced-miss and rotate-N never promote (key change resets the
     * counter), so router vs wNAF there is the routing-overhead check. */
    const struct { const char *name; verify_fn fn; } vfns[] = {
        {"verify-router", verify_core_impl},
        {"verify-wnaf  ", verify_core_wnaf},
    };
    for (int v = 0; v < 2; ++v) {
        printf("BENCH: %s first-call=%.2f, warm=%.2f, forced-miss=%.2f",
               vfns[v].name,
               benchmark_verify_first_call(vfns[v].fn, e, rs, pubs[0], 100),
               benchmark_verify_pattern(vfns[v].fn, e, rs, pubs, 1, rounds, 0),
               benchmark_verify_pattern(vfns[v].fn, e, rs, pubs, 1, rounds, 1));
        for (int keys = 2; keys <= MAX_KEYS; keys *= 5) {
            printf(", rotate-%d=%.2f", keys,
                   benchmark_verify_pattern(vfns[v].fn, e, rs, pubs, keys,
                                            rounds, 0));
            if (keys == 50) keys = 20;
        }
        printf(" us\n");
    }
    run_pubcomb_build_benchmark(200);
    run_verify_comb_cold_benchmark(500);
}
#endif

int main(int argc, char **argv) {
    uint64_t random_cases = UINT64_C(1000000);
    uint64_t benchmark_rounds = UINT64_C(5000000);
    uint64_t verify_cases = UINT64_C(100000);
    if (argc > 1) random_cases = strtoull(argv[1], NULL, 10);
    if (argc > 2) benchmark_rounds = strtoull(argv[2], NULL, 10);
    if (argc > 3) verify_cases = strtoull(argv[3], NULL, 10);

    if (!test_wnaf_reconstruction(10000)) return 1;

#if GM_HAS_X86_RUNTIME_DISPATCH && HAS_INT128
    if (!cpu_has_bmi2_adx()) {
        puts("SKIP: CPU does not expose BMI2+ADX");
        return 0;
    }
    if (!test_montgomery(random_cases)) return 1;
    if (!test_shamir(128)) return 1;
    if (!test_verify_jac_e2e(verify_cases)) return 1;
    if (!test_verify_jac_synthetic(random_cases)) return 1;
    if (!test_comb_point_differential(10000)) return 1;
    if (!test_verify_comb_edges()) return 1;
    if (!test_comb_promotion()) return 1;
    /* contract: >= 100k valid + >= 100k tampered for the comb path */
    if (!test_verify_comb_e2e(verify_cases < 100000 ? 100000 : verify_cases))
        return 1;
    run_benchmark(benchmark_rounds);
    run_shamir_benchmark(2000);
    run_tail_benchmark(200000);
    run_verify_benchmark(2000);
    run_verify_comb_benchmark(10000);
    run_key_pattern_benchmark(1000);
    return 0;
#else
    (void)random_cases;
    (void)benchmark_rounds;
    puts("SKIP: compiler/architecture has no BMI2+ADX candidate");
    return 0;
#endif
}
