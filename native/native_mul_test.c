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

static void run_key_pattern_benchmark(uint64_t rounds) {
    enum { MAX_KEYS = 100 };
    uint32_t pub_x[MAX_KEYS][8], pub_y[MAX_KEYS][8];
    uint32_t private_k[8], s[8], t[8];
    g_mont_mul_impl = mont_mul_bmi2_adx;
    reset_point_caches();
    random_u32(s);
    random_u32(t);
    for (int i = 0; i < MAX_KEYS; ++i) {
        random_u32(private_k);
        private_k[0] |= 1;
        fixed_base_mul(private_k, pub_x[i], pub_y[i]);
    }

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
}
#endif

int main(int argc, char **argv) {
    uint64_t random_cases = UINT64_C(1000000);
    uint64_t benchmark_rounds = UINT64_C(5000000);
    if (argc > 1) random_cases = strtoull(argv[1], NULL, 10);
    if (argc > 2) benchmark_rounds = strtoull(argv[2], NULL, 10);

#if GM_HAS_X86_RUNTIME_DISPATCH && HAS_INT128
    if (!cpu_has_bmi2_adx()) {
        puts("SKIP: CPU does not expose BMI2+ADX");
        return 0;
    }
    if (!test_montgomery(random_cases)) return 1;
    if (!test_shamir(128)) return 1;
    run_benchmark(benchmark_rounds);
    run_shamir_benchmark(2000);
    run_key_pattern_benchmark(1000);
    return 0;
#else
    (void)random_cases;
    (void)benchmark_rounds;
    puts("SKIP: compiler/architecture has no BMI2+ADX candidate");
    return 0;
#endif
}
