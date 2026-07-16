/* Phase 3 experiment B — isolate pure dispatch overhead.
 *
 * phase3_ceiling_test.c (full-TU -mbmi2 -madx) forces the ALWAYS_INLINE
 * leaves into every point op, which measures inlining code bloat on top of
 * dispatch removal. This binary instead calls the BMI2+ADX leaves through
 * noinline wrappers: the indirect branch per field op becomes a direct call
 * but codegen at the call sites stays identical to the dispatched build.
 * The delta vs native_mul_test.exe is the pure indirect-call overhead that
 * a shamir-level single dispatch could remove at best.
 */
#include <stdint.h>
typedef uint64_t felem[4];
static void mont_leaf_direct(const felem a, const felem b, felem r);
static void modn_leaf_direct(const felem a, const felem b, felem r);
#define GM_DIRECT_MONT_MUL mont_leaf_direct
#define GM_DIRECT_MODN_MUL modn_leaf_direct
#include "native_mul_test.c"

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("bmi2,adx"), noinline))
#endif
static void mont_leaf_direct(const felem a, const felem b, felem r) {
    mont_mul_bmi2_adx(a, b, r);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((target("bmi2,adx"), noinline))
#endif
static void modn_leaf_direct(const felem a, const felem b, felem r) {
    modn_mul_bmi2_adx(a, b, r);
}
