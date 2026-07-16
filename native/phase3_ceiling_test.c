/* Phase 3 ceiling experiment.
 *
 * A shamir-level single dispatch (one function pointer selecting a whole
 * monolithic Shamir/verify implementation) would replace ~3126 indirect
 * field-op calls per verify with direct, inlinable calls. This binary
 * simulates that ceiling: the entire translation unit is compiled with
 * -mbmi2 -madx and mont_mul/modn_mul route straight to the BMI2+ADX leaves
 * via the GM_DIRECT_* hooks, so the compiler may inline field arithmetic
 * into the point operations. Compare the "verify projective" number of this
 * binary against the regular native_mul_test.exe built from the same source.
 */
#define GM_DIRECT_MONT_MUL mont_mul_bmi2_adx
#define GM_DIRECT_MODN_MUL modn_mul_bmi2_adx
#include "native_mul_test.c"
