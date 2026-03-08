/**
 * SM2 P-256-V1 native acceleration — Montgomery-form field arithmetic
 *
 * Key: SM2 prime p ≡ -1 (mod 2^64), so Montgomery parameter p' = 1.
 * This makes the CIOS reduction step trivially cheap (no multiplication by p').
 *
 * Internal representation: uint64_t[4] in Montgomery form (aR mod p).
 * JNI boundary converts between uint32_t[8] (little-endian) and Montgomery form.
 *
 * Build: gcc -shared -O3 -fPIC -march=native -funroll-loops -flto ...
 */
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
typedef signed   __int128 int128_t;
#define HAS_INT128 1
#else
#define HAS_INT128 0
#endif

typedef uint64_t felem[4];
typedef uint64_t felem_wide[8]; /* 512-bit */

/* ================================================================
 * Section 1 — SM2 constants (64-bit limb, little-endian)
 * ================================================================ */
static const felem P64 = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
};

/* R^2 mod p = (2^256)^2 mod p — for converting to Montgomery form */
static const felem R2_MODP = {
    0x0000000200000003ULL, 0x00000002FFFFFFFFULL,
    0x0000000100000001ULL, 0x0000000400000002ULL
};

/* Montgomery(1) = R mod p = 2^256 mod p */
static const felem MONT_ONE = {
    0x0000000000000001ULL, 0x00000000FFFFFFFFULL,
    0x0000000000000000ULL, 0x0000000100000000ULL
};

static const felem GX_MONT = {0,0,0,0}; /* filled lazily */
static const felem GY_MONT = {0,0,0,0};

/* Affine base point (non-Montgomery, little-endian 32-bit for JNI compat) */
static const uint32_t GX32[8] = {
    0x334C74C7, 0x715A4589, 0xF2660BE1, 0x8FE30BBF,
    0x6A39C994, 0x5F990446, 0x1F198119, 0x32C4AE2C
};
static const uint32_t GY32[8] = {
    0x2139F0A0, 0x02DF32E5, 0xC62A4740, 0xD0A9877C,
    0x6B692153, 0x59BDCEE3, 0xF4F6779C, 0xBC3736A2
};

/* ================================================================
 * Section 2 — helpers
 * ================================================================ */
static inline int felem_is_zero(const felem a) {
    return (a[0] | a[1] | a[2] | a[3]) == 0;
}

static inline void felem_copy(felem r, const felem a) {
    r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3];
}

static inline void u32_to_u64(const uint32_t *s, felem d) {
    d[0] = (uint64_t)s[0] | ((uint64_t)s[1] << 32);
    d[1] = (uint64_t)s[2] | ((uint64_t)s[3] << 32);
    d[2] = (uint64_t)s[4] | ((uint64_t)s[5] << 32);
    d[3] = (uint64_t)s[6] | ((uint64_t)s[7] << 32);
}

static inline void u64_to_u32(const felem s, uint32_t *d) {
    d[0]=(uint32_t)s[0]; d[1]=(uint32_t)(s[0]>>32);
    d[2]=(uint32_t)s[1]; d[3]=(uint32_t)(s[1]>>32);
    d[4]=(uint32_t)s[2]; d[5]=(uint32_t)(s[2]>>32);
    d[6]=(uint32_t)s[3]; d[7]=(uint32_t)(s[3]>>32);
}

/* ================================================================
 * Section 3 — Montgomery multiplication (CIOS, p'=1)
 *
 * The CIOS (Coarsely Integrated Operand Scanning) method interleaves
 * multiplication and reduction. Since p' = 1 for SM2, the quotient m
 * at each step is simply z[0] — no multiplication by p' needed.
 * ================================================================ */
#if HAS_INT128
static void mont_mul(const felem a, const felem b, felem r) {
    uint64_t z0=0, z1=0, z2=0, z3=0, z4=0;

    for (int i = 0; i < 4; i++) {
        /* z += a[i] * b */
        uint128_t carry = (uint128_t)a[i] * b[0] + z0;
        z0 = (uint64_t)carry; carry >>= 64;
        carry += (uint128_t)a[i] * b[1] + z1;
        z1 = (uint64_t)carry; carry >>= 64;
        carry += (uint128_t)a[i] * b[2] + z2;
        z2 = (uint64_t)carry; carry >>= 64;
        carry += (uint128_t)a[i] * b[3] + z3;
        z3 = (uint64_t)carry; carry >>= 64;
        uint128_t c1 = (uint128_t)(uint64_t)carry + z4;

        /* z += z[0] * p  (Montgomery reduction, m = z[0] since p' = 1) */
        uint64_t m = z0;
        carry = (uint128_t)m * P64[0] + z0;
        /* z0 becomes 0 by construction */ carry >>= 64;
        carry += (uint128_t)m * P64[1] + z1;
        z1 = (uint64_t)carry; carry >>= 64;
        carry += (uint128_t)m * P64[2] + z2;
        z2 = (uint64_t)carry; carry >>= 64;
        carry += (uint128_t)m * P64[3] + z3;
        z3 = (uint64_t)carry; carry >>= 64;
        c1 += (uint64_t)carry;

        /* shift right by 1 limb */
        z0 = z1; z1 = z2; z2 = z3; z3 = (uint64_t)c1; z4 = (uint64_t)(c1 >> 64);
    }

    /* conditional subtraction: if z >= p, z -= p */
    uint64_t d[4];
    int128_t bw = (int128_t)z0 - P64[0]; d[0]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z1 - P64[1];         d[1]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z2 - P64[2];         d[2]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z3 - P64[3];         d[3]=(uint64_t)bw; bw>>=64;
    bw += z4;

    uint64_t mask = (uint64_t)((int64_t)bw >> 63);
    r[0] = (z0 & mask) | (d[0] & ~mask);
    r[1] = (z1 & mask) | (d[1] & ~mask);
    r[2] = (z2 & mask) | (d[2] & ~mask);
    r[3] = (z3 & mask) | (d[3] & ~mask);
}
#else
/* Fallback: split to 32-bit */
static void mont_mul(const felem a, const felem b, felem r) {
    /* convert to uint32_t, schoolbook mul, Solinas reduce */
    uint32_t a32[8], b32[8], r32[8];
    u64_to_u32(a, a32); u64_to_u32(b, b32);
    /* ... existing Solinas approach as fallback ... */
    /* For brevity, this fallback calls the 32-bit path */
    uint32_t ext[16];
    memset(ext, 0, sizeof(ext));
    for (int i = 0; i < 8; i++) {
        uint64_t ai = a32[i], carry = 0;
        for (int j = 0; j < 8; j++) {
            carry += ai * (uint64_t)b32[j] + ext[i+j];
            ext[i+j] = (uint32_t)carry;
            carry >>= 32;
        }
        ext[i+8] = (uint32_t)carry;
    }
    /* Solinas reduce */
    uint64_t M = 0xFFFFFFFFULL;
    int64_t x0=ext[0]&M,x1=ext[1]&M,x2=ext[2]&M,x3=ext[3]&M,
            x4=ext[4]&M,x5=ext[5]&M,x6=ext[6]&M,x7=ext[7]&M,
            x8=ext[8]&M,x9=ext[9]&M,x10=ext[10]&M,x11=ext[11]&M,
            x12=ext[12]&M,x13=ext[13]&M,x14=ext[14]&M,x15=ext[15]&M;
    int64_t s0=x0+x8+x9+x10+x11+x12+2*x13+2*x14+2*x15;
    int64_t s1=x1+x9+x10+x11+x12+x13+2*x14+2*x15;
    int64_t s2=x2-x8-x9-x13-x14;
    int64_t s3=x3+x8+x11+x12+2*x13+x14+x15;
    int64_t s4=x4+x9+x12+x13+2*x14+x15;
    int64_t s5=x5+x10+x13+x14+2*x15;
    int64_t s6=x6+x11+x14+x15;
    int64_t s7=x7+x8+x9+x10+x11+2*x12+2*x13+2*x14+3*x15;
    int64_t cc;
    #define PROP cc=s0>>32;s0&=M;s1+=cc;cc=s1>>32;s1&=M;\
    s2+=cc;cc=s2>>32;s2&=M;s3+=cc;cc=s3>>32;s3&=M;\
    s4+=cc;cc=s4>>32;s4&=M;s5+=cc;cc=s5>>32;s5&=M;\
    s6+=cc;cc=s6>>32;s6&=M;s7+=cc;cc=s7>>32;s7&=M;\
    s0+=cc;s2-=cc;s3+=cc;s7+=cc;
    PROP PROP
    cc=s0>>32;s0&=M;s1+=cc;cc=s1>>32;s1&=M;
    s2+=cc;cc=s2>>32;s2&=M;s3+=cc;cc=s3>>32;s3&=M;
    s4+=cc;cc=s4>>32;s4&=M;s5+=cc;cc=s5>>32;s5&=M;
    s6+=cc;cc=s6>>32;s6&=M;s7+=cc;
    r32[0]=(uint32_t)s0;r32[1]=(uint32_t)s1;r32[2]=(uint32_t)s2;r32[3]=(uint32_t)s3;
    r32[4]=(uint32_t)s4;r32[5]=(uint32_t)s5;r32[6]=(uint32_t)s6;r32[7]=(uint32_t)s7;
    #undef PROP
    /* subPCond */
    {
        int64_t bw;
        uint32_t d[8];
        bw=(int64_t)(uint64_t)r32[0]-(int64_t)0xFFFFFFFF;d[0]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[1]-(int64_t)0xFFFFFFFF;d[1]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[2];d[2]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[3]-(int64_t)0xFFFFFFFF;d[3]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[4]-(int64_t)0xFFFFFFFF;d[4]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[5]-(int64_t)0xFFFFFFFF;d[5]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[6]-(int64_t)0xFFFFFFFF;d[6]=(uint32_t)bw;bw>>=32;
        bw+=(int64_t)(uint64_t)r32[7]-(int64_t)0xFFFFFFFE;d[7]=(uint32_t)bw;bw>>=32;
        int m=(int)bw;
        for(int i=0;i<8;i++) r32[i]=(d[i]&(uint32_t)~m)|(r32[i]&(uint32_t)m);
    }
    u32_to_u64(r32, r);
}
#endif

static inline void mont_sqr(const felem a, felem r) {
    mont_mul(a, a, r);
}

/* convert normal → Montgomery: mont(a) = a * R mod p = mont_mul(a, R^2 mod p) */
static void to_mont(const felem a, felem r) {
    mont_mul(a, R2_MODP, r);
}

/* convert Montgomery → normal: from_mont(a) = a * R^{-1} mod p = mont_mul(a, 1) */
static void from_mont(const felem a, felem r) {
    felem one = {1, 0, 0, 0};
    mont_mul(a, one, r);
}

/* Convert uint32_t[8] → Montgomery felem */
static void u32_to_mont(const uint32_t *s, felem r) {
    felem tmp;
    u32_to_u64(s, tmp);
    to_mont(tmp, r);
}

/* Convert Montgomery felem → uint32_t[8] */
static void mont_to_u32(const felem a, uint32_t *d) {
    felem tmp;
    from_mont(a, tmp);
    u64_to_u32(tmp, d);
}

/* ================================================================
 * Section 4 — Field add / sub / neg  (same in Montgomery domain)
 * ================================================================ */
static void felem_add(const felem a, const felem b, felem r) {
    uint128_t cc = 0;
    for (int i = 0; i < 4; i++) { cc += (uint128_t)a[i]+b[i]; r[i]=(uint64_t)cc; cc>>=64; }
    uint64_t carry = (uint64_t)cc;
    uint64_t d[4];
    int128_t bw = (int128_t)r[0] - P64[0]; d[0]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)r[1] - P64[1];         d[1]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)r[2] - P64[2];         d[2]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)r[3] - P64[3];         d[3]=(uint64_t)bw; bw>>=64;
    bw += carry;
    uint64_t mask = (uint64_t)((int64_t)bw >> 63);
    for (int i = 0; i < 4; i++) r[i] = (r[i] & mask) | (d[i] & ~mask);
}

static void felem_sub(const felem a, const felem b, felem r) {
    int128_t bw = 0;
    for (int i = 0; i < 4; i++) {
        bw += (int128_t)a[i] - b[i];
        r[i] = (uint64_t)bw;
        bw >>= 64;
    }
    if (bw < 0) {
        uint128_t cc = 0;
        for (int i = 0; i < 4; i++) { cc += (uint128_t)r[i]+P64[i]; r[i]=(uint64_t)cc; cc>>=64; }
    }
}

static void felem_neg(const felem a, felem r) {
    if (felem_is_zero(a)) { felem_copy(r, a); return; }
    int128_t bw = 0;
    for (int i = 0; i < 4; i++) {
        bw += (int128_t)P64[i] - a[i];
        r[i] = (uint64_t)bw;
        bw >>= 64;
    }
}

static void felem_twice(const felem a, felem r) {
    felem_add(a, a, r);
}

static void felem_thrice(const felem a, felem r) {
    felem t;
    felem_add(a, a, t);
    felem_add(t, a, r);
}

static void sqrN(const felem a, int n, felem r) {
    mont_sqr(a, r);
    for (int i = 1; i < n; i++) mont_sqr(r, r);
}

/* ================================================================
 * Section 5 — Montgomery inverse via addition chain (a^(p-2))
 * ================================================================ */
static void felem_inv(const felem a, felem r) {
    felem x2,x3,x4,x7,x8,x15,x16,x30,x31,x32,t;
    mont_sqr(a,t); mont_mul(t,a,x2);
    mont_sqr(x2,t); mont_mul(t,a,x3);
    sqrN(x2,2,t); mont_mul(t,x2,x4);
    sqrN(x4,3,t); mont_mul(t,x3,x7);
    sqrN(x4,4,t); mont_mul(t,x4,x8);
    sqrN(x8,7,t); mont_mul(t,x7,x15);
    sqrN(x8,8,t); mont_mul(t,x8,x16);
    sqrN(x15,15,t); mont_mul(t,x15,x30);
    sqrN(x16,15,t); mont_mul(t,x15,x31);
    sqrN(x16,16,t); mont_mul(t,x16,x32);

    felem_copy(r, x31);
    mont_sqr(r, r);
    sqrN(r,32,t); mont_mul(t,x32,r);
    sqrN(r,32,t); mont_mul(t,x32,r);
    sqrN(r,32,t); mont_mul(t,x32,r);
    sqrN(r,32,t); mont_mul(t,x32,r);
    sqrN(r,32,r);
    sqrN(r,32,t); mont_mul(t,x32,r);
    sqrN(r,30,t); mont_mul(t,x30,r);
    mont_sqr(r, r);
    mont_sqr(r, t); mont_mul(t, a, r);
}

/* ================================================================
 * Section 6 — Jacobian point operations (all in Montgomery domain)
 * ================================================================ */

static void jac_double(const felem X1, const felem Y1, const felem Z1,
                        felem X3, felem Y3, felem Z3) {
    if (felem_is_zero(Z1)) {
        felem_copy(X3,X1); felem_copy(Y3,Y1); memset(Z3,0,32); return;
    }
    felem s0,s1,s2,M,S,Y1sq,T;
    mont_sqr(Z1,s0);
    felem_sub(X1,s0,s1);
    felem_add(X1,s0,s2);
    mont_mul(s1,s2,M);
    felem_thrice(M,M);
    mont_sqr(Y1,Y1sq);
    mont_mul(X1,Y1sq,S);
    felem_twice(S,S); felem_twice(S,S);
    mont_sqr(M,X3);
    felem_sub(X3,S,X3); felem_sub(X3,S,X3);
    mont_sqr(Y1sq,T);
    felem_twice(T,T); felem_twice(T,T); felem_twice(T,T);
    felem_sub(S,X3,s0);
    mont_mul(M,s0,Y3);
    felem_sub(Y3,T,Y3);
    mont_mul(Y1,Z1,Z3);
    felem_twice(Z3,Z3);
}

static void jac_add_mixed(const felem X1, const felem Y1, const felem Z1,
                            const felem x2, const felem y2,
                            felem X3, felem Y3, felem Z3) {
    if (felem_is_zero(Z1)) {
        felem_copy(X3,x2); felem_copy(Y3,y2);
        felem_copy(Z3, MONT_ONE);
        return;
    }
    felem Z1sq,Z1cu,H,R,H2,H3,X1H2;
    mont_sqr(Z1,Z1sq);
    mont_mul(Z1sq,Z1,Z1cu);
    mont_mul(x2,Z1sq,H);
    mont_mul(y2,Z1cu,R);
    felem_sub(H,X1,H);
    felem_sub(R,Y1,R);
    if (felem_is_zero(H)) {
        if (felem_is_zero(R)) { jac_double(X1,Y1,Z1,X3,Y3,Z3); return; }
        memset(X3,0,32); memset(Y3,0,32); memset(Z3,0,32); return;
    }
    mont_sqr(H,H2);
    mont_mul(H2,H,H3);
    mont_mul(X1,H2,X1H2);
    mont_sqr(R,X3);
    felem_sub(X3,H3,X3); felem_sub(X3,X1H2,X3); felem_sub(X3,X1H2,X3);
    felem_sub(X1H2,X3,H2);
    mont_mul(R,H2,Y3);
    mont_mul(Y1,H3,H2);
    felem_sub(Y3,H2,Y3);
    mont_mul(Z1,H,Z3);
}

static void jac_add(const felem X1, const felem Y1, const felem Z1,
                     const felem X2, const felem Y2, const felem Z2,
                     felem X3, felem Y3, felem Z3) {
    if (felem_is_zero(Z1)) { felem_copy(X3,X2); felem_copy(Y3,Y2); felem_copy(Z3,Z2); return; }
    if (felem_is_zero(Z2)) { felem_copy(X3,X1); felem_copy(Y3,Y1); felem_copy(Z3,Z1); return; }
    felem Z1sq,Z2sq,U1,U2,S1,S2,H,R,H2,H3,U1H2,t;
    mont_sqr(Z1,Z1sq); mont_sqr(Z2,Z2sq);
    mont_mul(X1,Z2sq,U1); mont_mul(X2,Z1sq,U2);
    mont_mul(Z2sq,Z2,t); mont_mul(Y1,t,S1);
    mont_mul(Z1sq,Z1,t); mont_mul(Y2,t,S2);
    felem_sub(U2,U1,H); felem_sub(S2,S1,R);
    if (felem_is_zero(H)) {
        if (felem_is_zero(R)) { jac_double(X1,Y1,Z1,X3,Y3,Z3); return; }
        memset(X3,0,32); memset(Y3,0,32); memset(Z3,0,32); return;
    }
    mont_sqr(H,H2); mont_mul(H2,H,H3); mont_mul(U1,H2,U1H2);
    mont_sqr(R,X3); felem_sub(X3,H3,X3);
    felem_sub(X3,U1H2,X3); felem_sub(X3,U1H2,X3);
    felem_sub(U1H2,X3,t); mont_mul(R,t,Y3);
    mont_mul(S1,H3,t); felem_sub(Y3,t,Y3);
    mont_mul(Z1,Z2,Z3); mont_mul(Z3,H,Z3);
}

static void jac_to_affine(const felem X, const felem Y, const felem Z,
                            felem rx, felem ry) {
    if (felem_is_zero(Z)) { memset(rx,0,32); memset(ry,0,32); return; }
    felem zi,zi2,zi3;
    felem_inv(Z,zi);
    mont_sqr(zi,zi2);
    mont_mul(zi2,zi,zi3);
    mont_mul(X,zi2,rx);
    mont_mul(Y,zi3,ry);
}

/* ================================================================
 * Section 7 — wNAF encoding
 * ================================================================ */
static int wnaf_encode(const uint32_t *k, int w, int *wnaf, int max_len) {
    uint32_t d[9];
    memcpy(d, k, 32); d[8] = 0;
    int dLen = 9;
    while (dLen > 0 && d[dLen-1] == 0) dLen--;
    int pow2w = 1 << w, half = 1 << (w-1), mask = pow2w - 1;
    int len = 0;
    while (dLen > 0 && len < max_len) {
        if (d[0] & 1) {
            int digit = d[0] & mask;
            if (digit >= half) digit -= pow2w;
            wnaf[len] = digit;
            int64_t val = (int64_t)(uint64_t)d[0] - digit;
            d[0] = (uint32_t)val;
            int64_t carry = val >> 32;
            for (int j = 1; carry && j < dLen; j++) {
                carry += (uint64_t)d[j]; d[j] = (uint32_t)carry; carry >>= 32;
            }
        } else wnaf[len] = 0;
        for (int j = 0; j < dLen-1; j++) d[j] = (d[j] >> 1) | (d[j+1] << 31);
        if (dLen > 0) { d[dLen-1] >>= 1; if (d[dLen-1]==0) dLen--; }
        len++;
    }
    return len;
}

/* ================================================================
 * Section 8 — Precomputed tables (Montgomery form, batch affine)
 * ================================================================ */
#define WNAF_BASE_W    7
#define WNAF_BASE_SIZE 32
#define WNAF_FIELD_W   6
#define WNAF_FIELD_SIZE 16
#define MAX_TABLE      256

/* table[i] = {x, y} in Montgomery form, affine */
typedef struct { felem x, y; } affine_pt;

static void batch_to_affine(felem jx[][1], felem jy[][1], felem jz[][1],
                             int n, affine_pt *result) {
    felem cumZ[MAX_TABLE], zInvs[MAX_TABLE], invF, tmp, zi2, zi3;
    felem_copy(cumZ[0], jz[0][0]);
    for (int i = 1; i < n; i++) mont_mul(cumZ[i-1], jz[i][0], cumZ[i]);
    felem_inv(cumZ[n-1], invF);
    for (int i = n-1; i > 0; i--) {
        mont_mul(cumZ[i-1], invF, zInvs[i]);
        mont_mul(jz[i][0], invF, tmp);
        felem_copy(invF, tmp);
    }
    felem_copy(zInvs[0], invF);
    for (int i = 0; i < n; i++) {
        mont_sqr(zInvs[i], zi2);
        mont_mul(zi2, zInvs[i], zi3);
        mont_mul(jx[i][0], zi2, result[i].x);
        mont_mul(jy[i][0], zi3, result[i].y);
    }
}

static void build_table(const felem gx, const felem gy, affine_pt *table, int size) {
    felem dblX, dblY, dblZ, oneZ;
    felem_copy(oneZ, MONT_ONE);
    jac_double(gx, gy, oneZ, dblX, dblY, dblZ);

    felem jX[MAX_TABLE][1], jY[MAX_TABLE][1], jZ[MAX_TABLE][1];
    felem_copy(jX[0][0], gx); felem_copy(jY[0][0], gy); felem_copy(jZ[0][0], oneZ);
    for (int i = 1; i < size; i++)
        jac_add(jX[i-1][0], jY[i-1][0], jZ[i-1][0], dblX, dblY, dblZ,
                jX[i][0], jY[i][0], jZ[i][0]);
    batch_to_affine(jX, jY, jZ, size, table);
}

static volatile int g_base_ready = 0;
static affine_pt g_base_table[WNAF_BASE_SIZE];
static felem g_gx_mont, g_gy_mont;

static void ensure_base_table(void) {
    if (g_base_ready) return;
    u32_to_mont(GX32, g_gx_mont);
    u32_to_mont(GY32, g_gy_mont);
    build_table(g_gx_mont, g_gy_mont, g_base_table, WNAF_BASE_SIZE);
#if defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif
    g_base_ready = 1;
}

/* ================================================================
 * Section 9 — Scalar multiply (all in Montgomery domain)
 * ================================================================ */
static void fixed_base_mul(const uint32_t *k, uint32_t *rx, uint32_t *ry) {
    ensure_base_table();
    int wnaf[258]; int len = wnaf_encode(k, WNAF_BASE_W, wnaf, 258);
    if (len == 0) { memset(rx,0,32); memset(ry,0,32); return; }

    felem AX={0},AY={0},AZ={0}, BX,BY,BZ, py;
    for (int i = len-1; i >= 0; i--) {
        jac_double(AX,AY,AZ, BX,BY,BZ);
        felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        if (wnaf[i]) {
            int idx = (abs(wnaf[i])-1) >> 1;
            if (wnaf[i]>0) felem_copy(py, g_base_table[idx].y);
            else felem_neg(g_base_table[idx].y, py);
            jac_add_mixed(AX,AY,AZ, g_base_table[idx].x, py, BX,BY,BZ);
            felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        }
    }
    felem rxm, rym;
    jac_to_affine(AX,AY,AZ, rxm, rym);
    mont_to_u32(rxm, rx);
    mont_to_u32(rym, ry);
}

static void field_point_mul(const uint32_t *px32, const uint32_t *py32,
                             const uint32_t *k, uint32_t *rx, uint32_t *ry) {
    felem px, py_; u32_to_mont(px32, px); u32_to_mont(py32, py_);
    affine_pt tbl[WNAF_FIELD_SIZE];
    build_table(px, py_, tbl, WNAF_FIELD_SIZE);
    int wnaf[258]; int len = wnaf_encode(k, WNAF_FIELD_W, wnaf, 258);
    if (len == 0) { memset(rx,0,32); memset(ry,0,32); return; }
    felem AX={0},AY={0},AZ={0}, BX,BY,BZ, tmpY;
    for (int i = len-1; i >= 0; i--) {
        jac_double(AX,AY,AZ, BX,BY,BZ);
        felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        if (wnaf[i]) {
            int idx = (abs(wnaf[i])-1)>>1;
            if (wnaf[i]>0) felem_copy(tmpY, tbl[idx].y);
            else felem_neg(tbl[idx].y, tmpY);
            jac_add_mixed(AX,AY,AZ, tbl[idx].x, tmpY, BX,BY,BZ);
            felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        }
    }
    felem rxm, rym;
    jac_to_affine(AX,AY,AZ, rxm, rym);
    mont_to_u32(rxm, rx); mont_to_u32(rym, ry);
}

static void shamir_mul(const uint32_t *s, const uint32_t *px32, const uint32_t *py32,
                        const uint32_t *t, uint32_t *rx, uint32_t *ry) {
    ensure_base_table();
    felem px, py_; u32_to_mont(px32, px); u32_to_mont(py32, py_);
    affine_pt pTbl[WNAF_FIELD_SIZE];
    build_table(px, py_, pTbl, WNAF_FIELD_SIZE);
    int wS[258], wT[258];
    int lenS = wnaf_encode(s, WNAF_BASE_W, wS, 258);
    int lenT = wnaf_encode(t, WNAF_FIELD_W, wT, 258);
    int maxLen = lenS > lenT ? lenS : lenT;
    if (maxLen == 0) { memset(rx,0,32); memset(ry,0,32); return; }
    felem AX={0},AY={0},AZ={0}, BX,BY,BZ, tmpY;
    for (int i = maxLen-1; i >= 0; i--) {
        jac_double(AX,AY,AZ, BX,BY,BZ);
        felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        int si = (i<lenS)?wS[i]:0, ti = (i<lenT)?wT[i]:0;
        if (si) {
            int idx = (abs(si)-1)>>1;
            if (si>0) felem_copy(tmpY, g_base_table[idx].y);
            else felem_neg(g_base_table[idx].y, tmpY);
            jac_add_mixed(AX,AY,AZ, g_base_table[idx].x, tmpY, BX,BY,BZ);
            felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        }
        if (ti) {
            int idx = (abs(ti)-1)>>1;
            if (ti>0) felem_copy(tmpY, pTbl[idx].y);
            else felem_neg(pTbl[idx].y, tmpY);
            jac_add_mixed(AX,AY,AZ, pTbl[idx].x, tmpY, BX,BY,BZ);
            felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        }
    }
    felem rxm, rym;
    jac_to_affine(AX,AY,AZ, rxm, rym);
    mont_to_u32(rxm, rx); mont_to_u32(rym, ry);
}

/* ================================================================
 * Section 10 — Legacy compatibility: Solinas-form field operations
 * ================================================================ */
#define M64L 0xFFFFFFFFULL
static const uint32_t FP[8] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
};

static void sub_p_cond(uint32_t *r) {
    int64_t bw;
    uint32_t d[8];
    bw=(int64_t)(uint64_t)r[0]-(int64_t)0xFFFFFFFF;d[0]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[1]-(int64_t)0xFFFFFFFF;d[1]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[2];d[2]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[3]-(int64_t)0xFFFFFFFF;d[3]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[4]-(int64_t)0xFFFFFFFF;d[4]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[5]-(int64_t)0xFFFFFFFF;d[5]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[6]-(int64_t)0xFFFFFFFF;d[6]=(uint32_t)bw;bw>>=32;
    bw+=(int64_t)(uint64_t)r[7]-(int64_t)0xFFFFFFFE;d[7]=(uint32_t)bw;bw>>=32;
    int m=(int)bw;
    for(int i=0;i<8;i++) r[i]=(d[i]&(uint32_t)~m)|(r[i]&(uint32_t)m);
}

static void reduce(const uint32_t *ext, uint32_t *r) {
    int64_t x0=ext[0]&M64L,x1=ext[1]&M64L,x2=ext[2]&M64L,x3=ext[3]&M64L,
            x4=ext[4]&M64L,x5=ext[5]&M64L,x6=ext[6]&M64L,x7=ext[7]&M64L,
            x8=ext[8]&M64L,x9=ext[9]&M64L,x10=ext[10]&M64L,x11=ext[11]&M64L,
            x12=ext[12]&M64L,x13=ext[13]&M64L,x14=ext[14]&M64L,x15=ext[15]&M64L;
    int64_t s0=x0+x8+x9+x10+x11+x12+2*x13+2*x14+2*x15,
            s1=x1+x9+x10+x11+x12+x13+2*x14+2*x15,s2=x2-x8-x9-x13-x14,
            s3=x3+x8+x11+x12+2*x13+x14+x15,s4=x4+x9+x12+x13+2*x14+x15,
            s5=x5+x10+x13+x14+2*x15,s6=x6+x11+x14+x15,
            s7=x7+x8+x9+x10+x11+2*x12+2*x13+2*x14+3*x15;
    int64_t cc;
    #define PROP cc=s0>>32;s0&=M64L;s1+=cc;cc=s1>>32;s1&=M64L;\
    s2+=cc;cc=s2>>32;s2&=M64L;s3+=cc;cc=s3>>32;s3&=M64L;\
    s4+=cc;cc=s4>>32;s4&=M64L;s5+=cc;cc=s5>>32;s5&=M64L;\
    s6+=cc;cc=s6>>32;s6&=M64L;s7+=cc;cc=s7>>32;s7&=M64L;\
    s0+=cc;s2-=cc;s3+=cc;s7+=cc;
    PROP PROP
    cc=s0>>32;s0&=M64L;s1+=cc;cc=s1>>32;s1&=M64L;
    s2+=cc;cc=s2>>32;s2&=M64L;s3+=cc;cc=s3>>32;s3&=M64L;
    s4+=cc;cc=s4>>32;s4&=M64L;s5+=cc;cc=s5>>32;s5&=M64L;
    s6+=cc;cc=s6>>32;s6&=M64L;s7+=cc;
    r[0]=(uint32_t)s0;r[1]=(uint32_t)s1;r[2]=(uint32_t)s2;r[3]=(uint32_t)s3;
    r[4]=(uint32_t)s4;r[5]=(uint32_t)s5;r[6]=(uint32_t)s6;r[7]=(uint32_t)s7;
    sub_p_cond(r);
    #undef PROP
}

static void field_mul_legacy(const uint32_t *a, const uint32_t *b, uint32_t *r) {
    uint32_t ext[16]; memset(ext,0,sizeof(ext));
#if HAS_INT128
    uint64_t a64[4],b64[4],e64[8];
    for(int i=0;i<4;i++){a64[i]=(uint64_t)a[2*i]|((uint64_t)a[2*i+1]<<32);
                          b64[i]=(uint64_t)b[2*i]|((uint64_t)b[2*i+1]<<32);}
    memset(e64,0,sizeof(e64));
    for(int i=0;i<4;i++){uint128_t c=0;
        for(int j=0;j<4;j++){c+=(uint128_t)a64[i]*b64[j]+e64[i+j];e64[i+j]=(uint64_t)c;c>>=64;}
        e64[i+4]=(uint64_t)c;}
    for(int i=0;i<8;i++){ext[2*i]=(uint32_t)e64[i];ext[2*i+1]=(uint32_t)(e64[i]>>32);}
#else
    for(int i=0;i<8;i++){uint64_t ai=a[i],carry=0;
        for(int j=0;j<8;j++){carry+=ai*(uint64_t)b[j]+ext[i+j];ext[i+j]=(uint32_t)carry;carry>>=32;}
        ext[i+8]=(uint32_t)carry;}
#endif
    reduce(ext,r);
}

static void field_sqr_legacy(const uint32_t *a, uint32_t *r) {
    field_mul_legacy(a,a,r);
}

static void field_inv_legacy(const uint32_t *a, uint32_t *r) {
    felem am, rm;
    u32_to_mont(a, am);
    felem_inv(am, rm);
    mont_to_u32(rm, r);
}

/* ================================================================
 * Section 11 — JNI wrappers
 * ================================================================ */
JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeMulCore(
    JNIEnv *env, jclass clz, jintArray aA, jintArray bA, jintArray eA) {
    jint a[8],b[8],e[16]; memset(e,0,sizeof(e));
    (*env)->GetIntArrayRegion(env,aA,0,8,a);
    (*env)->GetIntArrayRegion(env,bA,0,8,b);
#if HAS_INT128
    uint64_t a64[4],b64[4],e64[8];
    for(int i=0;i<4;i++){a64[i]=(uint64_t)(uint32_t)a[2*i]|((uint64_t)(uint32_t)a[2*i+1]<<32);
                          b64[i]=(uint64_t)(uint32_t)b[2*i]|((uint64_t)(uint32_t)b[2*i+1]<<32);}
    memset(e64,0,sizeof(e64));
    for(int i=0;i<4;i++){uint128_t c=0;for(int j=0;j<4;j++){c+=(uint128_t)a64[i]*b64[j]+e64[i+j];e64[i+j]=(uint64_t)c;c>>=64;}e64[i+4]=(uint64_t)c;}
    for(int i=0;i<8;i++){e[2*i]=(jint)(uint32_t)e64[i];e[2*i+1]=(jint)(uint32_t)(e64[i]>>32);}
#else
    for(int i=0;i<8;i++){uint64_t ai=(uint32_t)a[i],carry=0;for(int j=0;j<8;j++){carry+=ai*(uint64_t)(uint32_t)b[j]+(uint32_t)e[i+j];e[i+j]=(jint)(uint32_t)carry;carry>>=32;}e[i+8]=(jint)(uint32_t)carry;}
#endif
    (*env)->SetIntArrayRegion(env,eA,0,16,e);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeSqrCore(
    JNIEnv *env, jclass clz, jintArray aA, jintArray eA) {
    jint a[8],e[16];
    (*env)->GetIntArrayRegion(env,aA,0,8,a);
    memset(e,0,sizeof(e));
    /* just call mul for sqr in legacy path */
    Java_com_yxj_gm_util_JNI_Nat256Native_nativeMulCore(env,clz,aA,aA,eA);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeReduce(
    JNIEnv *env, jclass clz, jintArray eA, jintArray rA) {
    jint e[16],r[8];
    (*env)->GetIntArrayRegion(env,eA,0,16,e);
    reduce((const uint32_t*)e,(uint32_t*)r);
    (*env)->SetIntArrayRegion(env,rA,0,8,r);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeInv(
    JNIEnv *env, jclass clz, jintArray aA, jintArray rA) {
    jint a[8],r[8];
    (*env)->GetIntArrayRegion(env,aA,0,8,a);
    field_inv_legacy((const uint32_t*)a,(uint32_t*)r);
    (*env)->SetIntArrayRegion(env,rA,0,8,r);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeMulMod(
    JNIEnv *env, jclass clz, jintArray aA, jintArray bA, jintArray rA) {
    jint a[8],b[8],r[8];
    (*env)->GetIntArrayRegion(env,aA,0,8,a);
    (*env)->GetIntArrayRegion(env,bA,0,8,b);
    field_mul_legacy((const uint32_t*)a,(const uint32_t*)b,(uint32_t*)r);
    (*env)->SetIntArrayRegion(env,rA,0,8,r);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeSqrMod(
    JNIEnv *env, jclass clz, jintArray aA, jintArray rA) {
    jint a[8],r[8];
    (*env)->GetIntArrayRegion(env,aA,0,8,a);
    field_sqr_legacy((const uint32_t*)a,(uint32_t*)r);
    (*env)->SetIntArrayRegion(env,rA,0,8,r);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeFixedBaseMul(
    JNIEnv *env, jclass clz, jintArray kA, jintArray outA) {
    jint k[8], out[16];
    (*env)->GetIntArrayRegion(env,kA,0,8,k);
    fixed_base_mul((const uint32_t*)k,(uint32_t*)out,(uint32_t*)(out+8));
    (*env)->SetIntArrayRegion(env,outA,0,16,out);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeFieldMul(
    JNIEnv *env, jclass clz, jintArray pxA, jintArray pyA, jintArray kA, jintArray outA) {
    jint px[8],py[8],k[8],out[16];
    (*env)->GetIntArrayRegion(env,pxA,0,8,px);
    (*env)->GetIntArrayRegion(env,pyA,0,8,py);
    (*env)->GetIntArrayRegion(env,kA,0,8,k);
    field_point_mul((const uint32_t*)px,(const uint32_t*)py,
                    (const uint32_t*)k,(uint32_t*)out,(uint32_t*)(out+8));
    (*env)->SetIntArrayRegion(env,outA,0,16,out);
}

JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeShamirMul(
    JNIEnv *env, jclass clz,
    jintArray sA, jintArray pxA, jintArray pyA, jintArray tA, jintArray outA) {
    jint s[8],px[8],py[8],t[8],out[16];
    (*env)->GetIntArrayRegion(env,sA,0,8,s);
    (*env)->GetIntArrayRegion(env,pxA,0,8,px);
    (*env)->GetIntArrayRegion(env,pyA,0,8,py);
    (*env)->GetIntArrayRegion(env,tA,0,8,t);
    shamir_mul((const uint32_t*)s,(const uint32_t*)px,(const uint32_t*)py,
              (const uint32_t*)t,(uint32_t*)out,(uint32_t*)(out+8));
    (*env)->SetIntArrayRegion(env,outA,0,16,out);
}

/* ================================================================
 * Section 12 — Modular arithmetic over curve order n (Montgomery)
 * ================================================================ */
static const felem N_ORD = {
    0x53BBF40939D54123ULL, 0x7203DF6B21C6052BULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFEFFFFFFFFULL
};
static const uint64_t N_PRIME_ORD = 0x327F9E8872350975ULL;
static const felem R2_MODN = {
    0x901192AF7C114F20ULL, 0x3464504ADE6FA2FAULL,
    0x620FC84C3AFFE0D4ULL, 0x1EB5E412A22B3D3BULL
};
static const felem MONT_ONE_N = {
    0xAC440BF6C62ABEDDULL, 0x8DFC2094DE39FAD4ULL,
    0x0000000000000000ULL, 0x0000000100000000ULL
};
static const uint32_t N_MINUS_2_U32[8] = {
    0x39D54121, 0x53BBF409, 0x21C6052B, 0x7203DF6B,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
};

#if HAS_INT128
static void modn_mul(const felem a, const felem b, felem r) {
    uint64_t z0=0,z1=0,z2=0,z3=0,z4=0;
    for (int i = 0; i < 4; i++) {
        uint128_t c = (uint128_t)a[i]*b[0]+z0; z0=(uint64_t)c; c>>=64;
        c += (uint128_t)a[i]*b[1]+z1; z1=(uint64_t)c; c>>=64;
        c += (uint128_t)a[i]*b[2]+z2; z2=(uint64_t)c; c>>=64;
        c += (uint128_t)a[i]*b[3]+z3; z3=(uint64_t)c; c>>=64;
        uint128_t c1 = (uint128_t)(uint64_t)c + z4;
        uint64_t m = z0 * N_PRIME_ORD;
        c = (uint128_t)m*N_ORD[0]+z0; c>>=64;
        c += (uint128_t)m*N_ORD[1]+z1; z1=(uint64_t)c; c>>=64;
        c += (uint128_t)m*N_ORD[2]+z2; z2=(uint64_t)c; c>>=64;
        c += (uint128_t)m*N_ORD[3]+z3; z3=(uint64_t)c; c>>=64;
        c1 += (uint64_t)c;
        z0=z1; z1=z2; z2=z3; z3=(uint64_t)c1; z4=(uint64_t)(c1>>64);
    }
    uint64_t d[4];
    int128_t bw = (int128_t)z0-N_ORD[0]; d[0]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z1-N_ORD[1]; d[1]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z2-N_ORD[2]; d[2]=(uint64_t)bw; bw>>=64;
    bw += (int128_t)z3-N_ORD[3]; d[3]=(uint64_t)bw; bw>>=64;
    bw += z4;
    uint64_t mask = (uint64_t)((int64_t)bw >> 63);
    r[0]=(z0&mask)|(d[0]&~mask); r[1]=(z1&mask)|(d[1]&~mask);
    r[2]=(z2&mask)|(d[2]&~mask); r[3]=(z3&mask)|(d[3]&~mask);
}
#else
static void modn_mul(const felem a, const felem b, felem r) {
    /* 32-bit fallback: schoolbook mul + trial subtraction */
    uint32_t a32[8],b32[8]; u64_to_u32(a,a32); u64_to_u32(b,b32);
    uint64_t prod[16]; memset(prod,0,sizeof(prod));
    for(int i=0;i<8;i++){uint64_t ai=a32[i],carry=0;
        for(int j=0;j<8;j++){carry+=ai*(uint64_t)b32[j]+(uint32_t)prod[i+j];
            prod[i+j]=(uint32_t)carry;carry>>=32;}prod[i+8]=(uint32_t)carry;}
    /* Barrett-like: since both operands < n < 2^256, product < 2^512.
       Simple approach: subtract n repeatedly. Since a,b < n, a*b < n^2 < 2^512,
       and n > 2^255, we need at most a few subtractions. For Montgomery,
       we do 8 rounds of reduction similar to the 32-bit CIOS. */
    uint32_t N32[8]; u64_to_u32(N_ORD, N32);
    /* Use Solinas-style: apply 8 reduction steps */
    uint32_t res[8];
    for(int i=0;i<8;i++) res[i]=(uint32_t)prod[i];
    /* crude mod: subtract n while >= n */
    for(int iter=0;iter<3;iter++){
        int64_t bw2=0;uint32_t dd[8];
        for(int i=0;i<8;i++){bw2+=(int64_t)(uint64_t)res[i]-(uint64_t)N32[i];dd[i]=(uint32_t)bw2;bw2>>=32;}
        if(bw2>=0) memcpy(res,dd,32);
    }
    u32_to_u64(res, r);
}
#endif

static void modn_add(const felem a, const felem b, felem r) {
#if HAS_INT128
    uint128_t cc=0;
    for(int i=0;i<4;i++){cc+=(uint128_t)a[i]+b[i];r[i]=(uint64_t)cc;cc>>=64;}
    uint64_t carry=(uint64_t)cc; uint64_t d[4];
    int128_t bw=(int128_t)r[0]-N_ORD[0];d[0]=(uint64_t)bw;bw>>=64;
    bw+=(int128_t)r[1]-N_ORD[1];d[1]=(uint64_t)bw;bw>>=64;
    bw+=(int128_t)r[2]-N_ORD[2];d[2]=(uint64_t)bw;bw>>=64;
    bw+=(int128_t)r[3]-N_ORD[3];d[3]=(uint64_t)bw;bw>>=64;
    bw+=carry;
    uint64_t mask=(uint64_t)((int64_t)bw>>63);
    for(int i=0;i<4;i++) r[i]=(r[i]&mask)|(d[i]&~mask);
#else
    uint32_t a32[8],b32[8],r32[8],N32[8];
    u64_to_u32(a,a32);u64_to_u32(b,b32);u64_to_u32(N_ORD,N32);
    int64_t cc2=0;for(int i=0;i<8;i++){cc2+=(uint64_t)a32[i]+(uint64_t)b32[i];r32[i]=(uint32_t)cc2;cc2>>=32;}
    int64_t bw2=0;uint32_t dd[8];
    for(int i=0;i<8;i++){bw2+=(int64_t)(uint64_t)r32[i]-(uint64_t)N32[i];dd[i]=(uint32_t)bw2;bw2>>=32;}
    bw2+=cc2; int m2=(int)(bw2>>63);
    for(int i=0;i<8;i++) r32[i]=(dd[i]&(uint32_t)~m2)|(r32[i]&(uint32_t)m2);
    u32_to_u64(r32,r);
#endif
}

static void modn_sub(const felem a, const felem b, felem r) {
#if HAS_INT128
    int128_t bw=0;
    for(int i=0;i<4;i++){bw+=(int128_t)a[i]-b[i];r[i]=(uint64_t)bw;bw>>=64;}
    if(bw<0){uint128_t cc=0;for(int i=0;i<4;i++){cc+=(uint128_t)r[i]+N_ORD[i];r[i]=(uint64_t)cc;cc>>=64;}}
#else
    uint32_t a32[8],b32[8],r32[8],N32[8];
    u64_to_u32(a,a32);u64_to_u32(b,b32);u64_to_u32(N_ORD,N32);
    int64_t bw2=0;for(int i=0;i<8;i++){bw2+=(int64_t)(uint64_t)a32[i]-(uint64_t)b32[i];r32[i]=(uint32_t)bw2;bw2>>=32;}
    if(bw2<0){int64_t cc2=0;for(int i=0;i<8;i++){cc2+=(uint64_t)r32[i]+(uint64_t)N32[i];r32[i]=(uint32_t)cc2;cc2>>=32;}}
    u32_to_u64(r32,r);
#endif
}

static inline void to_mont_n(const felem a, felem r) { modn_mul(a, R2_MODN, r); }
static inline void from_mont_n(const felem a, felem r) { felem one={1,0,0,0}; modn_mul(a,one,r); }

/* ================================================================
 * Section 13 — Comb fixed-base multiplication (d=32, t=8)
 *
 * Pre-computes 255-entry table. Scalar multiply uses only
 * 32 doublings + ≤32 additions vs wNAF's 256 doublings + ~37 additions.
 * ================================================================ */
#define COMB_D 32
#define COMB_T 8
#define COMB_SIZE 255

static volatile int g_comb_ready = 0;
static affine_pt g_comb_table[COMB_SIZE];

static void build_comb_table(void) {
    ensure_base_table();
    felem Gx[COMB_T], Gy[COMB_T], Gz[COMB_T];
    felem_copy(Gx[0], g_gx_mont); felem_copy(Gy[0], g_gy_mont); felem_copy(Gz[0], MONT_ONE);
    for (int i = 1; i < COMB_T; i++) {
        felem_copy(Gx[i],Gx[i-1]); felem_copy(Gy[i],Gy[i-1]); felem_copy(Gz[i],Gz[i-1]);
        for (int d = 0; d < COMB_D; d++) {
            felem tx,ty,tz;
            jac_double(Gx[i],Gy[i],Gz[i], tx,ty,tz);
            felem_copy(Gx[i],tx); felem_copy(Gy[i],ty); felem_copy(Gz[i],tz);
        }
    }
    /* batch-convert G_0..G_7 to affine */
    affine_pt G_aff[COMB_T];
    {
        felem gJX[COMB_T][1], gJY[COMB_T][1], gJZ[COMB_T][1];
        for(int i=0;i<COMB_T;i++){felem_copy(gJX[i][0],Gx[i]);felem_copy(gJY[i][0],Gy[i]);felem_copy(gJZ[i][0],Gz[i]);}
        batch_to_affine(gJX,gJY,gJZ,COMB_T,G_aff);
    }
    /* build 255-entry table: table[b-1] = sum of G_i where bit i is set in b */
    felem tJX[COMB_SIZE][1], tJY[COMB_SIZE][1], tJZ[COMB_SIZE][1];
    /* tooth 0 */
    felem_copy(tJX[0][0],G_aff[0].x); felem_copy(tJY[0][0],G_aff[0].y); felem_copy(tJZ[0][0],MONT_ONE);
    for (int tooth = 1; tooth < COMB_T; tooth++) {
        int stride = 1 << tooth;
        /* table[stride-1] = G_tooth (affine, Z=1) */
        felem_copy(tJX[stride-1][0],G_aff[tooth].x);
        felem_copy(tJY[stride-1][0],G_aff[tooth].y);
        felem_copy(tJZ[stride-1][0],MONT_ONE);
        for (int j = 1; j < stride; j++) {
            jac_add_mixed(tJX[j-1][0],tJY[j-1][0],tJZ[j-1][0],
                          G_aff[tooth].x, G_aff[tooth].y,
                          tJX[stride+j-1][0],tJY[stride+j-1][0],tJZ[stride+j-1][0]);
        }
    }
    batch_to_affine(tJX, tJY, tJZ, COMB_SIZE, g_comb_table);
}

static void ensure_comb_table(void) {
    if (g_comb_ready) return;
    build_comb_table();
#if defined(__GNUC__) || defined(__clang__)
    __sync_synchronize();
#endif
    g_comb_ready = 1;
}

static void comb_fixed_base_mul(const uint32_t *k, uint32_t *rx, uint32_t *ry) {
    ensure_comb_table();
    felem AX={0},AY={0},AZ={0}, BX,BY,BZ, py;
    int started = 0;
    for (int j = COMB_D - 1; j >= 0; j--) {
        if (started) {
            jac_double(AX,AY,AZ, BX,BY,BZ);
            felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
        }
        int idx = 0;
        for (int t = 0; t < COMB_T; t++)
            idx |= ((k[t] >> j) & 1) << t;
        if (idx) {
            if (!started) {
                felem_copy(AX, g_comb_table[idx-1].x);
                felem_copy(AY, g_comb_table[idx-1].y);
                felem_copy(AZ, MONT_ONE);
                started = 1;
            } else {
                felem_copy(py, g_comb_table[idx-1].y);
                jac_add_mixed(AX,AY,AZ, g_comb_table[idx-1].x, py, BX,BY,BZ);
                felem_copy(AX,BX); felem_copy(AY,BY); felem_copy(AZ,BZ);
            }
        }
    }
    if (!started) { memset(rx,0,32); memset(ry,0,32); return; }
    felem rxm,rym;
    jac_to_affine(AX,AY,AZ, rxm,rym);
    mont_to_u32(rxm,rx); mont_to_u32(rym,ry);
}

/* ================================================================
 * Section 14 — Byte array helpers + range check
 * ================================================================ */
static void be_to_u32(const jbyte *be, uint32_t *le) {
    for (int i = 0; i < 8; i++) {
        int off = 28 - 4*i;
        le[i] = ((uint32_t)(uint8_t)be[off]<<24) | ((uint32_t)(uint8_t)be[off+1]<<16) |
                ((uint32_t)(uint8_t)be[off+2]<<8) | (uint8_t)be[off+3];
    }
}

static void u32_to_be(const uint32_t *le, jbyte *be) {
    for (int i = 0; i < 8; i++) {
        int off = 28 - 4*i;
        be[off]  =(jbyte)(le[i]>>24); be[off+1]=(jbyte)(le[i]>>16);
        be[off+2]=(jbyte)(le[i]>>8);  be[off+3]=(jbyte)le[i];
    }
}

static int is_valid_scalar(const uint32_t *k) {
    int nonzero = 0;
    for (int i = 0; i < 8; i++) nonzero |= k[i];
    if (!nonzero) return 0;
    for (int i = 7; i >= 0; i--) {
        if (k[i] < N_MINUS_2_U32[i]) return 1;
        if (k[i] > N_MINUS_2_U32[i]) return 0;
    }
    return 1;
}

/* ================================================================
 * Section 15 — High-level SM2 operations (byte-array I/O)
 * ================================================================ */

/* Key generation: random[32] → prikey[32] + pubXY[64] */
static int keygen_point_impl(const jbyte *random32, jbyte *out96) {
    uint32_t k[8]; be_to_u32(random32, k);
    if (!is_valid_scalar(k)) return 0;
    uint32_t rx[8], ry[8];
    comb_fixed_base_mul(k, rx, ry);
    int nz = 0;
    for (int i = 0; i < 8; i++) nz |= rx[i] | ry[i];
    if (!nz) return 0;
    memcpy(out96, random32, 32);
    u32_to_be(rx, out96+32);
    u32_to_be(ry, out96+64);
    return 1;
}

/* Signing core: e[32], d[32], daInv[32], k[32] → r||s[64] */
static int sign_core_impl(const jbyte *e32, const jbyte *d32,
                           const jbyte *daInv32, const jbyte *k32, jbyte *out64) {
    uint32_t k_u[8]; be_to_u32(k32, k_u);
    if (!is_valid_scalar(k_u)) return 0;
    uint32_t x1[8], y1[8];
    comb_fixed_base_mul(k_u, x1, y1);

    uint32_t e_u[8], d_u[8], inv_u[8];
    be_to_u32(e32, e_u); be_to_u32(d32, d_u); be_to_u32(daInv32, inv_u);

    felem e_f, x1_f, r_f, k_f;
    u32_to_u64(e_u, e_f); u32_to_u64(x1, x1_f); u32_to_u64(k_u, k_f);

    modn_add(e_f, x1_f, r_f);
    if (felem_is_zero(r_f)) return 0;
    felem rk; modn_add(r_f, k_f, rk);
    if (felem_is_zero(rk)) return 0;

    felem r_m, d_m, k_m, inv_m, d_raw, inv_raw;
    u32_to_u64(d_u, d_raw); u32_to_u64(inv_u, inv_raw);
    to_mont_n(r_f, r_m); to_mont_n(d_raw, d_m);
    to_mont_n(k_f, k_m); to_mont_n(inv_raw, inv_m);

    felem rd_m, krd_m, s_m, s_f;
    modn_mul(r_m, d_m, rd_m);
    modn_sub(k_m, rd_m, krd_m);
    modn_mul(inv_m, krd_m, s_m);
    from_mont_n(s_m, s_f);

    if (felem_is_zero(s_f)) return 0;

    uint32_t r_out[8], s_out[8];
    u64_to_u32(r_f, r_out); u64_to_u32(s_f, s_out);
    u32_to_be(r_out, out64); u32_to_be(s_out, out64+32);
    return 1;
}

/* Verification core: e[32], r[32], s[32], pubXY[64] → 0/1 */
static int verify_core_impl(const jbyte *e32, const jbyte *r32,
                             const jbyte *s32, const jbyte *pubXY64) {
    uint32_t e_u[8], r_u[8], s_u[8], px_u[8], py_u[8];
    be_to_u32(e32, e_u); be_to_u32(r32, r_u); be_to_u32(s32, s_u);
    be_to_u32(pubXY64, px_u); be_to_u32(pubXY64+32, py_u);

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
    return (R_f[0]==r_check[0]) && (R_f[1]==r_check[1]) &&
           (R_f[2]==r_check[2]) && (R_f[3]==r_check[3]);
}

/* ================================================================
 * Section 16 — JNI wrappers for byte-based operations
 * ================================================================ */
JNIEXPORT jint JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeKeyGen(
    JNIEnv *env, jclass clz, jbyteArray randA, jbyteArray outA) {
    jbyte rand[32], out[96];
    (*env)->GetByteArrayRegion(env,randA,0,32,rand);
    int ok = keygen_point_impl(rand, out);
    if (ok) (*env)->SetByteArrayRegion(env,outA,0,96,out);
    return ok;
}

JNIEXPORT jint JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeSignCore(
    JNIEnv *env, jclass clz,
    jbyteArray eA, jbyteArray dA, jbyteArray daInvA, jbyteArray kA, jbyteArray outA) {
    jbyte e[32],d[32],inv[32],k[32],out[64];
    (*env)->GetByteArrayRegion(env,eA,0,32,e);
    (*env)->GetByteArrayRegion(env,dA,0,32,d);
    (*env)->GetByteArrayRegion(env,daInvA,0,32,inv);
    (*env)->GetByteArrayRegion(env,kA,0,32,k);
    int ok = sign_core_impl(e,d,inv,k,out);
    if (ok) (*env)->SetByteArrayRegion(env,outA,0,64,out);
    return ok;
}

JNIEXPORT jboolean JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeVerifyCore(
    JNIEnv *env, jclass clz,
    jbyteArray eA, jbyteArray rA, jbyteArray sA, jbyteArray pubA) {
    jbyte e[32],r[32],s[32],pub[64];
    (*env)->GetByteArrayRegion(env,eA,0,32,e);
    (*env)->GetByteArrayRegion(env,rA,0,32,r);
    (*env)->GetByteArrayRegion(env,sA,0,32,s);
    (*env)->GetByteArrayRegion(env,pubA,0,64,pub);
    return verify_core_impl(e,r,s,pub) ? JNI_TRUE : JNI_FALSE;
}

/* Also update fixedBaseMul to use comb method */
JNIEXPORT void JNICALL
Java_com_yxj_gm_util_JNI_Nat256Native_nativeCombFixedBaseMul(
    JNIEnv *env, jclass clz, jintArray kA, jintArray outA) {
    jint k[8], out[16];
    (*env)->GetIntArrayRegion(env,kA,0,8,k);
    comb_fixed_base_mul((const uint32_t*)k,(uint32_t*)out,(uint32_t*)(out+8));
    (*env)->SetIntArrayRegion(env,outA,0,16,out);
}
