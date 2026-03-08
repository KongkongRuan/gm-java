package com.yxj.gm;

import com.yxj.gm.util.JNI.Nat256Native;
import com.yxj.gm.util.SM2P256V1Field;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * Nat256Native 和 SM2P256V1Field 的单元测试。
 */
public class Nat256NativeTest {

    @Test
    public void testNativeMulCoreDirect() {
        if (!Nat256Native.isAvailable()) {
            System.out.println("Nat256Native not available, skip native test");
            return;
        }
        int[] a = {1, 0, 0, 0, 0, 0, 0, 0};
        int[] b = {2, 0, 0, 0, 0, 0, 0, 0};
        int[] ext = new int[16];
        Nat256Native.nativeMulCore(a, b, ext);
        assertEquals(2, ext[0]);
        assertEquals(0, ext[1]);
    }

    @Test
    public void testSM2FieldMulWithNative() {
        int[] a = new int[8];
        int[] b = new int[8];
        int[] r = new int[8];
        int[] ext = new int[16];

        // a = 3, b = 5 => r = 15 mod p
        a[0] = 3;
        b[0] = 5;
        Arrays.fill(ext, 0);
        SM2P256V1Field.mul(a, b, r, ext);
        assertEquals(15, r[0]);
        for (int i = 1; i < 8; i++) assertEquals(0, r[i]);
    }

    @Test
    public void benchmarkInv() {
        if (!Nat256Native.isAvailable()) return;
        int[] a = new int[8];
        int[] r = new int[8];
        java.util.Random rand = new java.util.Random(42);
        for (int i = 0; i < 8; i++) a[i] = rand.nextInt();
        if (SM2P256V1Field.isZero(a)) a[0] = 1;
        int warmup = 1000, runs = 10000;
        for (int i = 0; i < warmup; i++) SM2P256V1Field.inv(a, r);
        long t0 = System.nanoTime();
        for (int i = 0; i < runs; i++) SM2P256V1Field.inv(a, r);
        double us = (System.nanoTime() - t0) / 1000.0 / runs;
        System.out.println("SM2P256V1Field.inv: " + String.format("%.2f", us) + " us/call (" + runs + " runs)");
    }

    @Test
    public void benchmarkMul() {
        if (!Nat256Native.isAvailable()) {
            System.out.println("Nat256Native not available, skip benchmark");
            return;
        }
        int[] a = new int[8];
        int[] b = new int[8];
        int[] r = new int[8];
        int[] ext = new int[16];
        java.util.Random rand = new java.util.Random(42);
        for (int i = 0; i < 8; i++) {
            a[i] = rand.nextInt();
            b[i] = rand.nextInt();
        }
        int warmup = 10000;
        int runs = 500000;
        for (int i = 0; i < warmup; i++) SM2P256V1Field.mul(a, b, r, ext);
        long t0 = System.nanoTime();
        for (int i = 0; i < runs; i++) SM2P256V1Field.mul(a, b, r, ext);
        long t1 = System.nanoTime();
        double us = (t1 - t0) / 1000.0 / runs;
        System.out.println("SM2P256V1Field.mul: " + String.format("%.3f", us) + " us/call (" + runs + " runs)");
    }

    @Test
    public void testSM2FieldInv() {
        int[] a = new int[8];
        int[] r = new int[8];
        java.util.Random rand = new java.util.Random(999);
        for (int i = 0; i < 8; i++) a[i] = rand.nextInt();
        if (SM2P256V1Field.isZero(a)) a[0] = 1;
        SM2P256V1Field.inv(a, r);
        int[] ext = new int[16];
        int[] prod = new int[8];
        SM2P256V1Field.mul(a, r, prod, ext);
        assertEquals("a * inv(a) should be 1", 1, prod[0]);
        for (int i = 1; i < 8; i++) assertEquals(0, prod[i]);
    }

    @Test
    public void testSM2FieldSqrVsMul() {
        int[] a = new int[8];
        int[] rSqr = new int[8];
        int[] rMul = new int[8];
        int[] ext = new int[16];
        java.util.Random rand = new java.util.Random(123);
        for (int i = 0; i < 8; i++) a[i] = rand.nextInt();
        SM2P256V1Field.sqr(a, rSqr, ext);
        Arrays.fill(ext, 0);
        SM2P256V1Field.mul(a, a, rMul, ext);
        assertArrayEquals("sqr(a) == mul(a,a)", rSqr, rMul);
    }

    @Test
    public void testSM2FieldMulVsBigInteger() {
        BigInteger p = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16);
        for (int trial = 0; trial < 20; trial++) {
            BigInteger va = new BigInteger(256, new java.util.Random(trial));
            BigInteger vb = new BigInteger(256, new java.util.Random(trial + 1000));
            va = va.mod(p);
            vb = vb.mod(p);
            BigInteger expected = va.multiply(vb).mod(p);

            int[] a = fromBigInteger(va);
            int[] b = fromBigInteger(vb);
            int[] r = new int[8];
            int[] ext = new int[16];
            SM2P256V1Field.mul(a, b, r, ext);

            BigInteger actual = toBigInteger(r);
            assertEquals("trial=" + trial, expected, actual);
        }
    }

    private static int[] fromBigInteger(BigInteger x) {
        int[] r = new int[8];
        for (int i = 0; i < 8; i++) {
            r[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return r;
    }

    private static BigInteger toBigInteger(int[] a) {
        byte[] b = new byte[33];
        for (int i = 0; i < 8; i++) {
            int v = a[i];
            int off = 29 - 4 * i;
            b[off] = (byte) (v >>> 24);
            b[off + 1] = (byte) (v >>> 16);
            b[off + 2] = (byte) (v >>> 8);
            b[off + 3] = (byte) v;
        }
        b[0] = 0;
        return new BigInteger(b);
    }
}
