package com.yxj.gm;

import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.JNI.Nat256Native;
import com.yxj.gm.util.SM2P256V1Field;
import com.yxj.gm.util.SM2Util;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;

/**
 * Nat256Native 和 SM2P256V1Field 的单元测试。
 */
public class Nat256NativeTest {

    private static final byte[] SM2_DEFAULT_ID = "1234567812345678".getBytes();
    private static final byte[] SM2_MESSAGE = "SM2 verify validation".getBytes();
    private static final SM2Signature SM2_SIGNER = new SM2Signature();
    private static final byte[] SM2_PRIVATE_KEY;
    private static final byte[] SM2_PUBLIC_KEY;
    private static final byte[] SM2_SIGNATURE;

    static {
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        SM2_PRIVATE_KEY = keyPair.getPrivate().getEncoded();
        SM2_PUBLIC_KEY = keyPair.getPublic().getEncoded();
        SM2_SIGNATURE = SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY);
    }

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

    @Test
    public void testSm2GeneratedSignatureVerifiesThroughEveryEntryPoint() {
        assertTrue(SM2_SIGNER.verify(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));
        assertTrue(SM2_SIGNER.verifyInt(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));
        assertTrue(SM2_SIGNER.verifyFull(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));
        assertArrayEquals(new boolean[]{true}, SM2_SIGNER.verifyBatch(
                new byte[][]{SM2_MESSAGE}, new byte[][]{SM2_SIGNATURE},
                new byte[][]{SM2_PUBLIC_KEY}, SM2_DEFAULT_ID));
    }

    @Test
    public void testSm2FixedRawSignatureVector() {
        byte[] pub = Hex.decode("ccb5b5f46e876c5e3ab8bb47f6f8adab52facd3778e19c1644c05bdced772a516f10683a0202fe6cc1fbeaf45933f8afbd8cd7f765acb02185975453e9093bc3");
        byte[] sig = Hex.decode("112f12ea7474e00be1154febc4bc252a3f32c50becc0734a7a86b814251d67145f57276a3941a91f7b3eb8b7a3404b32af39e0a5e50fc14b2f89606dc13cecf1");

        assertTrue(SM2_SIGNER.verify(SM2_MESSAGE, SM2_DEFAULT_ID, sig, pub));
    }

    @Test
    public void testSm2VerifyRejectsNullAndWrongLengthInputs() {
        assertAllSm2VerifyVariantsFalse(null, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, null, SM2_PUBLIC_KEY);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, new byte[0], SM2_PUBLIC_KEY);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, new byte[63], SM2_PUBLIC_KEY);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, new byte[65], SM2_PUBLIC_KEY);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, null);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, new byte[0]);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, new byte[63]);
        assertAllSm2VerifyVariantsFalse(SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, new byte[65]);
        assertAllSm2VerifyVariantsFalse(
                SM2_MESSAGE, new byte[8192], SM2_SIGNATURE, SM2_PUBLIC_KEY);

        assertArrayEquals(new boolean[0],
                SM2_SIGNER.verifyBatch(null, null, null, SM2_DEFAULT_ID));
        assertArrayEquals(new boolean[]{false}, SM2_SIGNER.verifyBatch(
                new byte[][]{SM2_MESSAGE}, null,
                new byte[][]{SM2_PUBLIC_KEY}, SM2_DEFAULT_ID));
        assertArrayEquals(new boolean[]{false}, SM2_SIGNER.verifyBatch(
                new byte[][]{SM2_MESSAGE}, new byte[0][],
                new byte[][]{SM2_PUBLIC_KEY}, SM2_DEFAULT_ID));
    }

    @Test
    public void testSm2RejectsNonCanonicalAndOffCurvePublicKeys() {
        byte[] zeroPoint = new byte[64];
        byte[] nonCanonicalX = SM2_PUBLIC_KEY.clone();
        byte[] fieldPrime = SM2Util.toFixedBytes(SM2Constant.getBigP(), 32);
        System.arraycopy(fieldPrime, 0, nonCanonicalX, 0, 32);

        assertAllSm2VerifyVariantsFalse(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, zeroPoint);
        assertAllSm2VerifyVariantsFalse(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, nonCanonicalX);

        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, zeroPoint));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, nonCanonicalX));
    }

    @Test
    public void testSm2AcceptsMaximumEncodableIdLength() {
        byte[] maxId = new byte[8191];
        for (int i = 0; i < maxId.length; i++) {
            maxId[i] = (byte) i;
        }
        byte[] sig = SM2_SIGNER.signature(
                SM2_MESSAGE, maxId, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY);

        assertTrue(SM2_SIGNER.verify(SM2_MESSAGE, maxId, sig, SM2_PUBLIC_KEY));
    }

    @Test
    public void testSm2BatchHandlesEmptyMessagesAndMixedValidity() {
        byte[] emptyMessage = new byte[0];
        byte[] emptySignature = SM2_SIGNER.signature(
                emptyMessage, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY);

        assertArrayEquals(new boolean[]{true, true}, SM2_SIGNER.verifyBatch(
                new byte[][]{emptyMessage, emptyMessage},
                new byte[][]{emptySignature, emptySignature},
                new byte[][]{SM2_PUBLIC_KEY, SM2_PUBLIC_KEY},
                SM2_DEFAULT_ID));

        assertArrayEquals(new boolean[]{true, false, true}, SM2_SIGNER.verifyBatch(
                new byte[][]{emptyMessage, SM2_MESSAGE, SM2_MESSAGE},
                new byte[][]{emptySignature, new byte[64], SM2_SIGNATURE},
                new byte[][]{SM2_PUBLIC_KEY, SM2_PUBLIC_KEY, SM2_PUBLIC_KEY},
                SM2_DEFAULT_ID));
    }

    @Test
    public void testSm2SigningRejectsInvalidInputs() {
        byte[] tooLongId = new byte[8192];
        byte[] one = SM2Util.toFixedBytes(BigInteger.ONE, 32);
        byte[] nMinusTwo = SM2Util.toFixedBytes(
                SM2Constant.getBigN().subtract(BigInteger.valueOf(2)), 32);
        byte[] nMinusOne = SM2Util.toFixedBytes(
                SM2Constant.getBigN().subtract(BigInteger.ONE), 32);
        byte[] order = SM2Util.toFixedBytes(SM2Constant.getBigN(), 32);
        byte[] orderPlusOne = SM2Util.toFixedBytes(
                SM2Constant.getBigN().add(BigInteger.ONE), 32);

        assertSigningKeyBoundaryAccepted(one);
        assertSigningKeyBoundaryAccepted(nMinusTwo);

        assertIllegalArgument(() -> SM2_SIGNER.signature(
                null, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, tooLongId, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, tooLongId, SM2_PRIVATE_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, null, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, new byte[31], SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, new byte[33], SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, new byte[32], SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, nMinusOne, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, order, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, orderPlusOne, SM2_PUBLIC_KEY));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, null));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, new byte[63]));
        assertIllegalArgument(() -> SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, SM2_PRIVATE_KEY, new byte[65]));
    }

    @Test
    public void testSm2VerifyRejectsOutOfRangeSignatureComponents() {
        byte[] zero = new byte[32];
        byte[] order = SM2Util.toFixedBytes(SM2Constant.getBigN(), 32);
        byte[] orderPlusOne = SM2Util.toFixedBytes(
                SM2Constant.getBigN().add(BigInteger.ONE), 32);

        assertSm2ComponentRejected(0, zero);
        assertSm2ComponentRejected(32, zero);
        assertSm2ComponentRejected(0, order);
        assertSm2ComponentRejected(32, order);
        assertSm2ComponentRejected(0, orderPlusOne);
        assertSm2ComponentRejected(32, orderPlusOne);
    }

    @Test
    public void testSm2JavaFallbackUsesTheSameValidationRules() throws Exception {
        Field available = Nat256Native.class.getDeclaredField("available");
        available.setAccessible(true);
        boolean original = available.getBoolean(null);
        try {
            available.setBoolean(null, false);
            assertTrue(SM2_SIGNER.verify(
                    SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));
            assertTrue(SM2_SIGNER.verifyInt(
                    SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));
            assertTrue(SM2_SIGNER.verifyFull(
                    SM2_MESSAGE, SM2_DEFAULT_ID, SM2_SIGNATURE, SM2_PUBLIC_KEY));

            byte[] order = SM2Util.toFixedBytes(SM2Constant.getBigN(), 32);
            assertAllSm2VerifyVariantsFalse(
                    SM2_MESSAGE, SM2_DEFAULT_ID,
                    replaceSm2Component(SM2_SIGNATURE, 0, order), SM2_PUBLIC_KEY);
            assertAllSm2VerifyVariantsFalse(
                    SM2_MESSAGE, SM2_DEFAULT_ID, new byte[63], SM2_PUBLIC_KEY);
        } finally {
            available.setBoolean(null, original);
        }
    }

    @Test
    public void testSm2ZaCacheTracksCallerArrayMutations() {
        byte[] mutableId = SM2_DEFAULT_ID.clone();
        byte[] mutablePub = SM2_PUBLIC_KEY.clone();
        byte[] sig = SM2_SIGNER.signature(
                SM2_MESSAGE, mutableId, SM2_PRIVATE_KEY, mutablePub);
        assertTrue(SM2_SIGNER.verify(SM2_MESSAGE, mutableId, sig, mutablePub));

        mutableId[0] ^= 1;
        assertFalse(SM2_SIGNER.verify(SM2_MESSAGE, mutableId, sig, mutablePub));
        mutableId[0] ^= 1;
        assertTrue(SM2_SIGNER.verify(SM2_MESSAGE, mutableId, sig, mutablePub));

        mutablePub[0] ^= 1;
        assertFalse(SM2_SIGNER.verify(SM2_MESSAGE, mutableId, sig, mutablePub));
        mutablePub[0] ^= 1;
        assertTrue(SM2_SIGNER.verify(SM2_MESSAGE, mutableId, sig, mutablePub));
    }

    @Test
    public void testSm2ZaCacheIsThreadLocal() throws Exception {
        byte[] secondId = "8765432187654321".getBytes();
        byte[] secondSig = SM2_SIGNER.signature(
                SM2_MESSAGE, secondId, SM2_PRIVATE_KEY, SM2_PUBLIC_KEY);
        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();

        Thread first = sm2VerifierThread(
                start, failure, SM2_DEFAULT_ID, SM2_SIGNATURE);
        Thread second = sm2VerifierThread(start, failure, secondId, secondSig);
        first.start();
        second.start();
        start.countDown();
        first.join();
        second.join();

        if (failure.get() != null) {
            throw new AssertionError(failure.get());
        }
    }

    private static Thread sm2VerifierThread(CountDownLatch start,
                                            AtomicReference<Throwable> failure,
                                            byte[] id, byte[] signature) {
        return new Thread(() -> {
            try {
                start.await();
                for (int i = 0; i < 20; i++) {
                    assertTrue(SM2_SIGNER.verify(
                            SM2_MESSAGE, id, signature, SM2_PUBLIC_KEY));
                }
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            }
        });
    }

    private static void assertSm2ComponentRejected(int offset, byte[] value) {
        assertAllSm2VerifyVariantsFalse(
                SM2_MESSAGE, SM2_DEFAULT_ID,
                replaceSm2Component(SM2_SIGNATURE, offset, value), SM2_PUBLIC_KEY);
    }

    private static void assertSigningKeyBoundaryAccepted(byte[] privateKey) {
        byte[] publicKey = SM2Util.generatePubKeyByPriKey(privateKey);
        byte[] signature = SM2_SIGNER.signature(
                SM2_MESSAGE, SM2_DEFAULT_ID, privateKey, publicKey);
        assertTrue(SM2_SIGNER.verify(
                SM2_MESSAGE, SM2_DEFAULT_ID, signature, publicKey));
    }

    private static byte[] replaceSm2Component(byte[] source, int offset, byte[] value) {
        byte[] result = source.clone();
        System.arraycopy(value, 0, result, offset, 32);
        return result;
    }

    private static void assertAllSm2VerifyVariantsFalse(byte[] message, byte[] id,
                                                        byte[] signature, byte[] publicKey) {
        assertFalse(SM2_SIGNER.verify(message, id, signature, publicKey));
        assertFalse(SM2_SIGNER.verifyInt(message, id, signature, publicKey));
        assertFalse(SM2_SIGNER.verifyFull(message, id, signature, publicKey));
        assertArrayEquals(new boolean[]{false}, SM2_SIGNER.verifyBatch(
                new byte[][]{message}, new byte[][]{signature},
                new byte[][]{publicKey}, id));
    }

    private static void assertIllegalArgument(Runnable operation) {
        try {
            operation.run();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // Expected.
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
