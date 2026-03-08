package com.yxj.gm;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.JNI.Nat256Native;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;

public class QuickCorrectnessTest {
    public static void main(String[] args) throws Exception {
        System.out.println("Nat256Native available: " + Nat256Native.isAvailable());

        KeyPair kp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] pub = kp.getPublic().getEncoded();
        byte[] pri = kp.getPrivate().getEncoded();
        System.out.println("pri.length=" + pri.length + " pub.length=" + pub.length);

        byte[] msg = "Hello SM2 Test".getBytes();
        byte[] za = SM2Util.initZa(null, pub);
        SM3Digest digest = new SM3Digest();
        digest.update(za); digest.update(msg);
        byte[] e = digest.doFinal();

        // Test comb vs wNAF for simple scalars
        for (int testVal : new int[]{1, 2, 3, 7, 255}) {
            int[] testKArr = {testVal, 0, 0, 0, 0, 0, 0, 0};
            int[] outComb = new int[16], outWnaf = new int[16];
            Nat256Native.nativeCombFixedBaseMul(testKArr, outComb);
            Nat256Native.nativeFixedBaseMul(testKArr, outWnaf);
            boolean match = Arrays.equals(outComb, outWnaf);
            if (!match) {
                int[] cx = Arrays.copyOf(outComb, 8), wx = Arrays.copyOf(outWnaf, 8);
                System.out.println("k=" + testVal + " MISMATCH: comb=" +
                    com.yxj.gm.util.SM2P256V1Field.toBigInteger(cx).toString(16).substring(0, 16) + "... wnaf=" +
                    com.yxj.gm.util.SM2P256V1Field.toBigInteger(wx).toString(16).substring(0, 16) + "...");
            } else {
                System.out.println("k=" + testVal + " OK");
            }
        }
        // Test with a larger scalar
        BigInteger testK = new BigInteger(1, pri);
        int[] testKArr2 = com.yxj.gm.util.SM2P256V1Field.fromBigInteger(testK);
        int[] outComb2 = new int[16], outWnaf2 = new int[16];
        Nat256Native.nativeCombFixedBaseMul(testKArr2, outComb2);
        Nat256Native.nativeFixedBaseMul(testKArr2, outWnaf2);
        System.out.println("k=pri match: " + Arrays.equals(outComb2, outWnaf2));

        // Test native sign core directly
        BigInteger bigDa = new BigInteger(1, pri);
        BigInteger daInv = bigDa.add(BigInteger.ONE).modInverse(SM2Constant.getBigN());
        byte[] daInvBytes = SM2Util.toFixedBytes(daInv, 32);

        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);

        // Also compute expected result with Java
        BigInteger bigK = new BigInteger(1, k);
        BigInteger[] kG_java = SM2Util.fixedBaseMultiply(bigK);
        System.out.println("Java [k]G.x = " + kG_java[0].toString(16));

        byte[] outRS = new byte[64];
        System.out.println("Testing nativeSignCore...");
        int signResult = Nat256Native.nativeSignCore(e, pri, daInvBytes, k, outRS);
        System.out.println("nativeSignCore returned: " + signResult);

        if (signResult == 1) {
            byte[] rBytes = Arrays.copyOf(outRS, 32);
            byte[] sBytes = Arrays.copyOfRange(outRS, 32, 64);
            System.out.println("r = " + new BigInteger(1, rBytes).toString(16));
            System.out.println("s = " + new BigInteger(1, sBytes).toString(16));

            // Verify with Java path
            System.out.println("Testing nativeVerifyCore...");
            boolean nativeOk = Nat256Native.nativeVerifyCore(e, rBytes, sBytes, pub);
            System.out.println("nativeVerifyCore: " + nativeOk);

            // Verify with Java-only path (bypass native)
            BigInteger bigR = new BigInteger(1, rBytes);
            BigInteger bigS = new BigInteger(1, sBytes);
            BigInteger bigN = SM2Constant.getBigN();
            BigInteger bigT = bigR.add(bigS).mod(bigN);
            BigInteger px = new BigInteger(1, Arrays.copyOf(pub, 32));
            BigInteger py = new BigInteger(1, Arrays.copyOfRange(pub, 32, 64));
            BigInteger[] point = SM2Util.shamirMultiply(bigS, px, py, bigT);
            BigInteger bigE = new BigInteger(1, e);
            BigInteger R = bigE.add(point[0]).mod(bigN);
            System.out.println("Java verify R = " + R.toString(16));
            System.out.println("Java verify r = " + bigR.toString(16));
            System.out.println("Java verify ok: " + R.equals(bigR));
        }

        // Batch correctness test
        System.out.println("\n--- Batch correctness test (50 rounds) ---");
        int pass = 0, fail = 0;
        SM2Signature batchSigner = new SM2Signature();
        SM2Cipher batchCipher = new SM2Cipher();
        for (int i = 0; i < 50; i++) {
            KeyPair bkp = SM2KeyPairGenerate.generateSM2KeyPair();
            byte[] bpub = bkp.getPublic().getEncoded();
            byte[] bpri = bkp.getPrivate().getEncoded();
            byte[] bmsg = ("Msg#" + i).getBytes();
            byte[] bsig = batchSigner.signature(bmsg, null, bpri, bpub);
            if (!batchSigner.verify(bmsg, null, bsig, bpub)) { fail++; continue; }
            byte[] benc = batchCipher.SM2CipherEncrypt(bmsg, bpub);
            byte[] bdec = batchCipher.SM2CipherDecrypt(benc, bpri);
            if (!Arrays.equals(bmsg, bdec)) { fail++; continue; }
            pass++;
        }
        System.out.println("Results: " + pass + " passed, " + fail + " failed");
    }
}
