package com.yxj.gm;

import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.SM2P256V1Field;
import com.yxj.gm.util.SM2Util;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;

public class FieldDebug {
    public static void main(String[] args) {
        BigInteger p = SM2Constant.getBigP();
        BigInteger gx = SM2Constant.getBigGX();
        BigInteger gy = SM2Constant.getBigGY();

        System.out.println("=== fromBigInteger / toBigInteger ===");
        int[] fGx = SM2P256V1Field.fromBigInteger(gx);
        BigInteger gx2 = SM2P256V1Field.toBigInteger(fGx);
        System.out.println("gx match: " + gx.equals(gx2));
        System.out.println("gx = " + gx.toString(16));
        System.out.println("gx2= " + gx2.toString(16));

        System.out.println("\n=== mul test: gx * gy mod p ===");
        int[] fGy = SM2P256V1Field.fromBigInteger(gy);
        int[] fResult = new int[8];
        SM2P256V1Field.mul(fGx, fGy, fResult);
        BigInteger expected = gx.multiply(gy).mod(p);
        BigInteger actual = SM2P256V1Field.toBigInteger(fResult);
        System.out.println("mul match: " + expected.equals(actual));
        System.out.println("expected = " + expected.toString(16));
        System.out.println("actual   = " + actual.toString(16));

        System.out.println("\n=== sqr test: gx^2 mod p ===");
        SM2P256V1Field.sqr(fGx, fResult);
        expected = gx.multiply(gx).mod(p);
        actual = SM2P256V1Field.toBigInteger(fResult);
        System.out.println("sqr match: " + expected.equals(actual));

        System.out.println("\n=== add test: gx + gy mod p ===");
        SM2P256V1Field.add(fGx, fGy, fResult);
        expected = gx.add(gy).mod(p);
        actual = SM2P256V1Field.toBigInteger(fResult);
        System.out.println("add match: " + expected.equals(actual));

        System.out.println("\n=== sub test: gx - gy mod p ===");
        SM2P256V1Field.sub(fGx, fGy, fResult);
        expected = gx.subtract(gy).add(p).mod(p);
        actual = SM2P256V1Field.toBigInteger(fResult);
        System.out.println("sub match: " + expected.equals(actual));

        System.out.println("\n=== thrice test ===");
        int[] thr = new int[8];
        SM2P256V1Field.thrice(fGx, thr);
        BigInteger thrExpected = gx.multiply(BigInteger.valueOf(3)).mod(p);
        BigInteger thrActual = SM2P256V1Field.toBigInteger(thr);
        System.out.println("thrice match: " + thrExpected.equals(thrActual));
        if (!thrExpected.equals(thrActual)) {
            System.out.println("  expected = " + thrExpected.toString(16));
            System.out.println("  actual   = " + thrActual.toString(16));
        }

        System.out.println("\n=== twice test ===");
        int[] twi = new int[8];
        SM2P256V1Field.twice(fGx, twi);
        BigInteger twiExpected = gx.multiply(BigInteger.valueOf(2)).mod(p);
        BigInteger twiActual = SM2P256V1Field.toBigInteger(twi);
        System.out.println("twice match: " + twiExpected.equals(twiActual));

        System.out.println("\n=== neg test ===");
        int[] negR = new int[8];
        SM2P256V1Field.neg(fGx, negR);
        BigInteger negExpected = p.subtract(gx);
        BigInteger negActual = SM2P256V1Field.toBigInteger(negR);
        System.out.println("neg match: " + negExpected.equals(negActual));

        System.out.println("\n=== direct jacobianDouble test ===");
        // Compute [2]G directly via field doubling: double (Gx, Gy, Z=1)
        int[] inX = SM2P256V1Field.fromBigInteger(gx);
        int[] inY = SM2P256V1Field.fromBigInteger(gy);
        int[] inZ = new int[]{1,0,0,0,0,0,0,0};
        int[] oX = new int[8], oY = new int[8], oZ = new int[8];

        // Step by step doubleF internals
        int[] Z1sq = new int[8], ft1 = new int[8], ft2 = new int[8];
        int[] fM = new int[8], Y1sq = new int[8], fS = new int[8];
        int[] fY14 = new int[8], ftmp = new int[8];

        SM2P256V1Field.sqr(inZ, Z1sq);
        System.out.println("Z1sq = " + SM2P256V1Field.toBigInteger(Z1sq));
        SM2P256V1Field.sub(inX, Z1sq, ft1);
        System.out.println("t1 (X-Z^2) = " + SM2P256V1Field.toBigInteger(ft1).toString(16));
        BigInteger t1Exp = gx.subtract(BigInteger.ONE).mod(p);
        System.out.println("t1 expect  = " + t1Exp.toString(16));
        System.out.println("t1 match: " + t1Exp.equals(SM2P256V1Field.toBigInteger(ft1)));

        SM2P256V1Field.add(inX, Z1sq, ft2);
        SM2P256V1Field.mul(ft1, ft2, fM);
        BigInteger mPre = gx.subtract(BigInteger.ONE).multiply(gx.add(BigInteger.ONE)).mod(p);
        System.out.println("M pre-thrice = " + SM2P256V1Field.toBigInteger(fM).toString(16));
        System.out.println("M pre expect = " + mPre.toString(16));
        System.out.println("M pre match: " + mPre.equals(SM2P256V1Field.toBigInteger(fM)));

        SM2P256V1Field.thrice(fM, fM);
        BigInteger mExp = mPre.multiply(BigInteger.valueOf(3)).mod(p);
        System.out.println("M (3*(X^2-1))= " + SM2P256V1Field.toBigInteger(fM).toString(16));
        System.out.println("M expected   = " + mExp.toString(16));
        System.out.println("M match: " + mExp.equals(SM2P256V1Field.toBigInteger(fM)));

        SM2P256V1Field.sqr(inY, Y1sq);
        SM2P256V1Field.mul(inX, Y1sq, fS);
        SM2P256V1Field.twice(fS, fS);
        SM2P256V1Field.twice(fS, fS);
        BigInteger sExp = gx.multiply(gy.multiply(gy).mod(p)).mod(p).multiply(BigInteger.valueOf(4)).mod(p);
        System.out.println("S (4*X*Y^2)= " + SM2P256V1Field.toBigInteger(fS).toString(16));
        System.out.println("S expected = " + sExp.toString(16));
        System.out.println("S match: " + sExp.equals(SM2P256V1Field.toBigInteger(fS)));

        SM2P256V1Field.sqr(fM, oX);
        SM2P256V1Field.sub(oX, fS, oX);
        SM2P256V1Field.sub(oX, fS, oX);
        BigInteger x3Exp = mExp.multiply(mExp).mod(p).subtract(sExp.multiply(BigInteger.valueOf(2))).mod(p);
        System.out.println("X3 (M^2-2S) = " + SM2P256V1Field.toBigInteger(oX).toString(16));
        System.out.println("X3 expected = " + x3Exp.toString(16));
        System.out.println("X3 match: " + x3Exp.equals(SM2P256V1Field.toBigInteger(oX)));

        System.out.println("\n=== [2]G via BigInteger (reference) ===");
        byte[][] refResult = SM2Util.PointAdditionOperation(
                SM2Constant.getXG(), SM2Constant.getYG(),
                SM2Constant.getXG(), SM2Constant.getYG(),
                SM2Constant.getA(), SM2Constant.getP());
        BigInteger ref2Gx = new BigInteger(1, refResult[0]);
        BigInteger ref2Gy = new BigInteger(1, refResult[1]);
        System.out.println("ref [2]G x = " + ref2Gx.toString(16));
        System.out.println("ref [2]G y = " + ref2Gy.toString(16));

        System.out.println("\n=== fixedBaseMultiply [2]G ===");
        BigInteger[] pt = SM2Util.fixedBaseMultiply(BigInteger.valueOf(2));
        System.out.println("x = " + pt[0].toString(16));
        System.out.println("y = " + pt[1].toString(16));
        System.out.println("[2]G match ref: x=" + ref2Gx.equals(pt[0]) + " y=" + ref2Gy.equals(pt[1]));
        boolean onCurve = pt[1].multiply(pt[1]).mod(p).equals(
                pt[0].pow(3).add(SM2Constant.getBigA().multiply(pt[0])).add(SM2Constant.getBigB()).mod(p));
        System.out.println("[2]G on curve: " + onCurve);

        System.out.println("\nDone!");
    }
}
