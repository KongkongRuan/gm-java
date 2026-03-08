package com.yxj.gm;

import com.yxj.gm.SM3.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * SM3 正确性验证 - 运行 main 验证优化后结果
 */
public class SM3Verify {
    public static void main(String[] args) {
        String msg = "gm-java-1.0";
        String expected = "cc7e992374984c82ab13f3f117d52849970628d16acf4cc1d9c137953e23a418";

        SM3Digest sm3 = new SM3Digest();
        sm3.update(msg.getBytes());
        byte[] md1 = sm3.doFinal();
        byte[] md2 = sm3.doFinal(msg.getBytes());
        sm3.update("gm-java-".getBytes());
        sm3.update("1.0".getBytes());
        byte[] md3 = sm3.doFinal();

        String s1 = Hex.toHexString(md1);
        String s2 = Hex.toHexString(md2);
        String s3 = Hex.toHexString(md3);

        System.out.println("update:        " + s1);
        System.out.println("直接doFinal:   " + s2);
        System.out.println("多次分开update: " + s3);
        System.out.println("期望值:        " + expected);

        if (!expected.equals(s1) || !expected.equals(s2) || !expected.equals(s3)) {
            throw new AssertionError("SM3 结果不匹配!");
        }
        System.out.println("SM3 验证通过!");
    }
}
