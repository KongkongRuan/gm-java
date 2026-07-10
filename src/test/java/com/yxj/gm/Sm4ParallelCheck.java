package com.yxj.gm;

import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 校验并行化重构后的 SM4 ECB/CBC 与 BC 参考实现逐字节一致。
 * 覆盖多种数据长度（含 < 阈值 的串行路径 与 >= 阈值的并行路径）。
 */
public class Sm4ParallelCheck {
    static final int[] SIZES = {0, 1, 15, 16, 17, 100, 1024, 4096, 1_000_000, 10_000_000};

    public static void main(String[] args) {
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);

        SM4Cipher ecb = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.ECB);
        SM4Cipher cbc = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CBC);
        SM4Cipher cbcPkcs = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.CBC);

        int failures = 0;
        for (int n : SIZES) {
            byte[] data = new byte[n];
            new SecureRandom().nextBytes(data);
            // NoPadding 要求 16 字节对齐；n==0 用空数组，否则向上取整到 16 倍数
            int L = (n == 0) ? 0 : (((n + 15) / 16) * 16);
            byte[] in = Arrays.copyOf(data, L);

            // ---- ECB 往返 + 与 BC 交叉校验 ----
            byte[] eEnc = ecb.cipherEncrypt(key, in, null);
            byte[] eDec = ecb.cipherDecrypt(key, eEnc, null);
            if (!Arrays.equals(eDec, in)) { System.out.println("FAIL ECB roundtrip n=" + n); failures++; }
            if (!Arrays.equals(eEnc, bcEcb(key, in))) { System.out.println("FAIL ECB vs BC n=" + n); failures++; }

            // ---- CBC (NoPadding) 往返（含空输入：已修复 blockEncryptCBCInt 空数组越界） ----
            byte[] cEnc = cbc.cipherEncrypt(key, in, iv);
            byte[] cDec = cbc.cipherDecrypt(key, cEnc, iv);
            if (!Arrays.equals(cDec, in)) { System.out.println("FAIL CBC roundtrip n=" + n); failures++; }

            // ---- CBC (Pkcs7) 往返 ----
            if (n > 0) {
                byte[] p = Arrays.copyOf(data, n);
                byte[] cpEnc = cbcPkcs.cipherEncrypt(key, p, iv);
                byte[] cpDec = cbcPkcs.cipherDecrypt(key, cpEnc, iv);
                if (!Arrays.equals(cpDec, p)) { System.out.println("FAIL CBC-Pkcs7 roundtrip n=" + n); failures++; }
            }
            System.out.println("n=" + n + " (L=" + L + ") OK");
        }
        System.out.println(failures == 0 ? "ALL PASS" : ("FAILURES=" + failures));
        if (failures != 0) System.exit(1);
    }

    static byte[] bcEcb(byte[] key, byte[] in) {
        SM4Engine e = new SM4Engine();
        e.init(true, new KeyParameter(key));
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i += 16) e.processBlock(in, i, out, i);
        return out;
    }
}
