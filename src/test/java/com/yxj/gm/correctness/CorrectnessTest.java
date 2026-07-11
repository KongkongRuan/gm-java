package com.yxj.gm.correctness;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.SM3.SM3HMac;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;

/**
 * 国密算法标准正确性测试。
 *
 * 测试目标：
 * 1. 用 GM/T 标准测试向量断言 SM3、SM4-ECB 的精确输出；
 * 2. 对 SM2/SM4/HMAC-SM3 做自反（加解密、签名验签）测试；
 * 3. 用 BouncyCastle 作为独立参考实现做交叉校验。
 */
public class CorrectnessTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    // ==================== 工具方法 ====================

    private static byte[] hex(String s) {
        return Hex.decode(s);
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        RANDOM.nextBytes(b);
        return b;
    }

    private static void assertArrayEqualsHex(String message, byte[] expected, byte[] actual) {
        assertArrayEquals(message + "\nexpected: " + Hex.toHexString(expected)
                + "\nactual:   " + Hex.toHexString(actual), expected, actual);
    }

    // ==================== SM3 正确性 ====================

    /**
     * GM/T 0004-2012 示例 1：消息 "abc" 的 SM3 摘要值。
     */
    @Test
    public void testSm3AbcVector() {
        byte[] expected = hex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
        SM3Digest digest = new SM3Digest();
        digest.update("abc".getBytes());
        byte[] actual = digest.doFinal();
        assertArrayEqualsHex("SM3(\"abc\") 与标准向量不符", expected, actual);
    }

    @Test
    public void testSm3OneShotEqualsStreaming() {
        byte[] msg = randomBytes(1024);

        SM3Digest oneShot = new SM3Digest();
        byte[] expected = oneShot.doFinal(msg);

        SM3Digest streaming = new SM3Digest();
        int mid = msg.length / 3;
        streaming.update(msg, 0, mid);
        streaming.update(msg, mid, msg.length - mid);
        byte[] actual = streaming.doFinal();

        assertArrayEqualsHex("SM3 流式 update 结果应与一次性 doFinal 一致", expected, actual);
    }

    @Test
    public void testSm3AgainstBouncyCastle() {
        byte[] msg = randomBytes(12345);

        SM3Digest gm = new SM3Digest();
        byte[] gmHash = gm.doFinal(msg);

        org.bouncycastle.crypto.digests.SM3Digest bc = new org.bouncycastle.crypto.digests.SM3Digest();
        bc.update(msg, 0, msg.length);
        byte[] bcHash = new byte[bc.getDigestSize()];
        bc.doFinal(bcHash, 0);

        assertArrayEqualsHex("SM3 结果与 BouncyCastle 不一致", bcHash, gmHash);
    }

    // ==================== SM4 正确性 ====================

    /**
     * GM/T 0002-2012 示例：SM4-ECB 单分组加密标准向量。
     */
    @Test
    public void testSm4EcbKnownVector() {
        byte[] key = hex("0123456789abcdeffedcba9876543210");
        byte[] plaintext = hex("0123456789abcdeffedcba9876543210");
        byte[] expectedCiphertext = hex("681edf34d206965e86b3e94f536e4246");

        SM4Cipher cipher = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.ECB);
        byte[] ciphertext = cipher.cipherEncrypt(key, plaintext, null);
        assertArrayEqualsHex("SM4-ECB 标准向量加密结果不符", expectedCiphertext, ciphertext);

        byte[] decrypted = cipher.cipherDecrypt(key, ciphertext, null);
        assertArrayEqualsHex("SM4-ECB 标准向量解密结果不符", plaintext, decrypted);
    }

    @Test
    public void testSm4EcbCbcCtrRoundtrip() {
        byte[] key = randomBytes(16);
        byte[] iv = randomBytes(16);
        byte[] plaintext = randomBytes(100); // 非 16 整数倍，验证 PKCS7

        // ECB
        SM4Cipher ecb = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.ECB);
        byte[] ecbCipher = ecb.cipherEncrypt(key, plaintext, null);
        byte[] ecbPlain = ecb.cipherDecrypt(key, ecbCipher, null);
        assertArrayEquals("SM4-ECB 加解密往返失败", plaintext, ecbPlain);

        // CBC
        SM4Cipher cbc = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.CBC);
        byte[] cbcCipher = cbc.cipherEncrypt(key, plaintext, iv);
        byte[] cbcPlain = cbc.cipherDecrypt(key, cbcCipher, iv);
        assertArrayEquals("SM4-CBC 加解密往返失败", plaintext, cbcPlain);

        // CTR
        SM4Cipher ctr = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CTR);
        byte[] ctrCipher = ctr.cipherEncrypt(key, plaintext, iv);
        byte[] ctrPlain = ctr.cipherDecrypt(key, ctrCipher, iv);
        assertArrayEquals("SM4-CTR 加解密往返失败", plaintext, ctrPlain);
    }

    @Test
    public void testSm4GcmRoundtrip() {
        byte[] key = randomBytes(16);
        byte[] iv = randomBytes(12);
        byte[] aad = "gm-java-aad".getBytes();
        byte[] plaintext = randomBytes(256);

        SM4Cipher cipher = new SM4Cipher();
        AEADExecution enc = cipher.cipherEncryptGCM(key, plaintext, iv, aad, 16);
        byte[] decrypted = cipher.cipherDecryptGCM(key, enc.getCipherText(), iv, aad, enc.getTag());

        assertArrayEquals("SM4-GCM 加解密往返失败", plaintext, decrypted);
    }

    @Test
    public void testSm4AgainstBouncyCastle() throws Exception {
        byte[] key = randomBytes(16);
        byte[] iv = randomBytes(16);
        byte[] plaintext = randomBytes(64); // 16 整数倍，便于 NoPadding 与 BC 直接对比

        // ECB
        SM4Cipher gmEcb = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.ECB);
        byte[] gmEcbCipher = gmEcb.cipherEncrypt(key, plaintext, null);
        byte[] bcEcbCipher = bcCipher(true, new SM4Engine(), key, null, plaintext);
        assertArrayEquals("SM4-ECB 与 BouncyCastle 加密结果不一致", bcEcbCipher, gmEcbCipher);

        // CBC
        SM4Cipher gmCbc = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CBC);
        byte[] gmCbcCipher = gmCbc.cipherEncrypt(key, plaintext, iv);
        byte[] bcCbcCipher = bcCipher(true, new CBCBlockCipher(new SM4Engine()), key, iv, plaintext);
        assertArrayEquals("SM4-CBC 与 BouncyCastle 加密结果不一致", bcCbcCipher, gmCbcCipher);

        // CTR
        SM4Cipher gmCtr = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CTR);
        byte[] gmCtrCipher = gmCtr.cipherEncrypt(key, plaintext, iv);
        byte[] bcCtrCipher = bcCipher(true, new SICBlockCipher(new SM4Engine()), key, iv, plaintext);
        assertArrayEquals("SM4-CTR 与 BouncyCastle 加密结果不一致", bcCtrCipher, gmCtrCipher);
    }

    private static byte[] bcCipher(boolean encrypt, org.bouncycastle.crypto.BlockCipher mode, byte[] key,
                                   byte[] iv, byte[] input) throws Exception {
        BufferedBlockCipher cipher = new BufferedBlockCipher(mode);
        KeyParameter kp = new KeyParameter(key);
        if (iv != null) {
            cipher.init(encrypt, new ParametersWithIV(kp, iv));
        } else {
            cipher.init(encrypt, kp);
        }
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.processBytes(input, 0, input.length, output, 0);
        len += cipher.doFinal(output, len);
        return Arrays.copyOf(output, len);
    }

    // ==================== SM2 正确性 ====================

    @Test
    public void testSm2EncryptDecryptRoundtrip() {
        KeyPair kp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] pub = kp.getPublic().getEncoded();
        byte[] pri = kp.getPrivate().getEncoded();
        byte[] msg = randomBytes(64);

        SM2Cipher cipher = new SM2Cipher();
        byte[] enc = cipher.SM2CipherEncrypt(msg, pub);
        byte[] dec = cipher.SM2CipherDecrypt(enc, pri);

        assertArrayEquals("SM2 加解密往返失败", msg, dec);
    }

    @Test
    public void testSm2SignVerify() {
        KeyPair kp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] pub = kp.getPublic().getEncoded();
        byte[] pri = kp.getPrivate().getEncoded();
        byte[] msg = randomBytes(64);

        SM2Signature signer = new SM2Signature();
        byte[] sig = signer.signature(msg, null, pri);
        boolean ok = signer.verify(msg, null, sig, pub);

        assertTrue("SM2 签名验签失败", ok);

        byte[] tampered = msg.clone();
        tampered[0] ^= 1;
        assertFalse("SM2 验签应对篡改消息返回 false", signer.verify(tampered, null, sig, pub));
    }

    @Test
    public void testSm2SignVerifyWithPubKey() {
        KeyPair kp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] pub = kp.getPublic().getEncoded();
        byte[] pri = kp.getPrivate().getEncoded();
        byte[] msg = randomBytes(64);

        SM2Signature signer = new SM2Signature();
        byte[] sig = signer.signature(msg, null, pri, pub);
        boolean ok = signer.verify(msg, null, sig, pub);

        assertTrue("SM2 带公钥签名验签失败", ok);
    }

    // ==================== HMAC-SM3 正确性 ====================

    @Test
    public void testHmacSm3AgainstBouncyCastle() {
        byte[] key = randomBytes(32);
        byte[] msg = randomBytes(256);

        SM3HMac gmMac = new SM3HMac(key);
        gmMac.update(msg);
        byte[] gmTag = gmMac.doFinal();

        HMac bcMac = new HMac(new org.bouncycastle.crypto.digests.SM3Digest());
        bcMac.init(new KeyParameter(key));
        bcMac.update(msg, 0, msg.length);
        byte[] bcTag = new byte[bcMac.getMacSize()];
        bcMac.doFinal(bcTag, 0);

        assertArrayEqualsHex("HMAC-SM3 与 BouncyCastle 结果不一致", bcTag, gmTag);
    }

    @Test
    public void testHmacSm3StreamingEqualsOneShot() {
        byte[] key = randomBytes(16);
        byte[] msg = randomBytes(500);

        SM3HMac oneShot = new SM3HMac(key);
        byte[] expected = oneShot.doFinal(msg);

        SM3HMac streaming = new SM3HMac(key);
        streaming.update(msg, 0, 100);
        streaming.update(msg, 100, msg.length - 100);
        byte[] actual = streaming.doFinal();

        assertArrayEquals("HMAC-SM3 流式 update 结果应与一次性 doFinal 一致", expected, actual);
    }
}
