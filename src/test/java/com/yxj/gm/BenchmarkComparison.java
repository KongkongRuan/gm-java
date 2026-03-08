package com.yxj.gm;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.util.JNI.Nat256Native;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.symmetric.SM4;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.crypto.engines.SM2Engine;

import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class BenchmarkComparison {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    static final X9ECParameters SM2_PARAMS = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("sm2p256v1");
    static final ECDomainParameters SM2_DOMAIN = new ECDomainParameters(
            SM2_PARAMS.getCurve(), SM2_PARAMS.getG(), SM2_PARAMS.getN(), SM2_PARAMS.getH());

    public static void main(String[] args) throws Exception {
        int sm2Warmup = 500, sm2Rounds = 200, sm2Sets = 5;
        int sm3Warmup = 500, sm3Rounds = 1000, sm3Sets = 5;
        int sm4Warmup = 20, sm4Rounds = 5, sm4Sets = 5;
        int sm4DataMB = 10;

        System.out.println("════════════════════════════════════════════════════════");
        System.out.println("  gm-java vs BouncyCastle vs Hutool 性能对比（优化版）");
        System.out.println("════════════════════════════════════════════════════════");
        System.out.printf("  Nat256  : %s%n", Nat256Native.isAvailable() ? "JNI 加速 (C)" : "Java 实现");
        System.out.printf("  Java    : %s (%s)%n", System.getProperty("java.version"), System.getProperty("java.vm.name"));
        System.out.printf("  OS      : %s %s%n", System.getProperty("os.name"), System.getProperty("os.arch"));
        System.out.printf("  CPUs    : %d%n", Runtime.getRuntime().availableProcessors());
        System.out.printf("  SM2     : 预热 %d 次, 测量 %d 次 × %d 轮%n", sm2Warmup, sm2Rounds, sm2Sets);
        System.out.printf("  SM3     : 预热 %d 次, 测量 %d 次 × %d 轮%n", sm3Warmup, sm3Rounds, sm3Sets);
        System.out.printf("  SM4     : 预热 %d 次, 测量 %d 次 × %d 轮, 数据 %dMB%n", sm4Warmup, sm4Rounds, sm4Sets, sm4DataMB);
        System.out.println("════════════════════════════════════════════════════════\n");

        benchSM2KeyGen(sm2Warmup, sm2Rounds, sm2Sets);
        benchSM2EncDec(sm2Warmup, sm2Rounds, sm2Sets);
        benchSM2SignVerify(sm2Warmup, sm2Rounds, sm2Sets);
        benchSM3(sm3Warmup, sm3Rounds, sm3Sets);
        benchSM4(sm4Warmup, sm4Rounds, sm4Sets, sm4DataMB);

        System.out.println("════════════════════════════════════════════════════════");
        System.out.println("  全部测试完成");
        System.out.println("════════════════════════════════════════════════════════");
    }

    // ==================== SM2 密钥生成 ====================
    static void benchSM2KeyGen(int warmup, int rounds, int sets) throws Exception {
        System.out.println("╔══ SM2 密钥对生成 ══╗");
        ECKeyPairGenerator bcGen = new ECKeyPairGenerator();
        bcGen.init(new ECKeyGenerationParameters(SM2_DOMAIN, new SecureRandom()));

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) SM2KeyPairGenerate.generateSM2KeyPair();
        System.out.printf("    预热 gm-java      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcGen.generateKeyPair();
        System.out.printf("    预热 BC           %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) SmUtil.sm2();
        System.out.printf("    预热 Hutool       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        double[] gm = new double[sets], bc = new double[sets], ht = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) SM2KeyPairGenerate.generateSM2KeyPair();
            gm[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcGen.generateKeyPair();
            bc[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) SmUtil.sm2();
            ht[s] = System.currentTimeMillis() - t0;
        }
        printResult("SM2 密钥生成", rounds, gm, bc, ht, sets);
    }

    // ==================== SM2 加解密 ====================
    static void benchSM2EncDec(int warmup, int rounds, int sets) throws Exception {
        System.out.println("\n╔══ SM2 加解密 ══╗");
        byte[] msg = "Hello SM2 benchmark test message!".getBytes();

        KeyPair gmKp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] gmPub = gmKp.getPublic().getEncoded();
        byte[] gmPri = gmKp.getPrivate().getEncoded();
        SM2Cipher gmCipher = new SM2Cipher();

        AsymmetricCipherKeyPair bcKp = genBCKeyPair();
        ECPublicKeyParameters bcPub = (ECPublicKeyParameters) bcKp.getPublic();
        ECPrivateKeyParameters bcPri = (ECPrivateKeyParameters) bcKp.getPrivate();

        SM2 htSm2 = SmUtil.sm2();

        byte[] gmEnc = gmCipher.SM2CipherEncrypt(msg, gmPub);
        byte[] bcEnc = bcEncrypt(msg, bcPub);

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmCipher.SM2CipherEncrypt(msg, gmPub);
        System.out.printf("    预热 gm-enc       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmCipher.SM2CipherDecrypt(gmEnc, gmPri);
        System.out.printf("    预热 gm-dec       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcEncrypt(msg, bcPub);
        System.out.printf("    预热 BC-enc       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcDecrypt(bcEnc, bcPri);
        System.out.printf("    预热 BC-dec       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        byte[] htEnc = htSm2.encrypt(msg);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) htSm2.encrypt(msg);
        System.out.printf("    预热 HT-enc       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) htSm2.decrypt(htEnc, KeyType.PrivateKey);
        System.out.printf("    预热 HT-dec       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmCipher.SM2CipherEncrypt(msg, gmPub);
            gmE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcEncrypt(msg, bcPub);
            bcE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htSm2.encrypt(msg);
            htE[s] = System.currentTimeMillis() - t0;

            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmCipher.SM2CipherDecrypt(gmEnc, gmPri);
            gmD[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcDecrypt(bcEnc, bcPri);
            bcD[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htSm2.decrypt(htEnc, KeyType.PrivateKey);
            htD[s] = System.currentTimeMillis() - t0;
        }
        printResult("SM2 加密", rounds, gmE, bcE, htE, sets);
        printResult("SM2 解密", rounds, gmD, bcD, htD, sets);
    }

    // ==================== SM2 签名/验签 ====================
    static void benchSM2SignVerify(int warmup, int rounds, int sets) throws Exception {
        System.out.println("\n╔══ SM2 签名/验签 ══╗");
        byte[] msg = "Hello SM2 sign benchmark!".getBytes();

        KeyPair gmKp = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] gmPub = gmKp.getPublic().getEncoded();
        byte[] gmPri = gmKp.getPrivate().getEncoded();
        SM2Signature gmSigner = new SM2Signature();

        AsymmetricCipherKeyPair bcKp = genBCKeyPair();
        ECPublicKeyParameters bcPub = (ECPublicKeyParameters) bcKp.getPublic();
        ECPrivateKeyParameters bcPri = (ECPrivateKeyParameters) bcKp.getPrivate();

        SM2 htSm2 = SmUtil.sm2();
        byte[] gmSig = gmSigner.signature(msg, null, gmPri, gmPub);
        byte[] bcSig = bcSign(msg, bcPri);

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSigner.signature(msg, null, gmPri, gmPub);
        System.out.printf("    预热 gm-sign      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSigner.verify(msg, null, gmSig, gmPub);
        System.out.printf("    预热 gm-vrfy      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSign(msg, bcPri);
        System.out.printf("    预热 BC-sign      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcVerify(msg, bcSig, bcPub);
        System.out.printf("    预热 BC-vrfy      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        byte[] htSig = htSm2.sign(msg);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) htSm2.sign(msg);
        System.out.printf("    预热 HT-sign      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) htSm2.verify(msg, htSig);
        System.out.printf("    预热 HT-vrfy      %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        double[] gmS = new double[sets], bcS = new double[sets], htS = new double[sets];
        double[] gmV = new double[sets], bcV = new double[sets], htV = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSigner.signature(msg, null, gmPri, gmPub);
            gmS[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSign(msg, bcPri);
            bcS[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htSm2.sign(msg);
            htS[s] = System.currentTimeMillis() - t0;

            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSigner.verify(msg, null, gmSig, gmPub);
            gmV[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcVerify(msg, bcSig, bcPub);
            bcV[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htSm2.verify(msg, htSig);
            htV[s] = System.currentTimeMillis() - t0;
        }
        printResult("SM2 签名", rounds, gmS, bcS, htS, sets);
        printResult("SM2 验签", rounds, gmV, bcV, htV, sets);
    }

    // ==================== SM3 ====================
    static void benchSM3(int warmup, int rounds, int sets) {
        System.out.println("\n╔══ SM3 哈希 ══╗");
        byte[] data1K = new byte[1024];
        byte[] data1M = new byte[1024 * 1024];
        new SecureRandom().nextBytes(data1K);
        new SecureRandom().nextBytes(data1M);
        org.bouncycastle.crypto.digests.SM3Digest bcDigest = new org.bouncycastle.crypto.digests.SM3Digest();

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) { SM3Digest d = new SM3Digest(); d.update(data1K); d.doFinal(); }
        System.out.printf("    预热 gm-1KB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) { bcDigest.reset(); bcDigest.update(data1K, 0, data1K.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
        System.out.printf("    预热 BC-1KB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) cn.hutool.crypto.digest.SM3.create().digest(data1K);
        System.out.printf("    预热 HT-1KB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        double[] gm1 = new double[sets], bc1 = new double[sets], ht1 = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) { SM3Digest d = new SM3Digest(); d.update(data1K); d.doFinal(); }
            gm1[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) { bcDigest.reset(); bcDigest.update(data1K, 0, data1K.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
            bc1[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) cn.hutool.crypto.digest.SM3.create().digest(data1K);
            ht1[s] = System.currentTimeMillis() - t0;
        }
        printResult("SM3 (1KB)", rounds, gm1, bc1, ht1, sets);

        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) { SM3Digest d = new SM3Digest(); d.update(data1M); d.doFinal(); }
        System.out.printf("    预热 gm-1MB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) { bcDigest.reset(); bcDigest.update(data1M, 0, data1M.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
        System.out.printf("    预热 BC-1MB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) cn.hutool.crypto.digest.SM3.create().digest(data1M);
        System.out.printf("    预热 HT-1MB       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        double[] gm2 = new double[sets], bc2 = new double[sets], ht2 = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) { SM3Digest d = new SM3Digest(); d.update(data1M); d.doFinal(); }
            gm2[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) { bcDigest.reset(); bcDigest.update(data1M, 0, data1M.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
            bc2[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) cn.hutool.crypto.digest.SM3.create().digest(data1M);
            ht2[s] = System.currentTimeMillis() - t0;
        }
        printResult("SM3 (1MB)", rounds, gm2, bc2, ht2, sets);
    }

    // ==================== SM4 ====================
    static void benchSM4(int warmup, int rounds, int sets, int dataMB) {
        System.out.println("\n╔══ SM4 对称加解密 (" + dataMB + "MB) ══╗");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(iv);
        byte[] data = new byte[dataMB * 1024 * 1024];
        new SecureRandom().nextBytes(data);

        SM4Cipher gmSm4Ecb = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.ECB);
        SM4Cipher gmSm4Cbc = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.CBC);
        SM4Cipher gmSm4Ctr = new SM4Cipher(PaddingEnum.Pkcs7, ModeEnum.CTR);

        SM4 htEcb = SmUtil.sm4(key);
        SM4 htCbc = new SM4(cn.hutool.crypto.Mode.CBC, cn.hutool.crypto.Padding.PKCS5Padding, key, iv);

        benchSM4Mode("SM4-ECB", gmSm4Ecb, key, data, iv, htEcb, null, warmup, rounds, sets, dataMB, true);
        benchSM4Mode("SM4-CBC", gmSm4Cbc, key, data, iv, htCbc, iv, warmup, rounds, sets, dataMB, true);
        benchSM4CTR(gmSm4Ctr, key, data, iv, warmup, rounds, sets, dataMB);
    }

    static void benchSM4Mode(String name, SM4Cipher gmSm4, byte[] key, byte[] data, byte[] iv,
                              SM4 htSm4, byte[] htIv, int warmup, int rounds, int sets, int dataMB, boolean testDecrypt) {
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSm4.cipherEncrypt(key, data, iv);
        System.out.printf("    预热 gm-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSM4Encrypt(data, key);
        System.out.printf("    预热 BC-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) htSm4.encrypt(data);
        System.out.printf("    预热 HT-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);

        byte[] gmEnc = gmSm4.cipherEncrypt(key, data, iv);
        byte[] bcEnc = bcSM4Encrypt(data, key);
        byte[] htEnc = htSm4.encrypt(data);

        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherEncrypt(key, data, iv);
            gmE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4Encrypt(data, key);
            bcE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htSm4.encrypt(data);
            htE[s] = System.currentTimeMillis() - t0;
        }
        printResultMB(name + " 加密", rounds, gmE, bcE, htE, sets, dataMB);

        if (testDecrypt) {
            double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
            for (int s = 0; s < sets; s++) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
                gmD[s] = System.currentTimeMillis() - t0;
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) bcSM4Decrypt(bcEnc, key);
                bcD[s] = System.currentTimeMillis() - t0;
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) htSm4.decrypt(htEnc);
                htD[s] = System.currentTimeMillis() - t0;
            }
            printResultMB(name + " 解密", rounds, gmD, bcD, htD, sets, dataMB);
        }
    }

    static void benchSM4CTR(SM4Cipher gmSm4, byte[] key, byte[] data, byte[] iv,
                             int warmup, int rounds, int sets, int dataMB) {
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSm4.cipherEncrypt(key, data, iv);
        System.out.printf("    预热 gm-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSM4Encrypt(data, key);
        System.out.printf("    预热 BC-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        SM4 htCtr = new SM4(cn.hutool.crypto.Mode.CTR, cn.hutool.crypto.Padding.NoPadding, key, iv);
        for (int i = 0; i < warmup; i++) htCtr.encrypt(data);
        System.out.printf("    预热 HT-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);

        byte[] gmEnc = gmSm4.cipherEncrypt(key, data, iv);
        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherEncrypt(key, data, iv);
            gmE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4Encrypt(data, key);
            bcE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htCtr.encrypt(data);
            htE[s] = System.currentTimeMillis() - t0;

            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
            gmD[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4Decrypt(bcSM4Encrypt(data, key), key);
            bcD[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) htCtr.decrypt(htCtr.encrypt(data));
            htD[s] = System.currentTimeMillis() - t0;
        }
        printResultMB("SM4-CTR 加密 [gm多线程]", rounds, gmE, bcE, htE, sets, dataMB);
        printResultMB("SM4-CTR 解密 [gm多线程]", rounds, gmD, bcD, htD, sets, dataMB);
    }

    // ==================== BC helpers ====================
    static AsymmetricCipherKeyPair genBCKeyPair() {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(SM2_DOMAIN, new SecureRandom()));
        return gen.generateKeyPair();
    }

    static byte[] bcEncrypt(byte[] msg, ECPublicKeyParameters pub) {
        try {
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(pub, new SecureRandom()));
            return engine.processBlock(msg, 0, msg.length);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] bcDecrypt(byte[] cipher, ECPrivateKeyParameters pri) {
        try {
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, pri);
            return engine.processBlock(cipher, 0, cipher.length);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] bcSign(byte[] msg, ECPrivateKeyParameters pri) {
        try {
            SM2Signer signer = new SM2Signer();
            signer.init(true, new ParametersWithRandom(pri, new SecureRandom()));
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static boolean bcVerify(byte[] msg, byte[] sig, ECPublicKeyParameters pub) {
        SM2Signer signer = new SM2Signer();
        signer.init(false, pub);
        signer.update(msg, 0, msg.length);
        return signer.verifySignature(sig);
    }

    static byte[] bcSM4Encrypt(byte[] data, byte[] key) {
        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        int blockSize = engine.getBlockSize();
        int blocks = (data.length + blockSize - 1) / blockSize;
        byte[] out = new byte[blocks * blockSize];
        for (int i = 0; i < data.length / blockSize; i++) {
            engine.processBlock(data, i * blockSize, out, i * blockSize);
        }
        return out;
    }

    static byte[] bcSM4Decrypt(byte[] data, byte[] key) {
        SM4Engine engine = new SM4Engine();
        engine.init(false, new KeyParameter(key));
        int blockSize = engine.getBlockSize();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length / blockSize; i++) {
            engine.processBlock(data, i * blockSize, out, i * blockSize);
        }
        return out;
    }

    // ==================== 输出格式化 ====================
    static void printResult(String name, int rounds, double[] gm, double[] bc, double[] ht, int sets) {
        Arrays.sort(gm); Arrays.sort(bc); Arrays.sort(ht);
        double gmMed = gm[sets/2], bcMed = bc[sets/2], htMed = ht[sets/2];
        double gmAvg = avg(gm), bcAvg = avg(bc), htAvg = avg(ht);
        double gmMin = gm[0], bcMin = bc[0], htMin = ht[0];
        double gmMax = gm[sets-1], bcMax = bc[sets-1], htMax = ht[sets-1];

        System.out.printf("%n  %-20s │ %d 次/轮%n", name, rounds);
        System.out.printf("    gm-java   : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.3f ms%n",
                gmMed, gmAvg, gmMin, gmMax, gmAvg/rounds);
        System.out.printf("    BC        : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.3f ms%n",
                bcMed, bcAvg, bcMin, bcMax, bcAvg/rounds);
        System.out.printf("    Hutool    : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.3f ms%n",
                htMed, htAvg, htMin, htMax, htAvg/rounds);

        double best = Math.min(gmMed, Math.min(bcMed, htMed));
        String winner = gmMed == best ? "gm-java" : bcMed == best ? "BC" : "Hutool";
        double pctGm = gmMed == best ? 0 : (gmMed - best) / best * 100;
        double pctBc = bcMed == best ? 0 : (bcMed - best) / best * 100;
        double pctHt = htMed == best ? 0 : (htMed - best) / best * 100;
        System.out.printf("    >>> %s 最快", winner);
        if (pctGm > 0) System.out.printf("  gm-java慢 %.1f%%", pctGm);
        if (pctBc > 0) System.out.printf("  BC慢 %.1f%%", pctBc);
        if (pctHt > 0) System.out.printf("  Hutool慢 %.1f%%", pctHt);
        System.out.println();
    }

    static void printResultMB(String name, int rounds, double[] gm, double[] bc, double[] ht, int sets, int dataMB) {
        Arrays.sort(gm); Arrays.sort(bc); Arrays.sort(ht);
        double gmMed = gm[sets/2], bcMed = bc[sets/2], htMed = ht[sets/2];
        double gmAvg = avg(gm), bcAvg = avg(bc), htAvg = avg(ht);

        double gmMBs = rounds * dataMB * 1000.0 / gmMed;
        double bcMBs = rounds * dataMB * 1000.0 / bcMed;
        double htMBs = rounds * dataMB * 1000.0 / htMed;

        System.out.printf("%n  %-30s │ %d × %dMB%n", name, rounds, dataMB);
        System.out.printf("    gm-java   : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                gmMed, gmAvg, gm[0], gm[sets-1], gmMBs);
        System.out.printf("    BC        : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                bcMed, bcAvg, bc[0], bc[sets-1], bcMBs);
        System.out.printf("    Hutool    : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                htMed, htAvg, ht[0], ht[sets-1], htMBs);

        double best = Math.min(gmMed, Math.min(bcMed, htMed));
        String winner = gmMed == best ? "gm-java" : bcMed == best ? "BC" : "Hutool";
        double pctGm = gmMed == best ? 0 : (gmMed - best) / best * 100;
        double pctBc = bcMed == best ? 0 : (bcMed - best) / best * 100;
        double pctHt = htMed == best ? 0 : (htMed - best) / best * 100;
        System.out.printf("    >>> %s 最快", winner);
        if (pctGm > 0) System.out.printf("  gm-java慢 %.1f%%", pctGm);
        if (pctBc > 0) System.out.printf("  BC慢 %.1f%%", pctBc);
        if (pctHt > 0) System.out.printf("  Hutool慢 %.1f%%", pctHt);
        System.out.println();
    }

    static double avg(double[] a) {
        double s = 0;
        for (double v : a) s += v;
        return s / a.length;
    }
}
