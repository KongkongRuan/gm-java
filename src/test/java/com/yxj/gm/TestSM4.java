package com.yxj.gm;

import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.util.FileUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class TestSM4 {
//    public static void main(String[] args) {
//        UseKey useKey = new UseKey();
//        KeyPair generateSM2KeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
//        SecureRandom secureRandom = new SecureRandom();
//        byte[] key = new byte[16];
//        secureRandom.nextBytes(key);
//        byte[] msg = new byte[99560];
//        secureRandom.nextBytes(msg);
//
//        SM4Cipher sm4Cipher = new SM4Cipher();
//        long l = System.currentTimeMillis();
//        byte[] bytes = sm4Cipher.cipherEncrypt(key, msg, new byte[16]);
//        System.out.println("加密耗时："+(System.currentTimeMillis()-l));
//        l=System.currentTimeMillis();
//        byte[] sm4s = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(key), msg);
//        System.out.println("加密耗时："+(System.currentTimeMillis()-l));
//        System.out.println(Hex.toHexString(sm4s));
//
//
//        System.out.println(Hex.toHexString(bytes));
//    }

//    public static void main5(String[] args) {
//        UseKey useKey = new UseKey();
//        byte[] msg = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10,(byte)0x52,(byte)0x52};
//        byte[] key = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10};
//        SM4Cipher sm4Cipher = new SM4Cipher();
//        System.out.println("密钥："+Hex.toHexString(key));
//        byte[] mi = sm4Cipher.cipherEncrypt(key, msg, new byte[16]);
//        System.out.println("java-密文："+ Hex.toHexString(mi));
//        byte[] ming = sm4Cipher.cipherDecrypt(key, mi, new byte[16]);
//        System.out.println("java-明文："+Hex.toHexString(ming));
//        byte[] mic = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(key), msg);
//        System.out.println("c-密文：   "+ Hex.toHexString(mic));
//        byte[] mingc = useKey.cipherDecrype("SM4", new ZyxxSecretKey(key), mic);
//        System.out.println("c-明文：   "+Hex.toHexString(mingc));
//        int i = System.identityHashCode(useKey);
//        System.out.println(useKey);
//        System.out.println(i);
//        String s1 = "hh";
//        String s2 = "ss";
//        String s3 = "hhss";
//        String s4 = s1+s2;
//        System.out.println(s3.hashCode());
//        System.out.println(s4.hashCode());
//        int is3 = System.identityHashCode(s3);
//        System.out.println(is3);
//        int is4 = System.identityHashCode(s4);
//        System.out.println(is4);
//
//        SM4Cipher sm4_ecb = new SM4Cipher(ModeEnum.ECB);
//        byte[] mi_ecb = sm4_ecb.cipherEncrypt(key, msg, null);
//        System.out.println("ECB密文："+Hex.toHexString(mi_ecb));
//        byte[] ming_ecb = sm4_ecb.cipherDecrypt(key, mi_ecb, null);
//        System.out.println("ECB明文："+Hex.toHexString(ming_ecb));
//
//        SM4Cipher sm4_cbc = new SM4Cipher(ModeEnum.CBC);
//        byte[] mi_cbc = sm4_cbc.cipherEncrypt(key, msg, new byte[16]);
//        System.out.println("CBC密文："+Hex.toHexString(mi_cbc));
//        byte[] ming_cbc = sm4_cbc.cipherDecrypt(key, mi_cbc, new byte[16]);
//        System.out.println("CBC明文："+Hex.toHexString(ming_cbc));
//        SM4Cipher sm4_gcm = new SM4Cipher();
//        AEADExecution aeadExecution = sm4_gcm.cipherEncryptGCM(key, msg, new byte[12], "aad".getBytes(), 16);
//        System.out.println("GCM密文："+Hex.toHexString(aeadExecution.getCipherText()));
//        System.out.println("GCMtag："+Hex.toHexString(aeadExecution.getTag()));
//        byte[] ming_gcm = sm4_gcm.cipherDecryptGCM(key, aeadExecution.getCipherText(), new byte[12], "aad".getBytes(), aeadExecution.getTag());
//        System.out.println("GCM明文："+Hex.toHexString(ming_gcm));
//
//    }

//    public static void main1(String[] args) throws IOException {
////        String msg = "XDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYG";
//        SM4Cipher sm4Cipher = new SM4Cipher();
//        byte[] key = new byte[16];
//        SecureRandom secureRandom = new SecureRandom();
//        secureRandom.nextBytes(key);
//        long l = System.currentTimeMillis();
//        byte[] mi = sm4Cipher.cipherEncrypt(key, FileUtils.readFileToByteArray(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）.pdf")), new byte[16]);
//        System.out.println("加密耗时："+(System.currentTimeMillis()-l));
//
//        UseKey useKey = new UseKey();
//        long l1 = System.currentTimeMillis();
//        byte[] mic = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(key), FileUtils.readFileToByteArray(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）.pdf")));
//        System.out.println("组件化加密耗时："+(System.currentTimeMillis()-l1));
//
//
//
////        byte[] mi = sm4Cipher.cipherEncrypt(key, msg.getBytes(), new byte[16]);
////        byte[] ming = sm4Cipher.cipherDecrypt(key, mi, new byte[16]);
////        FileUtils.writeByteArrayToFile(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）解密后.pdf"), ming);
////        System.err.println(new String(ming));
//    }

    public static void main2(String[] args) {
        int count = 770371;
        /**
         * 创建线程池
         */
        ExecutorService executorService = Executors.newFixedThreadPool(10);
        ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executorService;
        //确定使用的线程数
        int processors = 2 * Runtime.getRuntime().availableProcessors() + 1;
        System.out.println(processors);
        if (count < processors) {
            processors = count;
        }
        //确定每个线程处理的数据量
        int size = count / processors;
        //确定每个线程处理的数据量
        int remainder = count % processors;
        for (int i = 0; i < processors; i++) {
            int start = i * size;
            int end = (i + 1) * size;
            if (i == processors - 1) {
                end += remainder;
            }
            int finalEnd = end;
            threadPoolExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    System.out.println(Thread.currentThread().getName()+"start:"+start+" end:"+ finalEnd + " count:"+(finalEnd-start));
                }
            });
        }

    }

    public static void main(String[] args) {
        /*
        私钥密文:279ed5ba8bcf5014567847388acdd116d3f62a1597513ad7b7bfdd4f34886fc8f03b4fc4e18d1ecd1e4b5e9d8fbbab86f08ef45fb0aa43fddef1851150ddd42480c135aebd175a06121cc731c4e63ddd6ac3823016fbda6a1b52bdb55a66f012af904636421dab1ebaefa9253f7de97442098f6c5c4d70d514c739b83a1b0f3fb0a85ac2c7d1107d8bebb6838ad11516
iv:e264853753e1de02fca5e3336a25839c
会话密钥:b168476a919cea42a3df0ba15bc69eae
         */
        SM4Cipher sm4Cipher= new SM4Cipher(ModeEnum.CBC);
        byte[] key = Hex.decode("fca13660a40d3d04f1c1934daa9e65a5");
        byte[] iv = Hex.decode("212e90407534ae58cfc0d8acd7b13f19");
        byte[] mi = Hex.decode("d9ad3d5c33f6932ec6fdbb2d9a8997bbeaf079a34dd89f022f35e90f2c7a069bc4a319b252e1b07414dbff2b853706e016e316e58a2e5d860358833ad9c0be7a33b3ee73bcdd0f8972425dc2319954a970b1410c505deb6e3cd03f6922df64916920df7356ec5c041402254aacd90d412b9e4d5561aaa707f94de3ba20f81c0d6967eeaa14e7a93a5811ab1499061f4a");
//        byte[] ming = sm4Cipher.cipherDecrypt(key, msg, iv);
//        byte[] ming = Hex.decode("308186020100301306072A8648CE3D020106082A811CCF5501822D046C306A0201010220F3445EF90EA0BFE3E6DB4CE60B9EA47675D759FA2C4D0429AE4FA8F805150C00A14303410010D68A7CAEB590BCEE271C198C2DE09CCEA692754961D8EF1E396C6A594DD07CBB1710D80EBACF46F022398B57267CE8D4C589DE76BAF6ECF94D8EC7492F2879");
//        byte[] javami = sm4Cipher.cipherEncrypt(key, ming, iv);
//        System.out.println(Hex.toHexString(javami));
        byte[] javaming = sm4Cipher.cipherDecrypt(key, mi, iv);
        System.out.println(Hex.toHexString(javaming));
        byte[] bytes = ASN1Util.Asn1PriKeyToPriKey(javaming);
        System.out.println(Hex.toHexString(bytes));
    }
}
