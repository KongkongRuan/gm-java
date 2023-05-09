package com.yxj.gm;

import com.kms.jca.UseKey;
import com.kms.provider.key.ZyxxSecretKey;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.util.FileUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class TestSM4 {
    public static void main1(String[] args) {
        UseKey useKey = new UseKey();
        byte[] msg = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10,(byte)0x52,(byte)0x52};
        byte[] key = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10};
        SM4Cipher sm4Cipher = new SM4Cipher();
        System.out.println("密钥："+Hex.toHexString(key));
        byte[] mi = sm4Cipher.cipherEncrypt(key, msg, new byte[16]);
        System.out.println("java-密文："+ Hex.toHexString(mi));
        byte[] ming = sm4Cipher.cipherDecrypt(key, mi, new byte[16]);
        System.out.println("java-明文："+Hex.toHexString(ming));
        byte[] mic = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(key), msg);
        System.out.println("c-密文：   "+ Hex.toHexString(mic));
        byte[] mingc = useKey.cipherDecrype("SM4", new ZyxxSecretKey(key), mic);
        System.out.println("c-明文：   "+Hex.toHexString(mingc));
        int i = System.identityHashCode(useKey);
        System.out.println(useKey);
        System.out.println(i);
        String s1 = "hh";
        String s2 = "ss";
        String s3 = "hhss";
        String s4 = s1+s2;
        System.out.println(s3.hashCode());
        System.out.println(s4.hashCode());
        int is3 = System.identityHashCode(s3);
        System.out.println(is3);
        int is4 = System.identityHashCode(s4);
        System.out.println(is4);

        SM4Cipher sm4_ecb = new SM4Cipher(ModeEnum.ECB);
        byte[] mi_ecb = sm4_ecb.cipherEncrypt(key, msg, null);
        System.out.println("ECB密文："+Hex.toHexString(mi_ecb));
        byte[] ming_ecb = sm4_ecb.cipherDecrypt(key, mi_ecb, null);
        System.out.println("ECB明文："+Hex.toHexString(ming_ecb));

        SM4Cipher sm4_cbc = new SM4Cipher(ModeEnum.CBC);
        byte[] mi_cbc = sm4_cbc.cipherEncrypt(key, msg, new byte[16]);
        System.out.println("CBC密文："+Hex.toHexString(mi_cbc));
        byte[] ming_cbc = sm4_cbc.cipherDecrypt(key, mi_cbc, new byte[16]);
        System.out.println("CBC明文："+Hex.toHexString(ming_cbc));

    }

    public static void main(String[] args) throws IOException {
//        String msg = "XDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYGXDYG";
        SM4Cipher sm4Cipher = new SM4Cipher();
        byte[] key = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        long l = System.currentTimeMillis();
        byte[] mi = sm4Cipher.cipherEncrypt(key, FileUtils.readFileToByteArray(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）.pdf")), new byte[16]);
        System.out.println("加密耗时："+(System.currentTimeMillis()-l));

        UseKey useKey = new UseKey();
        long l1 = System.currentTimeMillis();
        byte[] mic = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(key), FileUtils.readFileToByteArray(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）.pdf")));
        System.out.println("组件化加密耗时："+(System.currentTimeMillis()-l1));



//        byte[] mi = sm4Cipher.cipherEncrypt(key, msg.getBytes(), new byte[16]);
//        byte[] ming = sm4Cipher.cipherDecrypt(key, mi, new byte[16]);
//        FileUtils.writeByteArrayToFile(new File("D:\\soft\\面试题\\java电子书\\10w+字总结的Java面试题（附答案）解密后.pdf"), ming);
//        System.err.println(new String(ming));
    }

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
}
