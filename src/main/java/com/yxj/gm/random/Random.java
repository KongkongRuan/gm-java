package com.yxj.gm.random;

import com.kms.jca.UseKey;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.util.FileUtils;
import com.yxj.gm.util.TLSUtil;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class Random {
    public static void main(String[] args) throws IOException {
//        UseKey useKey = new UseKey();
        long l = System.currentTimeMillis();
//        SecretKey secretKey = useKey.secureRandom(15000000);
//        System.out.println("zjh："+(System.currentTimeMillis()-l));
//        System.out.println(test1(secretKey.getEncoded()));
//        FileUtils.writeByteArrayToFile(new File("D:\\random\\zjhrandom.txt"),secretKey.getEncoded());
//        SecureRandom secureRandom = new SecureRandom();
//
//
//        byte[] random = new byte[15000000];
//        l = System.currentTimeMillis();
//        secureRandom.nextBytes(random);
//        System.out.println("java："+(System.currentTimeMillis()-l));
//        System.out.println(test1(random));
//        FileUtils.writeByteArrayToFile(new File("D:\\random\\javarandom.txt"),random);
//        random=secretKey.getEncoded();
////        random = new byte[]{(byte) 0xAA,(byte) 0xAA,(byte) 0xAA,(byte) 0xAA};
//        l = System.currentTimeMillis();
//
//        random=myRandomBySM3(16);
//        System.out.println("SM3："+(System.currentTimeMillis()-l));
//        l = System.currentTimeMillis();
////        random=myRandomByHkdf(1300000);
//        System.out.println("hkdf:"+(System.currentTimeMillis()-l));
////        FileUtils.writeByteArrayToFile(new File("D:\\random.txt"),random);

        l = System.currentTimeMillis();
        byte[] bytes = myRandomBySM3Thread(10000);
        System.out.println("SM3 Thread:"+(System.currentTimeMillis()-l));
        System.out.println(test1(bytes));
//        FileUtils.writeByteArrayToFile(new File("D:\\random\\sm3thread.txt"),bytes);

        l = System.currentTimeMillis();
        byte[] bytes2 = myRandomBySM3(10000);
        System.out.println("SM3 :"+(System.currentTimeMillis()-l));

//        FileUtils.write(new File("D:\\testRandom.txt"), Hex.toHexString(bytes),"utf8");


    }

    public static double test1(byte[] random){
        long S = 0;
        for (int i = 0; i < random.length; i++) {
            S+=((random[i] >> 7) & 0x1)*2-1;
            S+=((random[i] >> 6) & 0x1)*2-1;
            S+=((random[i] >> 5) & 0x1)*2-1;
            S+=((random[i] >> 4) & 0x1)*2-1;
            S+=((random[i] >> 3) & 0x1)*2-1;
            S+=((random[i] >> 2) & 0x1)*2-1;
            S+=((random[i] >> 1) & 0x1)*2-1;
            S+=(random[i] & 0x1)*2-1;
        }
        System.out.println("S:");
        System.out.println(S);
        double V = (double) Math.abs(S) /1000;

        return  erfc(V / Math.sqrt(2));

    }
    private static byte[] getCurrentPCinfor(){
        long l = System.currentTimeMillis();
        String threadInfo = Thread.currentThread().getName() + "-" + Thread.currentThread().getId();
        long totalMemory = Runtime.getRuntime().totalMemory();
        long freeMemory = Runtime.getRuntime().freeMemory();
        long maxMemory = Runtime.getRuntime().maxMemory();
        String memoryInfo =totalMemory+"-"+freeMemory+"-"+maxMemory;
        return (l+threadInfo + memoryInfo).getBytes();
    }

    public static byte[] RandomBySM3(int length){
        if(length<1000){
            return myRandomBySM3(length);
        }else {
            return myRandomBySM3Thread(length);
        }
    }
    public static byte[] myRandomBySM3(int length){

        byte[] result = new byte[length];
        int x=length/32;
        int y=length%32;
        SM3Digest sm3Digest = new SM3Digest();
        byte[] bytes = new SM3Digest().doFinal(getCurrentPCinfor());
        if(length<=32){
            System.arraycopy(bytes,0,result,0,length);
        }else {
            System.arraycopy(bytes,0,result,0,32);
            for (int i = 1; i < x; i++) {
                bytes = sm3Digest.doFinal(bytes);
                System.arraycopy(bytes,0,result,32*(i-1)+32,32);
            }
            bytes = sm3Digest.doFinal(bytes);
            if(y!=0){
                System.arraycopy(bytes,0,result,32*x,y);
            }
        }
        return result;

    }
    public static byte[] myRandomBySM3Thread(int length){

        byte[] result = new byte[length];
        int x=length/32;
        int y=length%32;
        SM3Digest sm3Digest = new SM3Digest();
        byte[] bytes = new SM3Digest().doFinal(getCurrentPCinfor());
        if(length<=32){
            System.arraycopy(bytes,0,result,0,length);
        }else {
            int processors = 2 * Runtime.getRuntime().availableProcessors() + 1;
//            int processors = 2 ;
            ExecutorService executorService = Executors.newFixedThreadPool(processors+2);
            ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executorService;
//            System.arraycopy(bytes,0,result,0,32);
            int count = x/processors;
            int remainder = x%processors;
            if(x<processors){
                processors=x;
            }
            int countDownLatchCount =0;
            if(remainder!=0){
                countDownLatchCount = processors+1;
            }else {
                countDownLatchCount = processors;
            }

            CountDownLatch countDownLatch = new CountDownLatch(processors+1);

            for (int i = 0; i < processors; i++) {
                int start = 32*i*count;
                int end = 32*count*(i+1);
                threadPoolExecutor.execute(new Runnable() {
                    final SM3Digest tSm3Digest2 = new SM3Digest();

                    byte[] tBytes2 = tSm3Digest2.doFinal(getCurrentPCinfor());


                    @Override
                    public void run() {
                        for (int j = 0; j < count; j++) {
                            tBytes2 = tSm3Digest2.doFinal(tBytes2);
                            System.arraycopy(tBytes2,0,result,start+j*32,32);
                        }
                        countDownLatch.countDown();
                    }
                });
            }
            if(remainder!=0){
                int start = 32*count*processors;
                int end = 32*x;
                threadPoolExecutor.execute(new Runnable() {
                    final SM3Digest tSm3Digest = new SM3Digest();
                    byte[] tBytes = tSm3Digest.doFinal(getCurrentPCinfor());
                    @Override
                    public void run() {
                        for (int j = 0; j < remainder; j++) {
                            tBytes = tSm3Digest.doFinal(tBytes);
                            System.arraycopy(tBytes,0,result,start+j*32,32);
                        }
                        countDownLatch.countDown();
                    }
                });
            }
            try {
                countDownLatch.await();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            threadPoolExecutor.shutdown();

            bytes = sm3Digest.doFinal(bytes);
            if(y!=0){
                System.arraycopy(bytes,0,result,32*x,y);
            }
        }
        return result;

    }
    public static byte[] myRandomByHkdf(int length){
        Security.addProvider(new XaProvider());
        MessageDigest xaMd = null;
        try {
            xaMd = MessageDigest.getInstance("SM3", "XaProvider");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }

        byte[] md = new SM3Digest().doFinal(getCurrentPCinfor());

//        byte[] md = new SM3Digest().doFinal(String.valueOf(l).getBytes());

        byte[] key = new byte[16];
        System.arraycopy(md, 0, key, 0, 16);
        return TLSUtil.hkdf(xaMd, null, key, "1234".getBytes(), length);
    }

    //erfc函数
    public static double erfc(double x)
    {
        return 1-erf(x);
    }
    //erf函数
    public static double erf(double x)
    {
        double result = 0;
        int index = 0;
        do
        {
            index++;
        } while (x / Math.pow(10, index) > 1e-3);//设置计算精度
        int maxIndex =(int) Math.pow(10, index);
        double deltaX = x / maxIndex;
        for (int i = 0; i <=maxIndex; i++)
        {
            if (i > 0 && i<maxIndex)
            {
                result += 2 * Math.exp(-Math.pow(deltaX * i, 2));
                continue;
            }
            else if (i == maxIndex)
            {
                result += Math.exp(-Math.pow(deltaX * i, 2));
                continue;
            }
            else if(i==0){
                result += Math.exp(-Math.pow(deltaX * i, 2));
                continue;
            }
        }
        return result*deltaX/Math.pow(Math.PI,0.5);
    }
}
