package com.yxj.gm.RSA.Key;




import com.sun.scenario.effect.impl.sw.java.JSWBlend_SRC_OUTPeer;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;

public class RSAKeyPairGenerate {

    private static final BigInteger E = BigInteger.valueOf(65537);

    public static void generateRSAKeyPair(int bitLen){
        SecureRandom secureRandom = new SecureRandom();
        BigInteger p = myGeneratePrime(bitLen / 2, secureRandom);
        BigInteger q = myGeneratePrime(bitLen / 2, secureRandom);

//        BigInteger p = BigInteger.probablePrime(bitLen / 2, secureRandom);
//        BigInteger q = BigInteger.probablePrime(bitLen / 2, secureRandom);



        BigInteger n = p.multiply(q);
        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger q_1 = q.subtract(BigInteger.ONE);
        BigInteger phi = p_1.multiply(q_1);
//        long l = System.currentTimeMillis();
//        BigInteger d = E.modInverse(phi);
//        System.err.println(System.currentTimeMillis()-l);
//        System.out.println("d:"+d.toString(16));
        BigInteger d = DataConvertUtil.ex_gcd_ny(E, phi);
//        System.out.println("d:"+d.toString(16));
//        System.out.println("n:"+n.toString(16).toUpperCase());



    }
    public static void main(String[] args) throws NoSuchAlgorithmException {

//        SecureRandom secureRandom = new SecureRandom();
//        int testCount = 1000;
//        long la = System.currentTimeMillis();
//        int keyLen = 1024;
//        byte[] random = new byte[keyLen/8];
//        for (int i = 0; i < 100000; i++) {
////            System.out.println("------------------------------------------------");
//
//            secureRandom.nextBytes(random);
//            random[0]= (byte)(random[0]|1);
//            random[keyLen/8-1]= (byte)(random[keyLen/8-1]|1);
////            System.out.println(Hex.toHexString(DataConvertUtil.byteToBitArray(random[255])));
//            long l = System.currentTimeMillis();
//            long bitime =0;
////            boolean probablePrime = new BigInteger(1,random).isProbablePrime(testCount);
////            long bitime=System.currentTimeMillis()-l;
////            System.out.println("BigInteger:"+probablePrime+"---"+bitime);
//
//            l = System.currentTimeMillis();
//            long bcTime =System.currentTimeMillis()-l;
//            boolean mrProbablePrime = Primes.isMRProbablePrime(new BigInteger(1,random), secureRandom, testCount);
////            System.out.println("BC:"+mrProbablePrime+"---"+bcTime);
//            if(i==0){
////                System.err.println("FIRST TIME:"+(bcTime-bitime));
//            }
//            if(mrProbablePrime){
//                System.err.println("1. random break---:"+(System.currentTimeMillis()-la));
//                System.out.println("LAST TIME:"+(bcTime-bitime));
//                break;
//            }
//        }
//        System.out.println("my Random:"+Hex.toHexString(random));
//        boolean mrProbablePrime = Primes.isMRProbablePrime(new BigInteger(1,random), secureRandom, 1000);
//        System.out.println(mrProbablePrime);
//        la = System.currentTimeMillis();
//        BigInteger bigInteger = generateNBitRandomPrime(keyLen);
//        System.err.println("2. generateNBitRandomPrime:"+(System.currentTimeMillis()-la));
//        System.out.println("generateNBitRandomPrime random:"+bigInteger.toString(16));
//        mrProbablePrime = Primes.isMRProbablePrime(bigInteger, secureRandom, 1000);
//        System.out.println(mrProbablePrime);
//        la = System.currentTimeMillis();
//        BigInteger bigInteger1 = BigInteger.probablePrime(keyLen, secureRandom);
//        System.err.println("3. BigInteger.probablePrime:"+(System.currentTimeMillis()-la));
//        System.out.println("BigInteger.probablePrime random:"+bigInteger1.toString(16));
//        mrProbablePrime = Primes.isMRProbablePrime(bigInteger1, secureRandom, 1000);
//        System.out.println(mrProbablePrime);
//        la=System.currentTimeMillis();
//        BigInteger bigInteger2 = myGeneratePrime(keyLen, 100);
//        System.err.println("4. myGeneratePrime :"+(System.currentTimeMillis()-la));
//        mrProbablePrime = Primes.isMRProbablePrime(bigInteger2, secureRandom, 1000);
//        System.out.println(mrProbablePrime);
//
//
//        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
//        la = System.currentTimeMillis();
//        KeyPair keyPair = rsa.generateKeyPair();
//        System.out.println("rsa.generateKeyPair:"+(System.currentTimeMillis()-la));

//        long l = System.currentTimeMillis();
//        SecureRandom secureRandom = new SecureRandom();
//        for (int i = 0; i < 1; i++) {
//            BigInteger.probablePrime(2048,secureRandom);
//        }
//        System.out.println("BigInteger.probablePrime 100 time:"+(System.currentTimeMillis()-l));
//        l=System.currentTimeMillis();
//        for (int i = 0; i < 1; i++) {
//            myGeneratePrime(2048,secureRandom);
//        }
//        System.out.println("myGeneratePrime 100 time:"+(System.currentTimeMillis()-l));


        long l = System.currentTimeMillis();
        generateRSAKeyPair(4096);
        System.out.println("generateRSAKeyPair:"+(System.currentTimeMillis()-l));
    }

    public static BigInteger myGeneratePrime(int bitLen,SecureRandom secureRandom){
        BigInteger base = new BigInteger(bitLen,secureRandom).setBit(bitLen-1).setBit(0);
        BigInteger amplitude = BigInteger.TEN;
        BigInteger TWO = BigInteger.valueOf(2);
        int i=0;
        while (!Primes.isMRProbablePrime(base, secureRandom, 100)){
            base=base.add(amplitude);
            amplitude=amplitude.add(TWO);

            if(i++==50){
                base = new BigInteger(bitLen,secureRandom).setBit(bitLen-1).setBit(0);
            }
        }
        return base;
    }
    private static int processors = 2 * Runtime.getRuntime().availableProcessors() + 1;
    /**
     * 创建线程池
     */
    static ExecutorService executorService = Executors.newFixedThreadPool(10);
    static ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executorService;
    static volatile boolean isPrime = false;


    private static BigInteger generateNBitRandomPrime(int n) {
        BigInteger tmp = new BigInteger("2").pow(n - 1);// 最高位肯定是1
        BigInteger result = new BigInteger("2").pow(n - 1);
        Random random = new Random();
        int r1 = random.nextInt(101);// 产生0-100的整数，用于确定0和1的比例
        int r2;

        while (true) {// 循环产生数，直到该数为素数
            for (int i = n - 2; i >= 0; i--) {// 逐位产生表示数的0和1，并根据所在位计算结果相加起来
                r2 = random.nextInt(101);
                if (0 < r2 && r2 < r1) {// 产生的数为1
                    result = result.add(new BigInteger("2").pow(i));
                }
                continue;
            }

            if (isPrime(result)) {// 素数判断
                return result;
            }

            result = tmp;// 重新计算
        }
    }
    private static boolean isPrime(BigInteger p) {
        if (p.compareTo(new BigInteger("2")) == -1) {// 小于2直接返回false
            return false;
        }
        if ((p.compareTo(new BigInteger("2")) != 0) && (p.remainder(new BigInteger("2")).compareTo(BigInteger.ZERO) == 0)) {// 不等于2且是偶数直接返回false
            return false;
        }

        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger m = p_1;// 找到q和m使得p = 1 + 2^q * m
        int q = m.getLowestSetBit();// 二进制下从右往左返回第一次出现1的索引
        m = m.shiftRight(q);

        for (int i = 0; i < 5; i++) {// 判断的轮数，精度、轮数和时间三者之间成正比关系
            BigInteger b;
            do {// 在区间1~p上生成均匀随机数
                b = new BigInteger(String.valueOf(p.bitLength()));
            } while (b.compareTo(BigInteger.ONE) <= 0 || b.compareTo(p) >= 0);

            int j = 0;
            BigInteger z = expMod(b, m, p);
            while (!((j == 0 && z.equals(BigInteger.ONE)) || z.equals(p_1))) {
                if ((j > 0 && z.equals(BigInteger.ONE)) || ++j == q) {
                    return false;
                }
                z = expMod(z, new BigInteger("2"), p);
            }
        }

        return true;
    }
    /**
     * 蒙哥马利快速幂模运算，返回base^exponent mod module的结果。
     *
     * @param base     底数
     * @param exponent 指数
     * @param module   模数
     * @return result 结果
     */
    private static BigInteger expMod(BigInteger base, BigInteger exponent, BigInteger module) {
        BigInteger result = BigInteger.ONE;
        BigInteger tmp = base.mod(module);

        while (exponent.compareTo(BigInteger.ZERO) != 0) {
            if ((exponent.and(BigInteger.ONE).compareTo(BigInteger.ZERO)) != 0) {
                result = result.multiply(tmp).mod(module);
            }
            tmp = tmp.multiply(tmp).mod(module);
            exponent = exponent.shiftRight(1);
        }

        return result;
    }
}
