package com.yxj.gm;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.util.JNI.Nat256Native;

import java.io.*;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TPS（Transactions Per Second）性能测试
 *
 * 防缓存优化：
 *   预生成 POOL_SIZE 组不同的输入数据，每个线程通过 ThreadLocal 计数器循环取用，
 *   避免 CPU L1/L2 cache 始终命中同一内存行导致结果偏乐观。
 *
 * 与 BenchmarkComparison 的区别：
 *   - BenchmarkComparison：单线程批量执行，测量每次操作的平均耗时（延迟视角）
 *   - TpsTest：多线程并发执行，在固定时间窗口内统计每秒完成的事务数（吞吐量视角）
 */
public class TpsTest {

    /** 测试持续时间（秒） */
    private static final int DURATION_SECONDS = 5;
    /** 预热时间（秒） */
    private static final int WARMUP_SECONDS = 2;
    /** 并发线程数列表 */
    private static final int[] THREAD_COUNTS = {1, 8, 32};
    /** SM4 测试数据大小（字节） */
    private static final int SM4_DATA_SIZE = 1024; // 1KB
    /** 数据池大小（必须是 2 的幂，方便位运算取模） */
    private static final int POOL_SIZE = 128;
    private static final int POOL_MASK = POOL_SIZE - 1;

    // ==================== 预生成测试数据（数据池） ====================

    private static KeyPair sm2KeyPair;
    private static byte[] sm2PubKey;
    private static byte[] sm2PriKey;

    /** SM2 消息池 / 密文池 / 签名池 */
    private static byte[][] sm2MsgPool;
    private static byte[][] sm2EncryptedPool;
    private static byte[][] sm2SignaturePool;

    /** SM3 数据池 */
    private static byte[][] sm3DataPool;

    /** SM4 数据池 / 密文池 */
    private static byte[] sm4Key = new byte[16];
    private static byte[] sm4Iv = new byte[16];
    private static byte[][] sm4DataPool;
    private static byte[][] sm4EncryptedECBPool;
    private static byte[][] sm4EncryptedCBCPool;
    private static byte[][] sm4EncryptedCTRPool;

    private static SM2Cipher sm2Cipher = new SM2Cipher();
    private static SM2Signature sm2Signer = new SM2Signature();

    /** 每线程独立的数据池索引，避免竞争 */
    private static final ThreadLocal<Integer> poolIdx = ThreadLocal.withInitial(() -> 0);

    // ==================== 入口 ====================

    public static void main(String[] args) throws Exception {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter tsFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HHmmss");
        String timestamp = now.format(tsFormatter);
        String yyyymmdd = now.format(dateFormatter);
        String hhmmss = now.format(timeFormatter);
        int jdkMajor = javaMajorVersion();

        String logFileName = String.format(Locale.US, "tps-%s-%s-JDK%d.log", yyyymmdd, hhmmss, jdkMajor);
        File logFile = new File("reports", logFileName);

        PrintStream originalOut = System.out;
        PrintStream fileOut = null;
        PrintStream tee = null;
        try {
            File parent = logFile.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            fileOut = new PrintStream(new FileOutputStream(logFile), true, "UTF-8");
            tee = new PrintStream(new TeeOutputStream(originalOut, fileOut), true, "UTF-8");
            System.setOut(tee);
        } catch (Exception e) {
            System.err.println("无法创建日志文件: " + e.getMessage());
        }

        try {
            String gitCommit = gitCommitShort();
            String pomVersion = readPomVersion();

            initTestData();

            System.out.println("════════════════════════════════════════════════════════════════");
            System.out.println("  测试类型：TpsTest（吞吐量）");
            System.out.println("════════════════════════════════════════════════════════════════");
            System.out.printf("  测试时间     : %s%n", timestamp);
            System.out.printf("  Git Commit   : %s%n", gitCommit);
            System.out.printf("  版本         : %s%n", pomVersion);
            System.out.printf("  Nat256       : %s%n", Nat256Native.isAvailable() ? "JNI 加速 (C)" : "Java 实现");
            System.out.printf("  Java         : %s (%s)%n", System.getProperty("java.version"), System.getProperty("java.vm.name"));
            System.out.printf("  OS           : %s %s%n", System.getProperty("os.name"), System.getProperty("os.arch"));
            System.out.printf("  CPUs         : %d%n", Runtime.getRuntime().availableProcessors());
            System.out.printf("  测试时长     : %d 秒/轮，预热 %d 秒%n", DURATION_SECONDS, WARMUP_SECONDS);
            System.out.printf("  并发线程     : %s%n", Arrays.toString(THREAD_COUNTS));
            System.out.printf("  数据池大小   : %d 组（防缓存）%n", POOL_SIZE);
            System.out.printf("  SM4 数据量   : %d bytes/事务%n", SM4_DATA_SIZE);
            System.out.println("════════════════════════════════════════════════════════════════\n");

            // SM2 系列
            runTpsBenchmark("SM2 密钥对生成", TpsTest::txnSM2KeyGen);
            runTpsBenchmark("SM2 加密", TpsTest::txnSM2Encrypt);
            runTpsBenchmark("SM2 解密", TpsTest::txnSM2Decrypt);
            runTpsBenchmark("SM2 签名", TpsTest::txnSM2Sign);
            runTpsBenchmark("SM2 验签", TpsTest::txnSM2Verify);
            runTpsBenchmark("SM2 加解密(完整)", TpsTest::txnSM2EncDec);
            runTpsBenchmark("SM2 签名验签(完整)", TpsTest::txnSM2SignVerify);

            // SM3 系列
            runTpsBenchmark("SM3 摘要(1KB)", TpsTest::txnSM3);

            // SM4 系列
            runTpsBenchmark("SM4-ECB 加密", TpsTest::txnSM4ECBEncrypt);
            runTpsBenchmark("SM4-ECB 解密", TpsTest::txnSM4ECBDecrypt);
            runTpsBenchmark("SM4-CBC 加密", TpsTest::txnSM4CBCEncrypt);
            runTpsBenchmark("SM4-CBC 解密", TpsTest::txnSM4CBCDecrypt);
            runTpsBenchmark("SM4-CTR 加密", TpsTest::txnSM4CTREncrypt);
            runTpsBenchmark("SM4-CTR 解密", TpsTest::txnSM4CTRDecrypt);

            System.out.println("════════════════════════════════════════════════════════════════");
            System.out.println("  全部 TPS 测试完成");
            System.out.println("════════════════════════════════════════════════════════════════");
            System.out.println("\n  报告已保存: " + logFile.getPath());
        } finally {
            if (tee != null) {
                tee.flush();
            }
            System.setOut(originalOut);
            if (fileOut != null) {
                fileOut.close();
            }
        }
    }

    private static int javaMajorVersion() {
        String spec = System.getProperty("java.specification.version", "");
        if (spec.startsWith("1.")) {
            spec = spec.substring(2);
        }
        try {
            return Integer.parseInt(spec);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static String gitCommitShort() {
        try {
            Process p = new ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                    .directory(new File("."))
                    .redirectErrorStream(true)
                    .start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line = r.readLine();
                p.waitFor();
                return line != null ? line.trim() : "unknown";
            }
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static String readPomVersion() {
        try {
            File pom = new File("pom.xml");
            if (!pom.exists()) return "unknown";
            try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(pom), "UTF-8"))) {
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.contains("<version>") && line.contains("</version>")) {
                        int s = line.indexOf("<version>") + "<version>".length();
                        int e = line.indexOf("</version>");
                        String v = line.substring(s, e).trim();
                        if (!v.startsWith("${")) {
                            return v;
                        }
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return "unknown";
    }

    /** 同时向控制台和文件输出 */
    private static class TeeOutputStream extends OutputStream {
        private final OutputStream out1;
        private final OutputStream out2;

        TeeOutputStream(OutputStream out1, OutputStream out2) {
            this.out1 = out1;
            this.out2 = out2;
        }

        @Override
        public void write(int b) throws IOException {
            out1.write(b);
            out2.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out1.write(b, off, len);
            out2.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out1.flush();
            out2.flush();
        }
    }

    // ==================== 初始化数据池 ====================

    private static void initTestData() {
        java.security.SecureRandom rng = new java.security.SecureRandom();

        sm2KeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        sm2PubKey = sm2KeyPair.getPublic().getEncoded();
        sm2PriKey = sm2KeyPair.getPrivate().getEncoded();

        // SM2 消息池：128 组不同消息
        sm2MsgPool = new byte[POOL_SIZE][];
        sm2EncryptedPool = new byte[POOL_SIZE][];
        sm2SignaturePool = new byte[POOL_SIZE][];
        for (int i = 0; i < POOL_SIZE; i++) {
            byte[] msg = new byte[32];
            rng.nextBytes(msg);
            sm2MsgPool[i] = msg;
            sm2EncryptedPool[i] = sm2Cipher.SM2CipherEncrypt(msg, sm2PubKey);
            sm2SignaturePool[i] = sm2Signer.signature(msg, null, sm2PriKey, sm2PubKey);
        }

        // SM3 数据池：128 组不同 1KB 数据
        sm3DataPool = new byte[POOL_SIZE][];
        for (int i = 0; i < POOL_SIZE; i++) {
            byte[] data = new byte[1024];
            rng.nextBytes(data);
            sm3DataPool[i] = data;
        }

        // SM4 密钥/IV
        rng.nextBytes(sm4Key);
        rng.nextBytes(sm4Iv);

        // SM4 数据池：128 组不同 1KB 数据 + 对应密文
        sm4DataPool = new byte[POOL_SIZE][];
        sm4EncryptedECBPool = new byte[POOL_SIZE][];
        sm4EncryptedCBCPool = new byte[POOL_SIZE][];
        sm4EncryptedCTRPool = new byte[POOL_SIZE][];
        SM4Cipher sm4ECB = new SM4Cipher(ModeEnum.ECB);
        SM4Cipher sm4CBC = new SM4Cipher(ModeEnum.CBC);
        SM4Cipher sm4CTR = new SM4Cipher(ModeEnum.CTR);
        for (int i = 0; i < POOL_SIZE; i++) {
            byte[] data = new byte[SM4_DATA_SIZE];
            rng.nextBytes(data);
            sm4DataPool[i] = data;
            sm4EncryptedECBPool[i] = sm4ECB.cipherEncrypt(sm4Key, data, null);
            sm4EncryptedCBCPool[i] = sm4CBC.cipherEncrypt(sm4Key, data, sm4Iv);
            sm4EncryptedCTRPool[i] = sm4CTR.cipherEncrypt(sm4Key, data, sm4Iv);
        }
    }

    /** 获取下一个数据池索引（线程安全，无竞争） */
    private static int nextIdx() {
        int idx = poolIdx.get();
        poolIdx.set((idx + 1) & POOL_MASK);
        return idx;
    }

    // ==================== TPS 测试核心逻辑 ====================

    private static void runTpsBenchmark(String name, TxnRunnable txn) {
        System.out.printf("╔══ %-30s ══╗%n", name);

        System.out.printf("    预热中 (%d 秒)...%n", WARMUP_SECONDS);
        warmup(txn);

        System.out.printf("    %-8s │ %14s │ %14s │ %12s%n", "线程数", "完成事务数", "TPS", "平均延迟");
        System.out.printf("    %-8s─┼─%14s─┼─%14s─┼─%12s%n", "───────", "──────────────", "──────────────", "────────────");

        for (int threads : THREAD_COUNTS) {
            TpsResult result = measureTps(threads, txn);
            System.out.printf("    %-8d │ %14d │ %14.1f │ %10.3f ms%n",
                    threads, result.txnCount, result.tps, result.avgLatencyMs);
        }
        System.out.println();
    }

    private static void warmup(TxnRunnable txn) {
        AtomicLong counter = new AtomicLong(0);
        AtomicBoolean stop = new AtomicBoolean(false);

        Thread warmupThread = new Thread(() -> {
            while (!stop.get()) {
                try {
                    txn.run();
                    counter.incrementAndGet();
                } catch (Exception e) {
                    // ignore
                }
            }
        });
        warmupThread.setDaemon(true);
        warmupThread.start();

        try {
            Thread.sleep(WARMUP_SECONDS * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        stop.set(true);
        try {
            warmupThread.join(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        System.out.printf("    预热完成，执行了 %d 次事务%n", counter.get());
    }

    private static TpsResult measureTps(int threadCount, TxnRunnable txn) {
        final AtomicLong txnCount = new AtomicLong(0);
        final AtomicLong totalLatencyNanos = new AtomicLong(0);
        final CountDownLatch ready = new CountDownLatch(threadCount);
        final CountDownLatch start = new CountDownLatch(1);
        final CountDownLatch done = new CountDownLatch(threadCount);

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        AtomicBoolean stop = new AtomicBoolean(false);

        for (int i = 0; i < threadCount; i++) {
            pool.submit(() -> {
                // 每个线程重置自己的数据池索引
                poolIdx.set(0);
                ready.countDown();
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }

                while (!stop.get()) {
                    long t0 = System.nanoTime();
                    try {
                        txn.run();
                    } catch (Exception e) {
                        continue;
                    }
                    long elapsed = System.nanoTime() - t0;
                    txnCount.incrementAndGet();
                    totalLatencyNanos.addAndGet(elapsed);
                }
                done.countDown();
            });
        }

        try {
            ready.await();
            long startTime = System.currentTimeMillis();
            start.countDown();

            // --- 每秒输出实时 TPS ---
            System.out.printf("        每秒 TPS: ");
            long lastCount = 0;
            for (int sec = 1; sec <= DURATION_SECONDS; sec++) {
                Thread.sleep(1000L);
                long currentCount = txnCount.get();
                long deltaCount = currentCount - lastCount;
                lastCount = currentCount;
                System.out.printf("[%ds]=%d  ", sec, deltaCount);
                if (sec % 5 == 0 && sec < DURATION_SECONDS) {
                    System.out.printf("%n                  ");
                }
            }
            System.out.println();

            stop.set(true);
            done.await();
            long actualDurationMs = System.currentTimeMillis() - startTime;
            pool.shutdownNow();

            long count = txnCount.get();
            double tps = count / (actualDurationMs / 1000.0);
            double avgLatencyMs = count > 0
                    ? (totalLatencyNanos.get() / (double) count) / 1_000_000.0
                    : 0;

            return new TpsResult(count, tps, avgLatencyMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
            return new TpsResult(0, 0, 0);
        }
    }

    // ==================== 事务定义（每次使用不同数据） ====================

    /** SM2 密钥对生成（天然无缓存问题） */
    private static void txnSM2KeyGen() {
        SM2KeyPairGenerate.generateSM2KeyPair();
    }

    /** SM2 加密 */
    private static void txnSM2Encrypt() {
        int idx = nextIdx();
        sm2Cipher.SM2CipherEncrypt(sm2MsgPool[idx], sm2PubKey);
    }

    /** SM2 解密 */
    private static void txnSM2Decrypt() {
        int idx = nextIdx();
        sm2Cipher.SM2CipherDecrypt(sm2EncryptedPool[idx], sm2PriKey);
    }

    /** SM2 加密+解密（完整事务） */
    private static void txnSM2EncDec() {
        int idx = nextIdx();
        byte[] enc = sm2Cipher.SM2CipherEncrypt(sm2MsgPool[idx], sm2PubKey);
        sm2Cipher.SM2CipherDecrypt(enc, sm2PriKey);
    }

    /** SM2 签名 */
    private static void txnSM2Sign() {
        int idx = nextIdx();
        sm2Signer.signature(sm2MsgPool[idx], null, sm2PriKey, sm2PubKey);
    }

    /** SM2 验签 */
    private static void txnSM2Verify() {
        int idx = nextIdx();
        sm2Signer.verify(sm2MsgPool[idx], null, sm2SignaturePool[idx], sm2PubKey);
    }

    /** SM2 签名+验签（完整事务） */
    private static void txnSM2SignVerify() {
        int idx = nextIdx();
        byte[] sig = sm2Signer.signature(sm2MsgPool[idx], null, sm2PriKey, sm2PubKey);
        sm2Signer.verify(sm2MsgPool[idx], null, sig, sm2PubKey);
    }

    /** SM3 摘要 */
    private static void txnSM3() {
        int idx = nextIdx();
        SM3Digest digest = new SM3Digest();
        digest.update(sm3DataPool[idx]);
        digest.doFinal();
    }

    /** SM4-ECB 加密 */
    private static void txnSM4ECBEncrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.ECB);
        cipher.cipherEncrypt(sm4Key, sm4DataPool[idx], null);
    }

    /** SM4-ECB 解密 */
    private static void txnSM4ECBDecrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.ECB);
        cipher.cipherDecrypt(sm4Key, sm4EncryptedECBPool[idx], null);
    }

    /** SM4-CBC 加密 */
    private static void txnSM4CBCEncrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.CBC);
        cipher.cipherEncrypt(sm4Key, sm4DataPool[idx], sm4Iv);
    }

    /** SM4-CBC 解密 */
    private static void txnSM4CBCDecrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.CBC);
        cipher.cipherDecrypt(sm4Key, sm4EncryptedCBCPool[idx], sm4Iv);
    }

    /** SM4-CTR 加密 */
    private static void txnSM4CTREncrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.CTR);
        cipher.cipherEncrypt(sm4Key, sm4DataPool[idx], sm4Iv);
    }

    /** SM4-CTR 解密 */
    private static void txnSM4CTRDecrypt() {
        int idx = nextIdx();
        SM4Cipher cipher = new SM4Cipher(ModeEnum.CTR);
        cipher.cipherDecrypt(sm4Key, sm4EncryptedCTRPool[idx], sm4Iv);
    }

    // ==================== 辅助类型 ====================

    @FunctionalInterface
    interface TxnRunnable {
        void run() throws Exception;
    }

    static class TpsResult {
        final long txnCount;
        final double tps;
        final double avgLatencyMs;

        TpsResult(long txnCount, double tps, double avgLatencyMs) {
            this.txnCount = txnCount;
            this.tps = tps;
            this.avgLatencyMs = avgLatencyMs;
        }
    }
}
