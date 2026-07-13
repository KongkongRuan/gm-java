package com.yxj.gm.SM4;

import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.util.JNI.SM4GCMNative;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.Locale;

/**
 * 对比 SM4 在不同组合下的性能：
 *   多线程开/关  ×  JNI GHASH 开/关
 * 并与 BC 做基准对照。
 *
 * 运行方式：
 *   java -cp ... com.yxj.gm.SM4.SM4CombinationBenchmark [parallel=true|false] [nativeGhash=true|false]
 *
 * 多线程开关由 -Dgm.sm4.parallel=true/false 控制（静态 final 读取）。
 * JNI GHASH 开关由程序参数 [nativeGhash] 控制：false 时调用 markUnavailable()。
 */
public class SM4CombinationBenchmark {

    private static final SecureRandom RND = new SecureRandom();

    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: SM4CombinationBenchmark <parallel=true|false> <nativeGhash=true|false>");
            System.exit(1);
        }
        boolean parallel = Boolean.parseBoolean(args[0]);
        boolean nativeGhash = Boolean.parseBoolean(args[1]);

        System.out.printf(Locale.US, "Config: parallel=%s, nativeGhash=%s, gm.sm4.parallel=%s%n",
                parallel, nativeGhash, System.getProperty("gm.sm4.parallel", "<unset>"));

        if (!nativeGhash) {
            SM4GCMNative.markUnavailable();
        }
        System.out.println("SM4GCMNative available: " + SM4GCMNative.isAvailable());

        int dataMB = 10;
        byte[] data = new byte[dataMB * 1024 * 1024];
        RND.nextBytes(data);
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        byte[] aad = new byte[64];
        RND.nextBytes(key);
        RND.nextBytes(iv);
        RND.nextBytes(aad);

        int warmup = 10;
        int rounds = 10;

        System.out.printf(Locale.US, "%nData: %d MB, warmup=%d, rounds=%d%n%n", dataMB, warmup, rounds);

        // gm-java ECB
        SM4Cipher gmEcb = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.ECB);
        bench("GM ECB enc", warmup, rounds, () -> gmEcb.cipherEncrypt(key, data, null));

        // gm-java CBC enc (sequential only)
        SM4Cipher gmCbc = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CBC);
        bench("GM CBC enc", warmup, rounds, () -> gmCbc.cipherEncrypt(key, data, iv));

        // gm-java CTR
        SM4Cipher gmCtr = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CTR);
        bench("GM CTR enc", warmup, rounds, () -> gmCtr.cipherEncrypt(key, data, iv));

        // gm-java GCM
        SM4Cipher gmGcm = new SM4Cipher();
        bench("GM GCM enc", warmup, rounds, () -> gmGcm.cipherEncryptGCM(key, data, iv, aad, 16));

        // BC ECB
        bench("BC ECB enc", warmup, rounds, () -> bcEcbEncrypt(data, key));

        // BC CBC (simple manual CBC using SM4Engine)
        bench("BC CBC enc", warmup, rounds, () -> bcCbcEncrypt(data, key, iv));

        // BC CTR (manual CTR using SM4Engine)
        bench("BC CTR enc", warmup, rounds, () -> bcCtrEncrypt(data, key, iv));

        // BC GCM not trivial with low-level SM4Engine; skip or use BouncyCastle JCE if available
        // We focus on ECB/CBC/CTR for direct comparison.
    }

    private static void bench(String name, int warmup, int rounds, Runnable task) {
        for (int i = 0; i < warmup; i++) task.run();
        long t0 = System.nanoTime();
        for (int i = 0; i < rounds; i++) task.run();
        long ns = System.nanoTime() - t0;
        double msPerCall = ns / (double) rounds / 1_000_000.0;
        System.out.printf(Locale.US, "%-18s : %.2f ms/call (total %.0f ms for %d rounds)%n",
                name, msPerCall, ns / 1_000_000.0, rounds);
    }

    private static byte[] bcEcbEncrypt(byte[] data, byte[] key) {
        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        int blockSize = engine.getBlockSize();
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length / blockSize; i++) {
            engine.processBlock(data, i * blockSize, out, i * blockSize);
        }
        return out;
    }

    private static byte[] bcCbcEncrypt(byte[] data, byte[] key, byte[] iv) {
        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        int blockSize = engine.getBlockSize();
        byte[] out = new byte[data.length];
        byte[] prev = iv.clone();
        byte[] block = new byte[blockSize];
        for (int i = 0; i < data.length / blockSize; i++) {
            int off = i * blockSize;
            for (int j = 0; j < blockSize; j++) block[j] = (byte) (data[off + j] ^ prev[j]);
            engine.processBlock(block, 0, out, off);
            System.arraycopy(out, off, prev, 0, blockSize);
        }
        return out;
    }

    private static byte[] bcCtrEncrypt(byte[] data, byte[] key, byte[] iv) {
        SM4Engine engine = new SM4Engine();
        engine.init(true, new KeyParameter(key));
        int blockSize = engine.getBlockSize();
        byte[] out = new byte[data.length];
        byte[] counter = iv.clone();
        byte[] ks = new byte[blockSize];
        for (int i = 0; i < data.length / blockSize; i++) {
            int off = i * blockSize;
            engine.processBlock(counter, 0, ks, 0);
            for (int j = 0; j < blockSize; j++) out[off + j] = (byte) (data[off + j] ^ ks[j]);
            incrementCounter(counter);
        }
        // last partial block if any (data is multiple of 16 here)
        return out;
    }

    private static void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }
}
