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
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.*;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.crypto.engines.SM2Engine;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class BenchmarkComparison {
    static final int MIN_RECOMMENDED_JAVA8_UPDATE = 161;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    static final X9ECParameters SM2_PARAMS = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("sm2p256v1");
    static final ECDomainParameters SM2_DOMAIN = new ECDomainParameters(
            SM2_PARAMS.getCurve(), SM2_PARAMS.getG(), SM2_PARAMS.getN(), SM2_PARAMS.getH());

    private static final List<BenchmarkResult> RESULTS = new ArrayList<BenchmarkResult>();
    private static final String BC_SM2_BENCHMARK_MODE =
            "lightweight engine/signer 预初始化后复用（签名使用 raw64 编码）";

    static double elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000.0;
    }

    public static String gmSm4ParallelLabel() {
        boolean enabled = Boolean.parseBoolean(System.getProperty("gm.sm4.parallel", "true"));
        return enabled ? "gm并行配置=开启" : "gm并行配置=关闭";
    }

    public static void main(String[] args) throws Exception {
        int sm2Warmup = 500, sm2Rounds = 200, sm2Sets = 5;
        int sm3Warmup = 500, sm3Rounds = 1000, sm3Sets = 5;
        int sm4Warmup = 50, sm4Rounds = 20, sm4Sets = 5;
        int[] sm4DataMBs = {1, 10, 20};

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter tsFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HHmmss");
        String timestamp = now.format(tsFormatter);
        String yyyymmdd = now.format(dateFormatter);
        String hhmmss = now.format(timeFormatter);
        int jdkMajor = javaMajorVersion();

        String logFileName = String.format(Locale.US, "benchmark-comparison-%s-%s-JDK%d.log", yyyymmdd, hhmmss, jdkMajor);
        File logFile = new File("reports", logFileName);
        String summaryFileName = String.format(Locale.US, "summary-%s-%s.md", yyyymmdd, hhmmss);
        File summaryFile = new File("reports", summaryFileName);

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

            printMetadataHeader(timestamp, gitCommit, pomVersion,
                    sm2Warmup, sm2Rounds, sm2Sets,
                    sm3Warmup, sm3Rounds, sm3Sets,
                    sm4Warmup, sm4Rounds, sm4Sets, sm4DataMBs);

            benchSM2KeyGen(sm2Warmup, sm2Rounds, sm2Sets);
            benchSM2EncDec(sm2Warmup, sm2Rounds, sm2Sets);
            benchSM2SignVerify(sm2Warmup, sm2Rounds, sm2Sets);
            benchSM3(sm3Warmup, sm3Rounds, sm3Sets);
            benchSM4(sm4Warmup, sm4Rounds, sm4Sets, sm4DataMBs);

            System.out.println("\n═══════════════════════════════════════════════════════════════");
            System.out.println("  全部测试完成");
            System.out.println("═══════════════════════════════════════════════════════════════");

            writeSummaryMarkdown(summaryFile, timestamp, gitCommit, pomVersion,
                    sm2Warmup, sm2Rounds, sm2Sets,
                    sm3Warmup, sm3Rounds, sm3Sets,
                    sm4Warmup, sm4Rounds, sm4Sets, sm4DataMBs);

            System.out.println("\n  报告已保存:");
            System.out.println("    " + logFile.getPath());
            System.out.println("    " + summaryFile.getPath());
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

    static void printMetadataHeader(String timestamp, String gitCommit, String pomVersion,
                                    int sm2Warmup, int sm2Rounds, int sm2Sets,
                                    int sm3Warmup, int sm3Rounds, int sm3Sets,
                                    int sm4Warmup, int sm4Rounds, int sm4Sets, int[] sm4DataMBs) {
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("  测试类型：BenchmarkComparison");
        System.out.println("  测试时间：" + timestamp);
        System.out.println("  Git Commit：" + gitCommit);
        System.out.println("  版本：" + pomVersion);
        System.out.println("  JDK：" + System.getProperty("java.version") + " (" + System.getProperty("java.vm.name") + ")");
        System.out.println("  OS：" + System.getProperty("os.name") + " " + System.getProperty("os.arch"));
        System.out.println("  CPUs：" + Runtime.getRuntime().availableProcessors());
        System.out.println("  Nat256：" + (Nat256Native.isAvailable() ? "JNI" : "Java"));
        System.out.println("  BC SM2：" + BC_SM2_BENCHMARK_MODE);
        System.out.println("  SM4：" + gmSm4ParallelLabel());
        System.out.println("  参数：SM2(warmup=" + sm2Warmup + ", rounds=" + sm2Rounds + ", sets=" + sm2Sets + "), " +
                "SM3(warmup=" + sm3Warmup + ", rounds=" + sm3Rounds + ", sets=" + sm3Sets + "), " +
                "SM4(warmup=" + sm4Warmup + ", rounds=" + sm4Rounds + ", sets=" + sm4Sets + ", dataMBs=" + Arrays.toString(sm4DataMBs) + ")");
        printLegacyJava8Hint();
        System.out.println("═══════════════════════════════════════════════════════════════\n");
    }

    static String gitCommitShort() {
        try {
            Process p = new ProcessBuilder("git", "rev-parse", "--short", "HEAD")
                    .directory(new File("."))
                    .redirectErrorStream(true)
                    .start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            int exit = p.waitFor();
            String out = sb.toString().trim();
            if (exit == 0 && !out.isEmpty()) {
                return out;
            }
        } catch (Exception e) {
            // ignore
        }
        return "unknown";
    }

    static String readPomVersion() {
        File pom = new File("pom.xml");
        if (!pom.exists()) {
            return "unknown";
        }
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(pom), "UTF-8"));
            String line;
            boolean foundArtifact = false;
            while ((line = br.readLine()) != null) {
                if (line.contains("<artifactId>gm-java</artifactId>")) {
                    foundArtifact = true;
                } else if (foundArtifact && line.contains("<version>")) {
                    int start = line.indexOf("<version>") + "<version>".length();
                    int end = line.indexOf("</version>");
                    if (end > start) {
                        return line.substring(start, end).trim();
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
        return "unknown";
    }

    static void writeSummaryMarkdown(File summaryFile, String timestamp, String gitCommit, String pomVersion,
                                     int sm2Warmup, int sm2Rounds, int sm2Sets,
                                     int sm3Warmup, int sm3Rounds, int sm3Sets,
                                     int sm4Warmup, int sm4Rounds, int sm4Sets, int[] sm4DataMBs) throws IOException {
        StringBuilder md = new StringBuilder();
        md.append("# gm-java 性能测试摘要\n\n");
        md.append("## 测试元数据\n\n");
        md.append("- **测试类型**：BenchmarkComparison\n");
        md.append("- **测试时间**：").append(timestamp).append("\n");
        md.append("- **Git Commit**：").append(gitCommit).append("\n");
        md.append("- **版本**：").append(pomVersion).append("\n");
        md.append("- **JDK**：").append(System.getProperty("java.version"))
          .append(" (").append(System.getProperty("java.vm.name")).append(")\n");
        md.append("- **OS**：").append(System.getProperty("os.name")).append(" ")
          .append(System.getProperty("os.arch")).append("\n");
        md.append("- **CPUs**：").append(Runtime.getRuntime().availableProcessors()).append("\n");
        md.append("- **Nat256**：").append(Nat256Native.isAvailable() ? "JNI" : "Java").append("\n");
        md.append("- **BC SM2**：").append(BC_SM2_BENCHMARK_MODE).append("\n");
        md.append("- **SM4**：").append(gmSm4ParallelLabel()).append("\n");
        md.append("- **参数**：\n");
        md.append("  - SM2: warmup=").append(sm2Warmup).append(", rounds=").append(sm2Rounds).append(", sets=").append(sm2Sets).append("\n");
        md.append("  - SM3: warmup=").append(sm3Warmup).append(", rounds=").append(sm3Rounds).append(", sets=").append(sm3Sets).append("\n");
        md.append("  - SM4: warmup=").append(sm4Warmup).append(", rounds=").append(sm4Rounds).append(", sets=").append(sm4Sets)
          .append(", dataMBs=").append(Arrays.toString(sm4DataMBs)).append("\n");
        md.append("\n");

        md.append("## SM2 测试结果\n\n");
        md.append("> 每个数值是一轮（").append(sm2Rounds).append(" 次操作）的总耗时，单位为毫秒。\n\n");
        md.append("| 操作 | gm-java (ms/轮) | BC 预初始化复用 (ms/轮) | Hutool (ms/轮) | 优胜者 |\n");
        md.append("|------|-------------:|--------:|------------:|--------|\n");
        for (BenchmarkResult r : RESULTS) {
            if ("SM2".equals(r.category)) {
                md.append(String.format(Locale.US, "| %s | %.3f | %.3f | %.3f | %s |%n",
                        r.name, r.gm, r.bc, r.ht, r.winner));
            }
        }
        md.append("\n");

        md.append("## SM3 测试结果\n\n");
        md.append("> 每个数值是一轮（").append(sm3Rounds).append(" 次操作）的总耗时，单位为毫秒。\n\n");
        md.append("| 数据大小 | gm-java (ms/轮) | BC (ms/轮) | Hutool (ms/轮) | 优胜者 |\n");
        md.append("|----------|-------------:|--------:|------------:|--------|\n");
        for (BenchmarkResult r : RESULTS) {
            if ("SM3".equals(r.category)) {
                md.append(String.format(Locale.US, "| %s | %.3f | %.3f | %.3f | %s |%n",
                        r.name, r.gm, r.bc, r.ht, r.winner));
            }
        }
        md.append("\n");

        md.append("## SM4 测试结果\n\n");
        md.append("| 模式+操作+大小 | gm-java (MB/s) | BC (MB/s) | Hutool (MB/s) | 优胜者 |\n");
        md.append("|----------------|---------------:|----------:|---------------:|--------|\n");
        for (BenchmarkResult r : RESULTS) {
            if ("SM4".equals(r.category)) {
                if (Double.isNaN(r.ht)) {
                    md.append(String.format(Locale.US, "| %s | %.1f | %.1f | N/A | %s |%n",
                            r.name, r.gm, r.bc, r.winner));
                } else {
                    md.append(String.format(Locale.US, "| %s | %.1f | %.1f | %.1f | %s |%n",
                            r.name, r.gm, r.bc, r.ht, r.winner));
                }
            }
        }
        md.append("\n");

        PrintWriter pw = null;
        try {
            pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(summaryFile), "UTF-8"));
            pw.print(md.toString());
        } finally {
            if (pw != null) {
                pw.close();
            }
        }
    }

    static void printLegacyJava8Hint() {
        if (isLegacyJava8Runtime()) {
            int update = java8UpdateVersion();
            String runtime = update > 0 ? "JDK 8u" + update : "JDK " + System.getProperty("java.version");
            System.out.printf("  提示    : 检测到较老的 %s，Hutool SM4 在当前 BC Provider 下可能因 JAR 验签失败而不可用。%n", runtime);
            System.out.println("           如出现 'JCE cannot authenticate the provider BC'，程序会给出明确提示并跳过 Hutool SM4。");
            System.out.println("           建议升级到更新的 JDK 8，或直接使用 JDK 11+/21。");
        }
    }

    static boolean isLegacyJava8Runtime() {
        return javaMajorVersion() == 8 && java8UpdateVersion() > 0 && java8UpdateVersion() < MIN_RECOMMENDED_JAVA8_UPDATE;
    }

    static int javaMajorVersion() {
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

    static int java8UpdateVersion() {
        if (javaMajorVersion() != 8) {
            return -1;
        }
        String version = System.getProperty("java.version", "");
        int underscore = version.indexOf('_');
        if (underscore < 0 || underscore == version.length() - 1) {
            return -1;
        }
        int end = underscore + 1;
        while (end < version.length() && Character.isDigit(version.charAt(end))) {
            end++;
        }
        try {
            return Integer.parseInt(version.substring(underscore + 1, end));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static final class HutoolSm4Support {
        final SM4 ecb;
        final SM4 cbc;
        final SM4 ctr;
        final String unavailableReason;

        HutoolSm4Support(SM4 ecb, SM4 cbc, SM4 ctr, String unavailableReason) {
            this.ecb = ecb;
            this.cbc = cbc;
            this.ctr = ctr;
            this.unavailableReason = unavailableReason;
        }

        boolean isAvailable() {
            return unavailableReason == null;
        }
    }

    static final class BenchmarkResult {
        final String category;
        final String name;
        final double gm;
        final double bc;
        final double ht;
        final String unit;
        final String winner;
        final String htUnavailableReason;

        BenchmarkResult(String category, String name, double gm, double bc, double ht, String unit, String winner, String htUnavailableReason) {
            this.category = category;
            this.name = name;
            this.gm = gm;
            this.bc = bc;
            this.ht = ht;
            this.unit = unit;
            this.winner = winner;
            this.htUnavailableReason = htUnavailableReason;
        }
    }

    static HutoolSm4Support initHutoolSm4(byte[] key, byte[] iv) {
        try {
            return new HutoolSm4Support(
                    new SM4(cn.hutool.crypto.Mode.ECB, cn.hutool.crypto.Padding.NoPadding, key),
                    new SM4(cn.hutool.crypto.Mode.CBC, cn.hutool.crypto.Padding.NoPadding, key, iv),
                    new SM4(cn.hutool.crypto.Mode.CTR, cn.hutool.crypto.Padding.NoPadding, key, iv),
                    null
            );
        } catch (RuntimeException e) {
            String reason = buildHutoolSm4UnavailableReason(e);
            System.out.println("    [提示] Hutool SM4 已跳过。");
            System.out.println("           " + reason);
            return new HutoolSm4Support(null, null, null, reason);
        }
    }

    static String buildHutoolSm4UnavailableReason(Throwable error) {
        Throwable root = rootCause(error);
        String javaVersion = System.getProperty("java.version");
        String rootMessage = root.getMessage() == null ? root.getClass().getSimpleName() : root.getMessage();
        if (rootMessage.contains("JCE cannot authenticate the provider BC")
                || rootMessage.contains("trusted signer")
                || rootMessage.contains("trust anchors")) {
            return "当前 Java 运行时为 " + javaVersion
                    + "，无法验证 BC Provider 的 JCE 签名链。通常是 JDK 8 版本过低导致。"
                    + " 建议升级到更新的 JDK 8 或 JDK 11+/21；若必须停留在旧 JDK 8，请回退 Bouncy Castle 版本。"
                    + " 原始原因: " + rootMessage;
        }
        return "初始化 Hutool SM4 失败，已跳过该项。原始原因: " + rootMessage;
    }

    static Throwable rootCause(Throwable error) {
        Throwable current = error;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current;
    }

    // ==================== SM2 密钥生成 ====================
    static void benchSM2KeyGen(int warmup, int rounds, int sets) throws Exception {
        System.out.println("╔══ SM2 密钥对生成 ══╗");
        ECKeyPairGenerator bcGen = new ECKeyPairGenerator();
        bcGen.init(new ECKeyGenerationParameters(SM2_DOMAIN, new SecureRandom()));

        long t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) SM2KeyPairGenerate.generateSM2KeyPair();
        System.out.printf("    预热 gm-java      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) bcGen.generateKeyPair();
        System.out.printf("    预热 BC           %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) SmUtil.sm2();
        System.out.printf("    预热 Hutool       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));

        double[] gm = new double[sets], bc = new double[sets], ht = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) SM2KeyPairGenerate.generateSM2KeyPair();
            gm[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) bcGen.generateKeyPair();
            bc[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) SmUtil.sm2();
            ht[s] = elapsedMillis(t0);
        }
        printResult("SM2", "SM2 密钥生成", rounds, gm, bc, ht, sets);
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
        BcSm2CipherSession bcCipher = new BcSm2CipherSession(bcPub, bcPri);

        SM2 htSm2 = SmUtil.sm2();

        byte[] gmEnc = gmCipher.SM2CipherEncrypt(msg, gmPub);
        byte[] bcEnc = bcCipher.encrypt(msg);

        long t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) gmCipher.SM2CipherEncrypt(msg, gmPub);
        System.out.printf("    预热 gm-enc       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) gmCipher.SM2CipherDecrypt(gmEnc, gmPri);
        System.out.printf("    预热 gm-dec       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) bcCipher.encrypt(msg);
        System.out.printf("    预热 BC-enc       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) bcCipher.decrypt(bcEnc);
        System.out.printf("    预热 BC-dec       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        byte[] htEnc = htSm2.encrypt(msg);
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) htSm2.encrypt(msg);
        System.out.printf("    预热 HT-enc       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) htSm2.decrypt(htEnc, KeyType.PrivateKey);
        System.out.printf("    预热 HT-dec       %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));

        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) gmCipher.SM2CipherEncrypt(msg, gmPub);
            gmE[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) bcCipher.encrypt(msg);
            bcE[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) htSm2.encrypt(msg);
            htE[s] = elapsedMillis(t0);

            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) gmCipher.SM2CipherDecrypt(gmEnc, gmPri);
            gmD[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) bcCipher.decrypt(bcEnc);
            bcD[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) htSm2.decrypt(htEnc, KeyType.PrivateKey);
            htD[s] = elapsedMillis(t0);
        }
        printResult("SM2", "SM2 加密", rounds, gmE, bcE, htE, sets);
        printResult("SM2", "SM2 解密", rounds, gmD, bcD, htD, sets);
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
        BcSm2SignerSession bcSigner = new BcSm2SignerSession(bcPri, bcPub);

        SM2 htSm2 = SmUtil.sm2();
        byte[] gmSig = gmSigner.signature(msg, null, gmPri, gmPub);
        byte[] bcSig = bcSigner.sign(msg);

        long t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) gmSigner.signature(msg, null, gmPri, gmPub);
        System.out.printf("    预热 gm-sign      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) gmSigner.verify(msg, null, gmSig, gmPub);
        System.out.printf("    预热 gm-vrfy      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) bcSigner.sign(msg);
        System.out.printf("    预热 BC-sign      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) bcSigner.verify(msg, bcSig);
        System.out.printf("    预热 BC-vrfy      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));

        byte[] htSig = htSm2.sign(msg);
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) htSm2.sign(msg);
        System.out.printf("    预热 HT-sign      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) htSm2.verify(msg, htSig);
        System.out.printf("    预热 HT-vrfy      %d 次 ... %.3f ms%n", warmup, elapsedMillis(t0));

        double[] gmS = new double[sets], bcS = new double[sets], htS = new double[sets];
        double[] gmV = new double[sets], bcV = new double[sets], htV = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) gmSigner.signature(msg, null, gmPri, gmPub);
            gmS[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) bcSigner.sign(msg);
            bcS[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) htSm2.sign(msg);
            htS[s] = elapsedMillis(t0);

            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) gmSigner.verify(msg, null, gmSig, gmPub);
            gmV[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) bcSigner.verify(msg, bcSig);
            bcV[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) htSm2.verify(msg, htSig);
            htV[s] = elapsedMillis(t0);
        }
        printResult("SM2", "SM2 签名", rounds, gmS, bcS, htS, sets);
        printResult("SM2", "SM2 验签", rounds, gmV, bcV, htV, sets);
    }

    // ==================== SM3 ====================
    static void benchSM3(int warmup, int rounds, int sets) {
        System.out.println("\n╔══ SM3 哈希 ══╗");
        byte[] data16B = new byte[16];
        byte[] data1K = new byte[1024];
        byte[] data64K = new byte[64 * 1024];
        byte[] data1M = new byte[1024 * 1024];
        SecureRandom random = new SecureRandom();
        random.nextBytes(data16B);
        random.nextBytes(data1K);
        random.nextBytes(data64K);
        random.nextBytes(data1M);
        org.bouncycastle.crypto.digests.SM3Digest bcDigest = new org.bouncycastle.crypto.digests.SM3Digest();

        benchSM3Size("16B", data16B, warmup, rounds, sets, bcDigest);
        benchSM3Size("1KB", data1K, warmup, rounds, sets, bcDigest);
        benchSM3Size("64KB", data64K, warmup, rounds, sets, bcDigest);
        benchSM3Size("1MB", data1M, warmup, rounds, sets, bcDigest);
    }

    static void benchSM3Size(String label, byte[] data, int warmup, int rounds, int sets,
                             org.bouncycastle.crypto.digests.SM3Digest bcDigest) {
        long t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) { SM3Digest d = new SM3Digest(); d.update(data); d.doFinal(); }
        System.out.printf("    预热 gm-%s       %d 次 ... %.3f ms%n", label, warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) { bcDigest.reset(); bcDigest.update(data, 0, data.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
        System.out.printf("    预热 BC-%s       %d 次 ... %.3f ms%n", label, warmup, elapsedMillis(t0));
        t0 = System.nanoTime();
        for (int i = 0; i < warmup; i++) cn.hutool.crypto.digest.SM3.create().digest(data);
        System.out.printf("    预热 HT-%s       %d 次 ... %.3f ms%n", label, warmup, elapsedMillis(t0));

        double[] gm = new double[sets], bc = new double[sets], ht = new double[sets];
        for (int s = 0; s < sets; s++) {
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) { SM3Digest d = new SM3Digest(); d.update(data); d.doFinal(); }
            gm[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) { bcDigest.reset(); bcDigest.update(data, 0, data.length); byte[] o = new byte[32]; bcDigest.doFinal(o, 0); }
            bc[s] = elapsedMillis(t0);
            t0 = System.nanoTime();
            for (int i = 0; i < rounds; i++) cn.hutool.crypto.digest.SM3.create().digest(data);
            ht[s] = elapsedMillis(t0);
        }
        printResult("SM3", "SM3 (" + label + ")", rounds, gm, bc, ht, sets);
    }

    // ==================== SM4 ====================
    static void benchSM4(int warmup, int rounds, int sets, int[] dataMBs) {
        for (int dataMB : dataMBs) {
            // 大数据量时减少预热和测量轮数，避免测试时间过长或 OOM
            int actualWarmup = warmup;
            int actualRounds = rounds;
            if (dataMB >= 20) {
                actualWarmup = Math.max(5, warmup / 5);
                actualRounds = Math.max(5, rounds / 4);
            } else if (dataMB >= 10) {
                actualWarmup = Math.max(10, warmup / 2);
                actualRounds = Math.max(10, rounds / 2);
            }

            System.out.println("\n╔══ SM4 对称加解密 (" + dataMB + "MB, warmup=" + actualWarmup + ", rounds=" + actualRounds + ") ══╗");
            byte[] key = new byte[16];
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(key);
            new SecureRandom().nextBytes(iv);
            byte[] data = new byte[dataMB * 1024 * 1024];
            new SecureRandom().nextBytes(data);

            SM4Cipher gmSm4Ecb = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.ECB);
            SM4Cipher gmSm4Cbc = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CBC);
            SM4Cipher gmSm4Ctr = new SM4Cipher(PaddingEnum.NoPadding, ModeEnum.CTR);

            HutoolSm4Support hutoolSm4 = initHutoolSm4(key, iv);

            benchSM4Mode("SM4-ECB", ModeEnum.ECB, gmSm4Ecb, key, data, iv, hutoolSm4.ecb, actualWarmup, actualRounds, sets, dataMB, true, hutoolSm4.unavailableReason);
            benchSM4Mode("SM4-CBC", ModeEnum.CBC, gmSm4Cbc, key, data, iv, hutoolSm4.cbc, actualWarmup, actualRounds, sets, dataMB, true, hutoolSm4.unavailableReason);
            benchSM4CTR(gmSm4Ctr, key, data, iv, hutoolSm4.ctr, actualWarmup, actualRounds, sets, dataMB, hutoolSm4.unavailableReason);
        }
    }

    static void benchSM4(int warmup, int rounds, int sets, int dataMB) {
        benchSM4(warmup, rounds, sets, new int[] { dataMB });
    }

    static void benchSM4Mode(String name, ModeEnum mode, SM4Cipher gmSm4, byte[] key, byte[] data, byte[] iv,
                              SM4 htSm4, int warmup, int rounds, int sets, int dataMB, boolean testDecrypt,
                              String htUnavailableReason) {
        byte[] gmEnc = gmSm4.cipherEncrypt(key, data, iv);
        byte[] bcEnc = bcSM4Encrypt(data, key, iv, mode);
        byte[] htEnc = htSm4 != null ? htSm4.encrypt(data) : null;
        validateSm4Interoperability(name, mode, gmSm4, htSm4, key, iv, data, gmEnc, bcEnc, htEnc);

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSm4.cipherEncrypt(key, data, iv);
        System.out.printf("    预热 gm-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSM4Encrypt(data, key, iv, mode);
        System.out.printf("    预热 BC-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
        if (htSm4 != null) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < warmup; i++) htSm4.encrypt(data);
            System.out.printf("    预热 HT-%s       %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
        } else {
            System.out.printf("    跳过 HT-%s       %s%n", name.substring(4), "当前 JDK/Provider 组合不兼容");
        }

        if (testDecrypt) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < warmup; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
            System.out.printf("    预热 gm-%s-dec   %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
            t0 = System.currentTimeMillis();
            for (int i = 0; i < warmup; i++) bcSM4Decrypt(bcEnc, key, iv, mode);
            System.out.printf("    预热 BC-%s-dec   %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
            if (htSm4 != null) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < warmup; i++) htSm4.decrypt(htEnc);
                System.out.printf("    预热 HT-%s-dec   %d 次 ... %d ms%n", name.substring(4), warmup, System.currentTimeMillis() - t0);
            }
        }

        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        if (htSm4 == null) {
            Arrays.fill(htE, Double.NaN);
        }
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherEncrypt(key, data, iv);
            gmE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4Encrypt(data, key, iv, mode);
            bcE[s] = System.currentTimeMillis() - t0;
            if (htSm4 != null) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) htSm4.encrypt(data);
                htE[s] = System.currentTimeMillis() - t0;
            }
        }
        printResultMB("SM4", name + " 加密", rounds, gmE, bcE, htE, sets, dataMB, htUnavailableReason);

        if (testDecrypt) {
            double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
            if (htSm4 == null) {
                Arrays.fill(htD, Double.NaN);
            }
            for (int s = 0; s < sets; s++) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
                gmD[s] = System.currentTimeMillis() - t0;
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) bcSM4Decrypt(bcEnc, key, iv, mode);
                bcD[s] = System.currentTimeMillis() - t0;
                if (htSm4 != null) {
                    t0 = System.currentTimeMillis();
                    for (int i = 0; i < rounds; i++) htSm4.decrypt(htEnc);
                    htD[s] = System.currentTimeMillis() - t0;
                }
            }
            printResultMB("SM4", name + " 解密", rounds, gmD, bcD, htD, sets, dataMB, htUnavailableReason);
        }
    }

    static void benchSM4CTR(SM4Cipher gmSm4, byte[] key, byte[] data, byte[] iv, SM4 htCtr,
                             int warmup, int rounds, int sets, int dataMB, String htUnavailableReason) {
        byte[] gmEnc = gmSm4.cipherEncrypt(key, data, iv);
        byte[] bcEnc = bcSM4CtrEncrypt(data, key, iv);
        byte[] htEnc = htCtr != null ? htCtr.encrypt(data) : null;
        validateSm4Interoperability("SM4-CTR", ModeEnum.CTR, gmSm4, htCtr,
                key, iv, data, gmEnc, bcEnc, htEnc);

        long t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSm4.cipherEncrypt(key, data, iv);
        System.out.printf("    预热 gm-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSM4CtrEncrypt(data, key, iv);
        System.out.printf("    预热 BC-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        if (htCtr != null) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < warmup; i++) htCtr.encrypt(data);
            System.out.printf("    预热 HT-CTR       %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        } else {
            System.out.printf("    跳过 HT-CTR       %s%n", "当前 JDK/Provider 组合不兼容");
        }

        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
        System.out.printf("    预热 gm-CTR-dec   %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        t0 = System.currentTimeMillis();
        for (int i = 0; i < warmup; i++) bcSM4CtrDecrypt(bcEnc, key, iv);
        System.out.printf("    预热 BC-CTR-dec   %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        if (htCtr != null) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < warmup; i++) htCtr.decrypt(htEnc);
            System.out.printf("    预热 HT-CTR-dec   %d 次 ... %d ms%n", warmup, System.currentTimeMillis() - t0);
        }

        double[] gmE = new double[sets], bcE = new double[sets], htE = new double[sets];
        double[] gmD = new double[sets], bcD = new double[sets], htD = new double[sets];
        if (htCtr == null) {
            Arrays.fill(htE, Double.NaN);
            Arrays.fill(htD, Double.NaN);
        }
        for (int s = 0; s < sets; s++) {
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherEncrypt(key, data, iv);
            gmE[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4CtrEncrypt(data, key, iv);
            bcE[s] = System.currentTimeMillis() - t0;
            if (htCtr != null) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) htCtr.encrypt(data);
                htE[s] = System.currentTimeMillis() - t0;
            }

            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) gmSm4.cipherDecrypt(key, gmEnc, iv);
            gmD[s] = System.currentTimeMillis() - t0;
            t0 = System.currentTimeMillis();
            for (int i = 0; i < rounds; i++) bcSM4CtrDecrypt(bcEnc, key, iv);
            bcD[s] = System.currentTimeMillis() - t0;
            if (htCtr != null) {
                t0 = System.currentTimeMillis();
                for (int i = 0; i < rounds; i++) htCtr.decrypt(htEnc);
                htD[s] = System.currentTimeMillis() - t0;
            }
        }
        String parallelLabel = gmSm4ParallelLabel();
        printResultMB("SM4", "SM4-CTR 加密 [" + parallelLabel + "]", rounds, gmE, bcE, htE, sets, dataMB, htUnavailableReason);
        printResultMB("SM4", "SM4-CTR 解密 [" + parallelLabel + "]", rounds, gmD, bcD, htD, sets, dataMB, htUnavailableReason);
    }

    // ==================== BC helpers ====================
    public static final class BcSm2CipherSession {
        private final SM2Engine encryptor;
        private final SM2Engine decryptor;

        public BcSm2CipherSession(ECPublicKeyParameters publicKey,
                                  ECPrivateKeyParameters privateKey) {
            encryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
            encryptor.init(true, new ParametersWithRandom(publicKey, new SecureRandom()));
            decryptor = new SM2Engine(SM2Engine.Mode.C1C3C2);
            decryptor.init(false, privateKey);
        }

        public byte[] encrypt(byte[] message) {
            try {
                return encryptor.processBlock(message, 0, message.length);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public byte[] decrypt(byte[] ciphertext) {
            try {
                return decryptor.processBlock(ciphertext, 0, ciphertext.length);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public static final class BcSm2SignerSession {
        private final SM2Signer signer;
        private final SM2Signer verifier;

        public BcSm2SignerSession(ECPrivateKeyParameters privateKey,
                                  ECPublicKeyParameters publicKey) {
            signer = new SM2Signer(PlainDSAEncoding.INSTANCE);
            signer.init(true, new ParametersWithRandom(privateKey, new SecureRandom()));
            verifier = new SM2Signer(PlainDSAEncoding.INSTANCE);
            verifier.init(false, publicKey);
        }

        public byte[] sign(byte[] message) {
            try {
                signer.update(message, 0, message.length);
                return signer.generateSignature();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public boolean verify(byte[] message, byte[] signature) {
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        }
    }

    public static AsymmetricCipherKeyPair genBCKeyPair() {
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

    public static byte[] bcSM4Encrypt(byte[] data, byte[] key, byte[] iv, ModeEnum mode) {
        return bcSM4Process(data, key, iv, mode, true);
    }

    public static byte[] bcSM4Decrypt(byte[] data, byte[] key, byte[] iv, ModeEnum mode) {
        return bcSM4Process(data, key, iv, mode, false);
    }

    private static byte[] bcSM4Process(byte[] data, byte[] key, byte[] iv, ModeEnum mode,
                                       boolean forEncryption) {
        if (mode == ModeEnum.CTR) {
            return bcSM4CtrProcess(data, key, iv, forEncryption);
        }

        BlockCipher cipher;
        CipherParameters parameters;
        if (mode == ModeEnum.ECB) {
            cipher = new SM4Engine();
            parameters = new KeyParameter(key);
        } else if (mode == ModeEnum.CBC) {
            cipher = new CBCBlockCipher(new SM4Engine());
            parameters = new ParametersWithIV(new KeyParameter(key), iv);
        } else {
            throw new IllegalArgumentException("不支持的 BC SM4 基准模式: " + mode);
        }

        cipher.init(forEncryption, parameters);
        int blockSize = cipher.getBlockSize();
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("SM4 NoPadding 输入长度必须是 16 的倍数");
        }
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length / blockSize; i++) {
            cipher.processBlock(data, i * blockSize, out, i * blockSize);
        }
        return out;
    }

    static byte[] bcSM4CtrEncrypt(byte[] data, byte[] key, byte[] iv) {
        return bcSM4CtrProcess(data, key, iv, true);
    }

    static byte[] bcSM4CtrDecrypt(byte[] data, byte[] key, byte[] iv) {
        return bcSM4CtrProcess(data, key, iv, false);
    }

    private static byte[] bcSM4CtrProcess(byte[] data, byte[] key, byte[] iv, boolean forEncryption) {
        SICBlockCipher cipher = new SICBlockCipher(new SM4Engine());
        cipher.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[data.length];
        cipher.processBytes(data, 0, data.length, out, 0);
        return out;
    }

    static void validateSm4Interoperability(String name, ModeEnum mode, SM4Cipher gmSm4, SM4 htSm4,
                                             byte[] key, byte[] iv, byte[] plain,
                                             byte[] gmCiphertext, byte[] bcCiphertext, byte[] htCiphertext) {
        requireSameBytes(name + " gm/BC 密文", gmCiphertext, bcCiphertext);
        requireSameBytes(name + " gm 解 BC 密文", plain, gmSm4.cipherDecrypt(key, bcCiphertext, iv));
        requireSameBytes(name + " BC 解 gm 密文", plain, bcSM4Decrypt(gmCiphertext, key, iv, mode));

        if (htSm4 != null) {
            requireSameBytes(name + " gm/Hutool 密文", gmCiphertext, htCiphertext);
            requireSameBytes(name + " gm 解 Hutool 密文", plain, gmSm4.cipherDecrypt(key, htCiphertext, iv));
            requireSameBytes(name + " Hutool 解 gm 密文", plain, htSm4.decrypt(gmCiphertext));
        }

        System.out.printf("    互操作校验 %-7s gm/BC%s%n", name.substring(4),
                htSm4 == null ? "" : "/Hutool");
    }

    private static void requireSameBytes(String operation, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new IllegalStateException(operation + "结果不一致");
        }
    }

    // ==================== 输出格式化 ====================
    static void printResult(String category, String name, int rounds, double[] gm, double[] bc, double[] ht, int sets) {
        Arrays.sort(gm); Arrays.sort(bc); Arrays.sort(ht);
        double gmMed = gm[sets/2], bcMed = bc[sets/2], htMed = ht[sets/2];
        double gmAvg = avg(gm), bcAvg = avg(bc), htAvg = avg(ht);
        double gmMin = gm[0], bcMin = bc[0], htMin = ht[0];
        double gmMax = gm[sets-1], bcMax = bc[sets-1], htMax = ht[sets-1];

        System.out.printf("%n  %-20s │ %d 次/轮%n", name, rounds);
        System.out.printf("    gm-java   : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.6f ms%n",
                gmMed, gmAvg, gmMin, gmMax, gmAvg/rounds);
        String bcLabel = "SM2".equals(category) ? "BC(reuse)" : "BC";
        System.out.printf("    %-10s: 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.6f ms%n",
                bcLabel,
                bcMed, bcAvg, bcMin, bcMax, bcAvg/rounds);
        System.out.printf("    Hutool    : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ avg/次 %.6f ms%n",
                htMed, htAvg, htMin, htMax, htAvg/rounds);

        String winner = computeWinner(gmMed, bcMed, htMed, true);
        double best = Math.min(gmMed, Math.min(bcMed, htMed));
        double pctGm = gmMed == best ? 0 : (gmMed - best) / best * 100;
        double pctBc = bcMed == best ? 0 : (bcMed - best) / best * 100;
        double pctHt = htMed == best ? 0 : (htMed - best) / best * 100;
        System.out.printf("    >>> %s 最快", winner);
        if (pctGm > 0) System.out.printf("  gm-java慢 %.1f%%", pctGm);
        if (pctBc > 0) System.out.printf("  BC慢 %.1f%%", pctBc);
        if (pctHt > 0) System.out.printf("  Hutool慢 %.1f%%", pctHt);
        System.out.println();

        RESULTS.add(new BenchmarkResult(category, name, gmMed, bcMed, htMed, "ms", winner, null));
    }

    static void printResultMB(String category, String name, int rounds, double[] gm, double[] bc, double[] ht, int sets, int dataMB,
                              String htUnavailableReason) {
        Arrays.sort(gm); Arrays.sort(bc); Arrays.sort(ht);
        double gmMed = gm[sets/2], bcMed = bc[sets/2], htMed = ht[sets/2];
        double gmAvg = avg(gm), bcAvg = avg(bc), htAvg = avg(ht);

        double gmMBs = rounds * dataMB * 1000.0 / gmMed;
        double bcMBs = rounds * dataMB * 1000.0 / bcMed;
        boolean htAvailable = !Double.isNaN(htMed);
        double htMBs = htAvailable ? rounds * dataMB * 1000.0 / htMed : Double.NaN;

        System.out.printf("%n  %-30s │ %d × %dMB%n", name, rounds, dataMB);
        System.out.printf("    gm-java   : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                gmMed, gmAvg, gm[0], gm[sets-1], gmMBs);
        System.out.printf("    BC        : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                bcMed, bcAvg, bc[0], bc[sets-1], bcMBs);
        if (htAvailable) {
            System.out.printf("    Hutool    : 中位 %8.1f ms │ 均值 %8.1f │ 最小 %8.1f │ 最大 %8.1f │ %.1f MB/s%n",
                    htMed, htAvg, ht[0], ht[sets-1], htMBs);
        } else {
            System.out.printf("    Hutool    : %s%n", htUnavailableReason == null ? "N/A" : "N/A │ " + htUnavailableReason);
        }

        String winner = computeWinner(gmMed, bcMed, htMed, htAvailable);
        double best = htAvailable ? Math.min(gmMed, Math.min(bcMed, htMed)) : Math.min(gmMed, bcMed);
        double pctGm = gmMed == best ? 0 : (gmMed - best) / best * 100;
        double pctBc = bcMed == best ? 0 : (bcMed - best) / best * 100;
        double pctHt = htAvailable && htMed != best ? (htMed - best) / best * 100 : 0;
        System.out.printf("    >>> %s 最快", winner);
        if (pctGm > 0) System.out.printf("  gm-java慢 %.1f%%", pctGm);
        if (pctBc > 0) System.out.printf("  BC慢 %.1f%%", pctBc);
        if (pctHt > 0) System.out.printf("  Hutool慢 %.1f%%", pctHt);
        System.out.println();

        String resultName = name + " (" + dataMB + "MB)";
        RESULTS.add(new BenchmarkResult(category, resultName, gmMBs, bcMBs, htMBs, "MB/s", winner, htUnavailableReason));
    }

    static String computeWinner(double gmMed, double bcMed, double htMed, boolean htAvailable) {
        double best = htAvailable ? Math.min(gmMed, Math.min(bcMed, htMed)) : Math.min(gmMed, bcMed);
        if (gmMed == best) return "gm-java";
        if (bcMed == best) return "BC";
        return "Hutool";
    }

    static double avg(double[] a) {
        double s = 0;
        for (double v : a) s += v;
        return s / a.length;
    }

    static class TeeOutputStream extends OutputStream {
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

        @Override
        public void close() throws IOException {
            out2.close();
            out1.flush();
        }
    }
}
