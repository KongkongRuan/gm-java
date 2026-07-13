# gm-java 热点分析报告

> 目标：用 profiling 工具找出 SM2 验签、SM3 1MB hash、SM4-CBC/ECB 加密的真正热点，避免在已经饱和的地方浪费精力。
> 
> 测试时间：2026-07-13  
> 测试人：Kimi Code CLI  
> JDK：21.0.6 (Java HotSpot(TM) 64-Bit Server VM)  
> OS：Windows 10 amd64  
> CPUs：20  
> Nat256 JNI：available（`nat256mul.dll` 已加载）

---

## 一、使用工具与执行命令

### 1.1 工具组合

| 工具 | 用途 | 开关/命令 |
|------|------|-----------|
| 项目自带 SM4 分相位计时 | pad / core / copy / unpad | `-Dgm.time=true` |
| 项目自带 SM2/SM4 debug 总耗时 | 打印单次耗时 | `-Dgm.debug=true` |
| 项目自带 SM3 debug | doFinal() 内 final 块耗时 | `-Dsm3.debug=true` |
| JFR (JDK 21) | 方法级 CPU/Native/Allocation 热点 | `java -XX:StartFlightRecording=...` |
| System.nanoTime() 插桩 | SM2 验签分相位：SM3、native、BigInteger、Shamir | `ProfileHarness` |
| async-profiler | 环境未安装，未使用 | N/A |

### 1.2 关键执行命令

```bash
# 1. 编译主代码与 profiling harness
mvn -q compile -DskipTests
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt -DincludeScope=test
javac -cp "target/classes;target/cp.txt" -d target/test-classes src/test/java/com/yxj/gm/ProfileHarness.java

# 2. 设置 classpath（Bash 中分号需放进变量，避免被解释为命令分隔符）
CP="target/classes;target/test-classes;$(cat target/cp.txt)"

# 3. 分操作运行并抓取 JFR
java -cp "$CP" -XX:StartFlightRecording=dumponexit=true,filename=reports/profiling/sm2verify.jfr,settings=profile,maxsize=500m \
     -Dgm.time=true -Dgm.debug=true -Dsm3.debug=true \
     com.yxj.gm.ProfileHarness sm2verify

java -cp "$CP" -XX:StartFlightRecording=dumponexit=true,filename=reports/profiling/sm2verify-java.jfr,settings=profile,maxsize=500m \
     -Dgm.time=true -Dgm.debug=true -Dsm3.debug=true \
     com.yxj.gm.ProfileHarness sm2verify-java

java -cp "$CP" -XX:StartFlightRecording=dumponexit=true,filename=reports/profiling/sm3-1mb.jfr,settings=profile,maxsize=500m \
     -Dgm.time=true -Dgm.debug=true -Dsm3.debug=true \
     com.yxj.gm.ProfileHarness sm3

java -cp "$CP" -XX:StartFlightRecording=dumponexit=true,filename=reports/profiling/sm4cbc.jfr,settings=profile,maxsize=500m \
     -Dgm.time=true -Dgm.debug=true -Dsm3.debug=true \
     com.yxj.gm.ProfileHarness sm4cbc

java -cp "$CP" -XX:StartFlightRecording=dumponexit=true,filename=reports/profiling/sm4ecb.jfr,settings=profile,maxsize=500m \
     -Dgm.time=true -Dgm.debug=true -Dsm3.debug=true \
     com.yxj.gm.ProfileHarness sm4ecb

# 4. JFR 热点/分配分析示例
jfr view --width 160 hot-methods reports/profiling/sm3-1mb.jfr
jfr view --width 160 allocation-by-site reports/profiling/sm4ecb.jfr
jfr view --width 160 native-methods reports/profiling/sm2verify.jfr
```

---

## 二、SM2 验签热点

### 2.1 带 JNI 的默认路径（生产环境）

| 指标 | 数值 |
|------|------|
| 中位总耗时 | **61–70 µs/op** |
| 吞吐量（相对） | 约 16,000 op/s |

**分相位耗时（System.nanoTime 插桩，300 次调用）：**

| 阶段 | 耗时 | 占比 | 说明 |
|------|------|------|------|
| SM3 哈希（Za\|\|M） | ~0.14 ms / 300 次 | **~0.9%** | 短消息 + Za，哈希量小 |
| native verify core | ~15.9 ms / 300 次 | **~99.0%** | `Nat256Native.nativeVerifyCore` |
| BigInteger 转换 | ~0 ms | 0% | JNI 路径已跳过 |
| BigInteger 模运算 | ~0 ms | 0% | JNI 路径已跳过 |
| Shamir 双标量乘 | ~0 ms | 0% | 在 native 中完成 |
| 其它/开销 | ~0.02 ms | ~0.1% | 方法调用、数组拷贝 |

**JFR 热点：**

```text
Native Methods:
  com.yxj.gm.util.JNI.Nat256Native.nativeVerifyCore(...)   75.0% samples

Java hot-methods 几乎无样本，说明 Java 端已不再是瓶颈。
```

**结论：** 当 `Nat256Native` 可用时，SM2 验签的绝对瓶颈是 **native verify core**。任何 Java 端的 BigInteger/对象分配优化对默认路径影响微乎其微。

### 2.2 JNI 不可用时的 Java 回退路径（故障降级场景）

通过 `Nat256Native.markUnavailable()` 强制走 Java 路径：

| 指标 | 数值 |
|------|------|
| 中位总耗时 | **165–205 µs/op**（约为 JNI 路径的 3×） |

**分相位耗时：**

| 阶段 | 耗时 | 占比 | 说明 |
|------|------|------|------|
| SM3 哈希（Za\|\|M） | ~0.15 ms / 300 次 | **~0.3%** | 仍然很小 |
| BigInteger 转换（e/r/s/pubKey → BigInteger） | ~0.15 ms | **~0.3%** | 4 次 `new BigInteger(1, bytes)` |
| BigInteger 模运算（T = r+s mod N，R = e+x mod N） | ~0.05–0.17 ms | **~0.4%** | 模加/模比较 |
| **Shamir 双标量乘法** | **~44.7 ms / 300 次** | **~98.6%** | 绝对瓶颈 |
| 其它/开销 | ~0.05 ms | ~0.2% | |

**JFR Java 热点方法：**

```text
Java Methods that Executes the Most
  com.yxj.gm.util.SM2P256V1Field.sqrCoreJava(...)        37.50%
  com.yxj.gm.util.SM2P256V1Field.mulCoreJava(...)        18.75%
  com.yxj.gm.util.SM2P256V1Field.sqr(...)                 9.38%
  com.yxj.gm.util.SM2P256V1Field.reduce(...)              9.38%
  com.yxj.gm.util.SM2P256V1Field.twice(...)               6.25%
  com.yxj.gm.util.SM2P256V1Field.subPCond(...)            6.25%
```

**分配压力（Java 回退）：**

```text
Allocation by Class
  int[]                                                   34.53%
  byte[]                                                  17.97%
  java.math.BigInteger                                     1.99%
  java.math.MutableBigInteger                              1.82%
```

**结论：** Java 回退路径的瓶颈是 **Shamir 双标量乘法中的有限域乘方/乘法/归约**。`SM2P256V1Field.sqrCoreJava` 和 `mulCoreJava` 占半壁江山。`int[]` 临时分配主要来自 `mul()/sqr()` 的无 ext 重载（内部 `new int[16]`）以及 wNAF/预计算表构建。

---

## 三、SM3 1MB Hash 热点

| 指标 | 数值 |
|------|------|
| 中位总耗时 | **~2980 µs/op** |
| 吞吐量 | **~335 MB/s** |
| 完整分组数 | 16384（1 MB / 64 B） |

**分相位耗时（单次调用内 nanoTime）：**

| 阶段 | 耗时 | 占比 | 说明 |
|------|------|------|------|
| `update()` 处理 16384 个完整 64B 分组 | ~2960 µs | **~99.1%** | 每个 CF ~180.7 ns |
| `doFinal()` 填充 + 最终压缩 + 输出 | ~0.5 µs | **~0.0%** | 可忽略 |

**JFR 热点方法：**

```text
Java Methods that Executes the Most
  com.yxj.gm.SM3.SM3Digest.CF(...)                       97.01%
  com.yxj.gm.SM3.SM3Digest.update(...)                    1.36%
  com.yxj.gm.SM3.SM3Digest.processBlock(...)              0.54%
```

**关于 `-Dsm3.debug=true` 的陷阱：**  
项目自带的 `SM3Digest` debug 计时只统计 **无参 `doFinal()`** 内部的时间（最终 1–2 个填充分组 + 结果输出）。对于 1MB 数据，它会错误地显示 `finalBlocks` 占 50% 以上，因为 `update()` 中的 16384 次完整 CF 根本没被计时。本报告使用外部 nanoTime 重新测量，才得到真实比例。

**分配压力：** JFR 显示 `byte[]` 仅占 27.5%，且大量是 JVM/Provider 初始化开销；`SM3Digest` 自身每调用只分配 `finalBlock[]` 和 `result[32]`，压力很小。

**结论：** SM3 1MB 的绝对热点是 **CF 压缩函数**。它已经使用 int 寄存器、预计算 T_ROTATED、FastIntView/Unsafe 做字节转换，Java JIT 已优化得很充分。进一步提升需要 SIMD/AVX2 或对多消息做 batch并行。

---

## 四、SM4-CBC 1MB 加密热点

| 指标 | 数值 |
|------|------|
| 中位总耗时 | **~5700–6350 µs/op** |
| 吞吐量 | **~157–175 MB/s** |

**分相位耗时（`-Dgm.time=true`，修复 CBC core 计时后）：**

| 阶段 | 占比 | 说明 |
|------|------|------|
| pad（PKCS7 填充 + 分配 padded[]） | **~2.4%** | 因 1MB 已接近 16 对齐，填充量小 |
| core（32 轮 + CBC 异或，串行） | **~97.6%** | 绝对瓶颈 |
| copy | 0% | 结果直接写入新数组，无额外拷贝 |
| unpad | 0% | 加密无此阶段 |

**JFR 热点方法：**

```text
Java Methods that Executes the Most
  com.yxj.gm.SM4.SM4Cipher.blockEncryptCBCInt(...)       93.41%
  com.yxj.gm.SM4.SM4Cipher.padding(...)                   4.95%
```

**分配压力：**

```text
Allocation by Site
  com.yxj.gm.SM4.SM4Cipher.padding(...)                  50.80%
  com.yxj.gm.SM4.SM4Cipher.blockEncryptCBCInt(...)       45.25%   // result[] 分配
```

**结论：** CBC 加密是串行链式依赖，无法像 ECB/CTR 那样并行。热点集中在 `blockEncryptCBCInt` 的轮函数和 XOR 融合循环。分配方面，`padded[]` + `result[]` 每次各约 1MB，是主要 GC 压力来源。

---

## 五、SM4-ECB 1MB 加密热点

| 指标 | 数值 |
|------|------|
| 中位总耗时 | **~630–740 µs/op** |
| 吞吐量 | **~1350–1580 MB/s** |

**分相位耗时（`-Dgm.time=true`）：**

| 阶段 | 占比 | 说明 |
|------|------|------|
| pad（PKCS7 填充 + 分配 padded[]） | **~32.9%** | 每次新建 ~1MB+16 数组并复制 |
| core（32 轮，线程池并行） | **~67.1%** | 分组独立，多核并行 |
| copy | 0% | |
| unpad | 0% | 加密无此阶段 |

**JFR 热点方法：**

```text
Java Methods that Executes the Most
  com.yxj.gm.SM4.SM4Cipher.lambda$parallelCore$1(...)    93.41%   // 线程池任务
  java.util.concurrent.CountDownLatch.countDown()         3.49%   // 同步开销
  com.yxj.gm.SM4.SM4Cipher.cipherCoreOff(...)             1.94%
  com.yxj.gm.SM4.SM4Cipher.bytesToIntBE(...)              0.39%
```

**分配压力：**

```text
Allocation by Site
  com.yxj.gm.SM4.SM4Cipher.padding(...)                  61.57%
  com.yxj.gm.SM4.SM4Cipher.blockEncryptECBInt(...)       36.80%   // result[] 分配
```

**结论：** ECB 加密的瓶颈是 **并行轮运算 + 填充分配**。核心轮运算已经多线程化，67% 时间在 core；但 **33% 时间花在 PKCS7 填充上**，这是容易被忽略的隐藏瓶颈。`padding()` 每次 `new byte[m.length+t]` + `System.arraycopy` 对 1MB 数据非常昂贵。

---

## 六、四类 API 的临时对象分配检查

| 类 | 明显可消除/可复用的分配 | 影响 | 备注 |
|------|------------------------|------|------|
| **SM2Signature** | 每次验签 `new SM3Digest()` | 低（native 路径）/ 中（Java 回退） | 可用 ThreadLocal 复用；native 路径总耗时中 SM3 仅占 0.9%，收益有限 |
| **SM2Signature** | `new BigInteger(1, bytes)` × 4–7 次 | 仅在 Java 回退路径 | native 路径已跳过；可改为 int[8] 直接传 native |
| **SM2Cipher** | 每次加密 `new byte[32]` × 多份、`new SM3Digest()`、KDF 内 `new byte[4]` 和 `new SM3Digest()` | 高 | SM2 加密单次即 2–3 次标量乘 + KDF 多次 SM3，对象分配密集 |
| **SM2Cipher.SM2_KDF** | 每轮 `digest.doFinal()` 产生 `byte[32]`，然后 `System.arraycopy` | 中 | 可改为 streaming update + 直接写目标数组，减少中间数组 |
| **SM3Digest** | `doFinal()` 中 `new byte[remainder<=55?64:128]` 和 `new byte[32]` | 低 | 可改为复用成员变量，但 1MB 场景下占比 <1% |
| **SM4Cipher** | `cipherCore/decryptCore` 中 `new byte[16]`（OFB/GCM 调用） | 中 | 高频小数组，可用 ThreadLocal 或传参复用 |
| **SM4Cipher** | ECB/CBC 每次 `padding()` 新建 padded[] + `result = new byte[padded.length]` | **高** | 1MB 数据每次 2MB 堆分配；NoPadding 已复用输入，但 Pkcs7  unavoidable 需要新数组 |
| **SM4Cipher** | `extKeyInt()` 每次新建 `int[36]`、`int[32]` | 中 | 短数据/多次调用同 key 时可用；1MB 已摊薄 |
| **SM4Cipher** | GCM 中 `block()` 产生 `byte[][]`、GHASH 中大量 `byte[16]` | **高** | 未在本次 profiling 范围内，但代码审查可见明显临时数组 |

---

## 七、跨算法优化建议（按 预期收益 / 实现难度 排序）

### 高 ROI、低难度

1. **SM4 ECB/CBC：消除 Pkcs7 填充的 1MB 临时数组**
   - 现状：`padding()` 每次 `new byte[m.length+t]` 并 `System.arraycopy`。
   - 方案：提供 `cipherEncrypt(byte[] key, byte[] in, int inOff, int len, byte[] out, int outOff, byte[] iv)` 的 in-place/no-alloc 重载；或对 Pkcs7 采用“先写原数据、最后补填充字节到输出数组”的方式，避免中间 padded[]。
   - 预期收益：ECB 提升 ~30–35%；CBC 提升 ~2–5%（CBC core 占主导）。

2. **SM4 OFB/GCM：复用 `byte[16]` 临时缓冲**
   - `cipherCore()` 每次返回新的 `byte[16]`；GCM 的 `GCTR` 中每轮也新建 `byte[16]`。
   - 方案：增加 `cipherCore(byte[] in, int inOff, byte[] out, int outOff, int[] rk)` 原地位版本，避免堆分配。
   - 预期收益：GCM/OFB 小数据高频场景显著；1MB ECB/CBC 已有 `cipherCoreOff` 优化，收益小。

3. **SM2Signature：复用 SM3Digest**
   - 每次 `verify()` 新建 `SM3Digest`。
   - 方案：ThreadLocal<SM3Digest> + `resetState()`（需确认 reset 彻底）。
   - 预期收益：native 路径 SM3 仅占 0.9%，收益很小；Java 回退路径 SM3 占 0.3%，同样很小。优先度低。

### 高 ROI、高难度

4. **SM3 1MB：SIMD / AVX2 / 多消息 batch**
   - 现状：CF 占 99%，Java int 运算已接近单线程极限（335 MB/s）。
   - 方案：native 实现 SM3 CF（AVX2/AVX-512）或一次处理 4/8 条消息的 batch，利用 SIMD 并行多条消息。
   - 预期收益：2–5× 提升，但需维护多平台 native 库。

5. **SM2 验签 Java 回退： assembly 优化 Montgomery / Solinas 域运算**
   - 现状：`sqrCoreJava` + `mulCoreJava` + `reduce` 占 75% Java 样本。
   - 方案：x86-64 上用 BMI2/ADX 指令优化 256-bit 乘法内循环；或直接使用 Project Everest / fiat-crypto 生成的汇编。
   - 预期收益：Java 回退路径可提升 2–3×，但实现复杂。

### 低 ROI（已接近 JIT 极限）

6. **SM2 验签 native 路径的 Java 端优化**
   - 99% 时间在 `nativeVerifyCore`，Java 端 BigInteger/对象分配已被绕过。
   - 继续优化 Java 端收益极低。

7. **SM4 CBC core 的纯 Java 优化**
   - 已经做了 int 寄存器、T-Table、XOR 与轮函数融合。
   - CBC 串行依赖决定无法简单并行，纯 Java 已接近单核极限。

8. **SM4 ECB core 的纯 Java 优化**
   - 已经多线程并行，core 占 67%。
   - 再优化单核轮函数收益有限，不如做 SIMD native 或优化填充。

### 架构/API 层面

9. **暴露 streaming / in-place API**
   - 现状：`cipherEncrypt(byte[], byte[], byte[])` 一次性返回新数组，大消息复制开销高。
   - 方案：增加 `update/doFinal` 风格或 `process(in, inOff, len, out, outOff)` 接口，允许调用方复用输出缓冲。
   - 预期收益：减少 GC 压力，提升服务端长连接/大文件吞吐。

10. **SM2 批量验签 / 全 native 验签（仓库已有实验代码）**
    - 仓库里 `SM2Signature` 已有 `verifyFull`、`verifyBatch` 实验方法。
    - 如果 native DLL 补齐对应符号，可消除每条消息的 Za 计算和 JNI 往返，显著提升 TPS。

---

## 八、核心结论

1. **真正值得 native/SIMD 化**：SM3 CF、SM2 Shamir/域运算（Java 回退）、SM4 轮函数（若要在单核上继续突破）。
2. **已经是 Java JIT 极限，再投入收益很低**：SM4 CBC 串行 core、SM2 native 验签的 Java 端、SM3 的 Java int 内循环。
3. **隐藏瓶颈在 API 设计/对象分配**：SM4 Pkcs7 填充占 ECB 33%、SM4 结果数组每次新建 1MB、SM2Cipher/SM4 GCM 中大量临时 `byte[16]` 和 `byte[][]`。
4. **优先做**：为 SM4 增加 in-place/no-alloc API 并消除填充临时数组；其次补齐 native 批量 SM2 验签；最后才考虑 SM3/SM4 的 SIMD native。

---

## 九、生成的 JFR 文件

全部位于 `reports/profiling/`：

- `sm2verify.jfr` — SM2 验签（native 路径）
- `sm2verify-java.jfr` — SM2 验签（Java 回退路径）
- `sm3-1mb.jfr` — SM3 1MB hash
- `sm4cbc.jfr` — SM4-CBC 1MB 加密
- `sm4ecb.jfr` — SM4-ECB 1MB 加密
