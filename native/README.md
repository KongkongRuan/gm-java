# SM2 Nat256 原生加速

纯 C 实现的 SM2 P-256-V1 椭圆曲线加速库，通过 JNI 为 gm-java 提供高性能标量乘法和完整 SM2 操作。

## 性能对比（SM2 各操作，200 次/轮中位数）

以下数据来自 Windows x64、JDK 25、BC 1.84。BC lightweight engine/signer 在计时前初始化并复用，签名统一使用 raw64 编码，完整记录见 `reports/summary-20260714-133248.md`。

> 本轮只重建并验证了仓库内置的 Windows x64 DLL。其他平台可使用同一 `native_mul.c` 构建，但发布前仍需由多平台 CI 重建并验证对应 `.so` / `.dylib`。

| 操作 | gm-java | BC | Hutool | gm vs BC |
|------|---------|-----|--------|----------|
| 密钥生成 | **3.1ms** | 9.8ms | 14.2ms | **gm 快 68%** |
| 加密 | **15.5ms** | 28.5ms | 27.2ms | **gm 快 46%** |
| 解密 | **12.0ms** | 19.6ms | 18.7ms | **gm 快 39%** |
| 签名 | **3.1ms** | 8.7ms | 16.9ms | **gm 快 64%** |
| 验签 | 10.7ms | **9.2ms** | 9.8ms | gm 慢 16.2% |

> 密钥生成、加密、解密、签名均快于 BC。本原生库仅加速 SM2，SM3/SM4 为纯 Java 实现。
> 7 轮、每轮 5000 次的聚焦基准中，JDK 25 下 gm-java 验签约 53.6 us/op，BC 预初始化复用约 46.6 us/op，gm-java 慢约 15.1%。小轮次完整报告与聚焦微基准的百分比会受样本规模和系统抖动影响。

## 核心优化技术

| 优化项 | 说明 |
|--------|------|
| **Comb 固定基点乘法** | d=32, t=8, 255 条目预计算表。32 次倍点 + 32 次加点 vs wNAF 的 256 次倍点 + 37 次加点，**固定基点乘法加速 ~3x** |
| **Montgomery CIOS 乘法** | 利用 SM2 素数 p ≡ -1 (mod 2^64)，Montgomery 参数 p'=1，归约步骤无需额外乘法 |
| **4-limb 64-bit 结构** | uint64_t[4] + `__uint128_t`，内循环仅 4×4=16 次乘法 |
| **加法链求逆** | 297S + 17M（vs 费马逐位 256S + 222M），单次求逆 7.5μs |
| **完整 SM2 操作在 C 中完成** | nativeKeyGen / nativeSignCore / nativeVerifyCore，消除所有 BigInteger 开销 |
| **mod-n Montgomery 算术** | 签名 r,s 计算全部在 C 中完成，使用 Montgomery CIOS 乘法 mod 曲线阶 n |
| **wNAF w=7/6** | 基点 w=7（32 项预表），变基 w=6（16 项）；同公钥验签直接引用线程本地预计算表，不再复制约 1 KB 数据 |
| **批量仿射化** | Montgomery trick 批量模逆，n 个点只需 1 次求逆 |

**容错**：JNI 加载失败或调用异常时，自动回退到纯 Java 实现。

## JNI 接口层级

```
Level 4 (推荐): nativeKeyGen / nativeSignCore / nativeVerifyCore
    ↓ 完整 SM2 操作，byte[] 输入输出，零 BigInteger 开销
Level 3: nativeCombFixedBaseMul / nativeFieldMul / nativeShamirMul
    ↓ 标量乘法，int[] 输入输出
Level 2: nativeMulMod / nativeSqrMod / nativeInv
    ↓ 融合域运算
Level 1: nativeMulCore / nativeSqrCore / nativeReduce
    ↓ 向后兼容
```

## 编译

### Windows (x86_64)

```bat
cd native
build.bat
```

需要：MinGW-w64 (gcc)，JDK 路径在 `build.bat` 中配置（默认检测多个路径）

输出：`src/main/resources/native/win-x86_64/nat256mul.dll`

---

### macOS

**Intel (x86_64)：**
```bash
cd native && chmod +x build-macos-x64.sh && ./build-macos-x64.sh
```

**Apple Silicon (M1/M2/M3, aarch64)：**
```bash
cd native && chmod +x build-macos-aarch64.sh && ./build-macos-aarch64.sh
```

---

### Linux

**x86_64：**
```bash
cd native && chmod +x build-linux-x64.sh && ./build-linux-x64.sh
```

**ARM64 / LoongArch / MIPS：** 参见对应 `build-linux-*.sh` 脚本。

### 全平台自动检测

```bash
cd native && chmod +x build-all.sh && ./build-all.sh
```

---

## 资源路径与平台映射

| 平台 | 资源路径 | 库名 |
|------|----------|------|
| Windows x64 | win-x86_64 | nat256mul.dll |
| macOS Intel | macos-x86_64 | libnat256mul.dylib |
| macOS Apple Silicon | macos-aarch64 | libnat256mul.dylib |
| Linux x64 | linux-x86_64 | libnat256mul.so |
| Linux ARM64 | linux-aarch64 | libnat256mul.so |
| Linux LoongArch | linux-loongarch64 | libnat256mul.so |
| Linux MIPS | linux-mips64 | libnat256mul.so |

## 架构

```
native_mul.c
├── Section 1-2:   常量 & 辅助
├── Section 3:     Montgomery CIOS 乘法（p'=1 特化）
├── Section 4:     域运算（add, sub, neg, twice, thrice）
├── Section 5:     加法链模逆（297S + 17M）
├── Section 6:     雅可比坐标点运算（double, add_mixed, add, to_affine）
├── Section 7:     wNAF 编码
├── Section 8:     预计算表 & 批量仿射化
├── Section 9:     标量乘法（fixedBase, fieldMul, shamir）
├── Section 10:    Legacy Solinas 归约（向后兼容）
├── Section 11:    JNI 包装器（int[] 接口）
├── Section 12:    mod-n Montgomery 算术（曲线阶运算）
├── Section 13:    Comb 固定基点乘法（d=32, t=8, 255 条目表）
├── Section 14:    字节数组转换辅助
├── Section 15:    高层 SM2 操作（keygen, sign, verify）
└── Section 16:    JNI 包装器（byte[] 接口）
```

## 测试

```bash
mvn compile test-compile
mvn exec:java -Dexec.mainClass="com.yxj.gm.BenchmarkComparison" -Dexec.classpathScope=test
```

Windows x64 原生差分测试：

```bat
set JAVA_HOME=C:\Program Files\Java\jdk-21
native\test-native.bat 1000000 5000000
```

该测试会比较 generic、BMI2、BMI2+ADX 三条 Montgomery 路径，并对 Shamir 双标量乘法做差分校验。

## 关于 SM2 验签性能

SM2 验签需要计算 Shamir 双标量乘法 `[s]G + [t]P`，主要成本在 native 域运算。当前机器上最终 `7/6` 窗口的原生微基准为：同公钥热路径约 51.0 us，强制公钥缓存失效约 58.4 us，包含基点表和公钥表构建的首次调用约 72.2 us（2026-07-16 复测，`reports/native-current-20260716.log`；验签主路径另见 Phase 1 项目坐标改造，同二进制 A/B 节省 8.5%–10.7%）。

本轮同时验证并否决了几条负优化：

- `8/7` 窗口的同公钥热收益仅约 0.37%，但首次调用慢约 19.2%，轮换公钥慢约 2.7%-7.4%，因此保持 `7/6`。
- 修正后的显式 `adcx/adox` Montgomery 实现虽然通过差分测试，但比编译器生成的 BMI2 + `__int128` 路径慢约 8.8%-10%，因此未启用。
- 强制内联完整 CIOS 和绕过函数指针的实验也均产生回退，最终代码已移除这些实验路径。

BC 的 HotSpot C2 路径在双标量乘法上仍更快。SM2 曲线参数 `a != 0` 且 `p ≡ 2 (mod 3)`，不能直接采用 secp256k1 常见的 GLV 分解；后续若继续追求明显提升，应优先评估经过形式化验证的整段点运算汇编或多签名批处理，而不是继续扩大单签预计算窗口。
