# SM2 Nat256 原生加速

纯 C 实现的 SM2 P-256-V1 椭圆曲线加速库，通过 JNI 为 gm-java 提供高性能标量乘法和完整 SM2 操作。

## 性能对比（SM2 各操作，200 次/轮中位数）

| 操作 | gm-java | BC | Hutool | gm vs BC |
|------|---------|-----|--------|----------|
| 密钥生成 | **6ms** | 16ms | 33ms | **gm 快 167%** |
| 加密 | **31ms** | 45ms | 46ms | **gm 快 45%** |
| 解密 | **23ms** | 33ms | 34ms | **gm 快 43%** |
| 签名 | **7ms** | 37ms | 34ms | **gm 快 429%** |
| 验签 | 28ms | **20ms** | **19ms** | gm 慢 40% |

> 密钥生成、加密、解密、签名 gm-java 全面超越 BC。SM3 持平，SM4-ECB/CBC 快 30-45%，SM4-CTR 多线程快 10-20x。
> 验签仍慢于 BC ~40%，原因：SM2 曲线 a≠0 且 p≡2(mod 3)，不支持 GLV 自同态；BC 的 JIT C2 编译器对纯 Java 域运算优化极致（自动向量化、常量折叠），在 Shamir 双标量乘法中与 C 实现性能接近。

## 核心优化技术

| 优化项 | 说明 |
|--------|------|
| **Comb 固定基点乘法** | d=32, t=8, 255 条目预计算表。32 次倍点 + 32 次加点 vs wNAF 的 256 次倍点 + 37 次加点，**固定基点乘法加速 ~3x** |
| **Montgomery CIOS 乘法** | 利用 SM2 素数 p ≡ -1 (mod 2^64)，Montgomery 参数 p'=1，归约步骤无需额外乘法 |
| **4-limb 64-bit 结构** | uint64_t[4] + `__uint128_t`，内循环仅 4×4=16 次乘法 |
| **加法链求逆** | 297S + 17M（vs 费马逐位 256S + 222M），单次求逆 7.5μs |
| **完整 SM2 操作在 C 中完成** | nativeKeyGen / nativeSignCore / nativeVerifyCore，消除所有 BigInteger 开销 |
| **mod-n Montgomery 算术** | 签名 r,s 计算全部在 C 中完成，使用 Montgomery CIOS 乘法 mod 曲线阶 n |
| **wNAF w=7/6** | 基点 w=7（32项预表），变基 w=6（16项），减少主循环非零位 |
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

## 关于 SM2 验签性能

SM2 验签需要计算 Shamir 双标量乘法 [s]G + [t]P，涉及约 258 次倍点和 80 次加点（~3700 次域乘法）。
BC 的 JIT C2 编译器对纯 Java long 算术优化极致（自动向量化、寄存器分配、常量折叠），
在这种密集循环中达到接近 C 的性能。SM2 曲线参数 a ≠ 0 且 p ≡ 2 (mod 3)，
不支持 GLV/GLS 自同态分解（secp256k1 支持因为 a=0 且 p ≡ 1 mod 3），
因此无法将 256 位标量分解为两个 128 位标量来减少循环次数。
进一步优化方向：x86-64 BMI2/ADX 汇编优化 Montgomery 乘法内循环。
