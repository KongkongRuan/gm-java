# GM-JAVA 性能优化修复文档

## 概述

本次优化针对 gm-java 国密算法库的密钥生成和加解密速度进行了全面的性能提升，涉及 SM2、SM3、SM4 三个核心算法模块。主要修改了 8 个文件，核心优化思路是**消除热路径上的对象分配**和**使用高效算法替代朴素实现**。

---

## 一、SM4 对称加密优化（SM4Cipher.java）

### 问题 1：S-Box 查找使用 BigInteger 做 byte→int 转换

**原因**：S-Box 是 SM4 最核心的热路径，每个 block 加密 32 轮 × 4 字节 = 128 次调用。原代码为了把 `byte` 转成无符号 `int` 索引，每次都创建一个 `BigInteger` 对象。

```java
// 修复前
private byte Sbox(byte in) {
    byte[] bs = new byte[]{(byte) 0x0, in};
    int i = new BigInteger(bs).intValue(); // 每次创建 BigInteger！
    out = SM4Constant.SboxTable[i];
}
```

**修复方案**：使用位运算 `in & 0xFF` 实现 byte→unsigned int 转换，零分配。

```java
// 修复后（内联到 tauInt 方法中）
private static int tauInt(int A) {
    return ((SM4Constant.SboxTable[(A >>> 24) & 0xFF] & 0xFF) << 24) |
           ((SM4Constant.SboxTable[(A >>> 16) & 0xFF] & 0xFF) << 16) |
           ((SM4Constant.SboxTable[(A >>> 8) & 0xFF] & 0xFF) << 8) |
           (SM4Constant.SboxTable[A & 0xFF] & 0xFF);
}
```

### 问题 2：所有位运算在 byte[] 上做，产生海量临时对象

**原因**：SM4 的轮函数 F、线性变换 L、非线性变换 τ 全部操作 `byte[4]` 数组。每次 XOR（`byteArrayXOR`）和循环左移（`bitCycleLeft`）都分配新的 `byte[]`。一个 block 加密约产生 640+ 个临时对象，加密 1MB 数据约产生 **3400 万**个临时对象。

**修复方案**：所有内部运算改用 `int` 类型：
- XOR 直接用 `^` 操作符
- 循环左移用 `Integer.rotateLeft()`
- 新增 `cipherCore(byte[] in, int[] rk)` 和 `decryptCore(byte[] in, int[] rk)` 方法

```java
// 修复后：全 int 运算
private byte[] cipherCore(byte[] in, int[] rk) {
    int x0 = bytesToIntBE(in, 0), x1 = bytesToIntBE(in, 4);
    int x2 = bytesToIntBE(in, 8), x3 = bytesToIntBE(in, 12);
    for (int i = 0; i < 32; i++) {
        int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[i]);
        x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
    }
    // ... 输出
}
```

### 问题 3：密钥扩展中的 BigInteger 滥用

**原因**：`ext_key_L` 方法中将 `int` 常量 FK/CK 通过 `Integer.toString() → BigInteger → toByteArray()` 转换为 `byte[]`，仅仅是为了做 XOR 运算。

**修复方案**：新增 `extKeyInt(byte[] key)` 方法直接用 `int` 运算，返回 `int[32]` 轮密钥。保留 `ext_key_L` 向后兼容。

### 问题 4：CTR 计数器使用 BigInteger 递增

**原因**：每加密一个 block 都创建多个 BigInteger 对象来给 128-bit 计数器加 1。

**修复方案**：直接在 `byte[16]` 上做进位加法。

```java
private static void incrementCounter(byte[] counter) {
    for (int i = counter.length - 1; i >= 0; i--) {
        if (++counter[i] != 0) break;
    }
}
```

### 问题 5：线程池每次调用重新创建销毁

**原因**：`blockEncryptCTR` 和 `GCTR` 每次调用都 `new FixedThreadPool(10)`，用完 `shutdown()`。线程创建销毁代价极高。

**修复方案**：使用类级别的静态守护线程池。

### 问题 6：processors 字段被修改后不可恢复（Bug）

**原因**：`processors` 是实例字段，在 CTR/GCTR 中被修改（`processors = blocks.length` 和 `processors++`），导致后续调用行为不确定。

**修复方案**：使用局部变量 `procs` 替代实例字段修改。

### 问题 7：GCM 的 VBox 初始化使用 O(n²) 算法

**原因**：`byteArrayRight` 将每个字节展开为 8 位数组再拼接，复杂度 O(n²)。

**修复方案**：使用直接的位移操作 `shiftRight1`。

---

## 二、SM3 哈希优化（SM3Digest.java）

### 问题 8：压缩函数 A-H 寄存器用 byte[4] 而非 int

**原因**：SM3 的 8 个工作变量 A-H 用 `byte[4]` 表示，每次运算都需要 `bytesToInt()`/`intToBytes()` 转换。64 轮循环中每轮约 10+ 次转换，每次还创建 `ByteBuffer`。每个 block 压缩约产生 **1000+ 个临时对象**。

**修复方案**：A-H 直接用 `int` 变量，消息扩展 W/W' 用 `int[]` 数组，所有运算（FF、GG、P0、P1）均为 `int` 操作。

```java
// 修复后：全 int 压缩函数
private static int[] CF(int[] V, byte[] block) {
    int A = V[0], B = V[1], C = V[2], D = V[3];
    int E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        int SS1 = Integer.rotateLeft(
            Integer.rotateLeft(A, 12) + E + Integer.rotateLeft(T, j % 32), 7);
        // ... 全部 int 运算
    }
}
```

### 问题 9：update() 方法 O(n²) 数组拼接

**原因**：每次 `update()` 用 `DataConvertUtil.byteArrAdd()` 做数组拼接，多次调用是 O(n²) 复制。

**修复方案**：改用 `ByteArrayOutputStream` 缓冲消息。

---

## 三、SM2 椭圆曲线优化（SM2Util.java）

### 问题 10（致命）：使用仿射坐标，每次点运算都需要模逆元

**原因**：这是 **最大的性能瓶颈**。在仿射坐标下，每次点加法/倍点都需要计算模逆元。模逆元的代价约等于 **80-100 次模乘**。对 256 位标量乘法，约需 ~384 次点运算，即 **384 次模逆元**。

**修复方案**：改用**雅可比坐标（Jacobian coordinates）**：
- 点以 `(X, Y, Z)` 表示，仿射坐标为 `(X/Z², Y/Z³)`
- 点加法和倍点只需要模乘和模平方，**不需要模逆**
- 整个标量乘法最终只需 **1 次模逆**转回仿射坐标
- 对 SM2 曲线 `a = p - 3` 使用优化倍点公式：`M = 3*(X - Z²)*(X + Z²)`
- 使用混合加法（Jacobian + Affine），因基点 G 始终是仿射坐标

```java
// 修复后：雅可比坐标标量乘法
private static BigInteger[] jacobianMultiply(BigInteger gx, BigInteger gy,
    BigInteger k, BigInteger a, BigInteger p, boolean aIsMinusThree) {
    BigInteger QX = BigInteger.ONE, QY = BigInteger.ONE, QZ = BigInteger.ZERO;
    for (int i = k.bitLength() - 1; i >= 0; i--) {
        // 倍点（不需要模逆！）
        BigInteger[] doubled = jacobianDouble(QX, QY, QZ, a, p, aIsMinusThree);
        QX = doubled[0]; QY = doubled[1]; QZ = doubled[2];
        if (k.testBit(i)) {
            // 混合加法（不需要模逆！）
            BigInteger[] added = jacobianAddMixed(QX, QY, QZ, gx, gy, ...);
            QX = added[0]; QY = added[1]; QZ = added[2];
        }
    }
    // 最终只需 1 次模逆转回仿射
    BigInteger zInv = QZ.modInverse(p);
    ...
}
```

### 问题 11：byte[] ↔ BigInteger 反复转换

**原因**：每次调用 `PointAdditionOperation` 内部都做 4 次 `byteToN()`、4 次 `oneAdd()`、6+ 次 `new BigInteger()`，返回时再 `toByteArray()` + `byteToN()`。一次标量乘法 ~384 次调用，产生 ~3000+ 次对象分配。

**修复方案**：内部运算全部使用 BigInteger，只在 `MultiplePointOperation` 的输入/输出处做一次转换。使用 `new BigInteger(1, bytes)` 统一处理有符号/无符号。

### 问题 12：最朴素的标量乘法 + 字符串位扫描

**原因**：用 `new BigInteger(k).toString(2)` 将 256 位整数转成字符串来逐位扫描。

**修复方案**：使用 `BigInteger.testBit(i)` 直接检查位，避免字符串创建。

### 问题 13：自实现递归扩展欧几里得算法

**原因**：`DataConvertUtil.ex_gcd()` 用递归实现，每层分配 `BigInteger[3]` 数组并重复计算除法。

**修复方案**：使用 `BigInteger.modInverse()`，这是 JDK 内置的优化实现。

---

## 四、辅助优化

### SM2Constant.java - 缓存 BigInteger 曲线参数

**原因**：`new BigInteger(SM2Constant.getP())` 在每次运算中重复创建。

**修复方案**：新增静态字段 `BIG_P`、`BIG_A`、`BIG_N` 等，类加载时初始化一次。

### SM2Cipher.java - KDF 中使用 int 计数器

**原因**：简单的 int 计数器用 BigInteger 表示，每次循环 `new BigInteger("1")`。

**修复方案**：直接使用 `int` 计数器和手动字节编码。

### SM2Signature.java / SM2SignatureBack.java - 使用 modInverse + 缓存常量

**原因**：使用 `DataConvertUtil.ex_gcd_ny()` 自实现模逆，且反复 `new BigInteger("0")`。

**修复方案**：使用 `BigInteger.modInverse()` 和 `BigInteger.ZERO`/`BigInteger.ONE` 常量。

### pom.xml - 添加 UTF-8 编码配置

**原因**：项目未指定源码编码，默认使用系统编码（GBK），导致 UTF-8 文件编译失败。

**修复方案**：添加 `project.build.sourceEncoding = UTF-8`。

---

## 修改文件清单

| 文件 | 修改类型 | 核心变化 |
|------|---------|---------|
| `SM4/SM4Cipher.java` | 重写 | 全部核心运算改为 int，S-Box 位运算索引，CTR 直接计数器，静态线程池 |
| `SM3/SM3Digest.java` | 重写 | 压缩函数全 int 运算，ByteArrayOutputStream 缓冲 |
| `util/SM2Util.java` | 重写 | 雅可比坐标标量乘法，BigInteger 内部运算，modInverse |
| `constant/SM2Constant.java` | 新增字段 | BigInteger 缓存（BIG_P, BIG_A, BIG_N 等） |
| `SM2/Cipher/SM2Cipher.java` | 优化 | KDF 用 int 计数器，Arrays.equals 比较 |
| `SM2/Signature/SM2Signature.java` | 优化 | modInverse，缓存常量 |
| `SM2/Signature/SM2SignatureBack.java` | 优化 | 同 SM2Signature |
| `pom.xml` | 配置 | 添加 UTF-8 编码 |

---

## 性能提升预估

### SM4（对称加密）

优化前每加密 1MB 数据（65536 个 block）创建约 **3400 万个临时对象**，优化后核心运算**接近零分配**。

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| S-Box BigInteger 创建 | 838 万/MB | 0 |
| XOR 数组分配 | 1441 万/MB | 0 |
| 循环左移数组分配 | 838 万/MB | 0 |
| CTR 计数器 BigInteger | 26 万/MB | 0 |
| 每 block 临时对象 | ~640 | ~2 (仅输入输出) |

### SM2（非对称加密/签名）

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| 每次标量乘法模逆次数 | ~384 | **1** |
| byte[]/BigInteger 转换 | ~3000+/次 | ~10/次 (仅边界) |
| 整体预期加速 | 基准 | **10-30 倍** |

### SM3（哈希）

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| 每 block 临时对象 | ~1000 | ~3 (W/W'/block 数组) |
| bytesToInt/intToBytes 调用 | ~20/轮×64 轮 | 0 |
| ByteBuffer 创建 | ~40/block | 0 |

---

## 向后兼容性

- 所有公开 API 签名保持不变
- `ext_key_L(byte[])` 返回 `byte[][]` 保持兼容，新增 `extKeyInt(byte[])` 返回 `int[]`
- `blockEncryptECB`、`blockEncryptCBC` 等方法仍接受 `byte[][]` 轮密钥
- `MultiplePointOperation` 和 `PointAdditionOperation` 接口完全不变
- SM3 的 `update()`、`doFinal()`、`doFinal(byte[])` 接口完全不变
