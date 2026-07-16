# 更新日志

## 未发布

- **SM2 验签输入校验前移**：`verify`、`verifyInt`、`verifyFull` 和 `verifyBatch` 在 ZA/SM3/JNI 之前统一拒绝空值、错误长度、非规范或不在曲线上的公钥点、超过 8191 字节的 ID，以及不满足 `1 <= r,s < n` 的签名分量；非法验签输入统一返回 `false`
- **SM2 签名参数契约明确化**：消息不能为空，私钥必须是满足 `1 <= d <= n-2` 的 32 字节值，公钥必须是 64 字节规范 SM2 曲线点；非法签名参数抛出 `IllegalArgumentException`
- **SM2 ZA 线程本地缓存**：默认缓存当前线程最近一次 ID/公钥对应的 ZA，重复验签可减少摘要预计算；可通过 JVM 参数 `-Dgm.sm2.zaCache=false` 关闭
- **SM2 JNI 回退行为统一**：`verifyInt`、`verifyFull`、`verifyBatch` 遇到 native 调用异常时标记 native 不可用并回退到 Java 实现
- **SM2 native 热路径优化**：验签命中线程本地公钥预计算缓存后直接引用缓存表，移除每次约 1 KB 的表复制；清理错误且未启用的 ADX 实验实现，Windows x64 DLL 已按最终源码重建
- **SM2 native 差分测试**：新增 `native/native_mul_test.c` 和 `native/test-native.bat`，覆盖 generic/BMI2/BMI2+ADX Montgomery 路径、别名输入和 Shamir 双标量乘法
- **SM2 批量验签抗退化**：混合批次只将通过输入校验的条目打包送入 JNI，非法条目直接返回 `false`，不再因单个坏条目让整个批次退回逐条验签
- **性能基准口径修正**：SM2/SM3 改用纳秒计时，避免毫秒计时精度不足；BC SM2 lightweight engine/signer 改为计时前初始化并复用，签名使用与 gm-java 相同的 raw64 编码；SM4 ECB/CBC/CTR 统一为 NoPadding、真实工作模式和等长输入，解密计时不再包含加密
- **交叉正确性覆盖增强**：新增 SM4 ECB/CBC/CTR 与 BC 的密文一致性及交叉解密测试，并补充 SM2 固定向量、签名分量/私钥边界、空消息批量验签、Java 回退、缓存数组变更和线程隔离测试
- **SM2 native 验签移除模逆**：验签改为在 Jacobian 项目坐标下直接完成 `(e + x1) mod n == r` 比较（利用 `n < p < 2n` 至多两个候选 `x0`、`x0+n`，先对未规约的 e 条件减 n，比较两侧统一在 Montgomery 域，保留 `Z == 0` 旧语义），消除每次验签约 297S+17M 的模逆加法链与无用的仿射 y 计算；native 验签热路径快 8.5%–10.7%，Java 端到端验签快约 11%，与 BC 的中位数差距从约 20% 收窄到约 4.5%；首次调用与多公钥轮换无回退
- **native wNAF 编码进位修复**：`wnaf_encode` 进位传播循环在标量含长段全 1 limbs 时（如 `n-1`、`2^256-1`）丢弃进位导致编码重构值不等于原标量，已修复；新增 12 组边界 + 万组随机的 wNAF 重构测试
- **SM2 验签项目坐标测试扩充**：`native/native_mul_test.c` 新增 10 万有效签名 + 10 万篡改签名的新旧路径端到端差分（旧仿射实现保留为 oracle）、100 万组合成域级用例（强制覆盖随机差分无法到达的 `x0+n` 候选、`x0+n == p`、`x0+n` 进位、`e >= n`、`Z == 0` 分支），并新增同二进制新旧验签 A/B 计时与 `felem_inv` 尾部占比实测

## 3.2.3 更新内容
- **SM4 内部并行化支持用户显式关闭**：新增 JVM 参数 `-Dgm.sm4.parallel=false`，关闭后 ECB/CTR/CBC 解密/GCM-GCTR 等可并行模式强制走单线程路径，内部线程池也不会被创建；适用于业务层自行管理线程池、容器或 Serverless 等线程敏感场景
- **SM4 线程池改为懒加载**：禁用内部并行时不再预先创建固定线程池，减少资源占用
- **README 补充 SM4 性能相关配置说明**：包括自动并行阈值、关闭并行参数
- **新增 GitHub Actions 工作流**：`.github/workflows/native-build.yml`，手动触发后可在 Windows/Linux/macOS 上自动构建 native 库产物并提交回仓库
- **补齐 native 构建脚本**：新增 `build-sm3.sh`、`build-sm4gcm.sh`（Linux/macOS 原生构建），以及 `build-sm3-linux-cross.sh`、`build-sm4gcm-linux-cross.sh`（aarch64/loongarch64/mips64 交叉编译）

## 3.2.2 更新内容（性能优化）

- **SM3 哈希性能优化**：将 `SM3Digest` 改为 streaming update，在 `update()` 阶段直接消化完整 64 字节分组，仅缓存不足 64 字节的尾部，消除了大数组拷贝与 `doFinal()` 前的扩容分配
- **实测提升**：SM3 1MB 哈希，JDK25 从 3339ms 降至 2996ms（**-10.3%**），JDK8 从 3339ms 降至 3054ms（**-8.5%**）
- **Netty 改为可选依赖**：核心 ASN1 工具类不再引用 `io.netty.buffer.ByteBuf`，作为纯加密工具包引入时不再强制传递 `netty-all`；如需 TLS/Netty 密钥协商功能，请自行显式引入 `netty-all`

## 3.2.1 更新内容

- 新增 `SM3HMac` 直接调用 API，和现有 `SM2` / `SM3` / `SM4` 的使用方式保持一致
- 新增 `XaProvider` 的 `HmacSM3` JCA `Mac` 注册，并提供 `SM3HMAC`、`HMACSM3`、`HMAC-SM3` 别名
- 补齐 `SM4` 的 `CFB` / `OFB` 模式，并补充 `NoPadding` 适配
- 补充 HMAC-SM3 与 SM4 新模式的 README 说明和单元测试

## 3.1.0 更新内容

修复依赖中的 bug 并解决 BC 库依赖传递问题

## 3.0.0 更新内容

使用 JNI 对 SM2 进行了专门优化（JNI 加载失败会自动降级使用原生 JAVA），除了 SM2 验签 gm-java 慢 43.8%，其余的均超过 BC 库的最新版本的 SM2P256V1 曲线

##### SM2 验签的 Shamir 双标量乘法需要 ~258 次倍点 + ~80 次加点，这是算法固有成本。SM2 曲线 a ≠ 0 且 p ≡ 2 (mod 3)，不支持 GLV 自同态分解（需要 a=0 或 p ≡ 1 mod 3）。BC 的 HotSpot C2 JIT 编译器对纯 Java long 算术优化极致，在此场景下接近 C 性能。进一步优化方向：x86-64 BMI2/ADX 汇编优化 Montgomery 乘法内循环。

- 测试结果见
#####
v3.0性能对比.txt
#####

## 2.2.1 更新内容

#### SM3 性能优化了 20%

## 2.2.0 更新内容

#### SM2 底层重构

#### 优化后的结果（BC（bcprov-jdk18on 1.76 版本））

- 密钥生成比 BC 快 1.63x
- 加密比 BC 快 2.24x
- 解密比 BC 快 3.14x
- 签名比 BC 快 2.80x
- 验签比 BC 快 1.54x

#### SM2 素数特化归约 + 更大预计算窗口

#### 核心思路

SM2 的素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1 是一个 Solinas 素数（广义 Mersenne 素数），其特殊结构允许用移位和加减法替代通用的除法取模。当前代码每次 a.multiply(b).mod(p) 会创建 2 个 BigInteger 临时对象并执行通用除法。一次标量乘法约有 1500 次这样的调用——这是最主要的性能瓶颈。

数学原理

由 p 的定义可得：2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p)
因此 512 位乘积 T = T_high * 2^256 + T_low 可以归约为：
T mod p ≡ T_low + T_high * (2^224 + 2^96 - 2^64 + 1) (mod p)
这只需要移位和加减法，完全消除了除法。

- SM2P256V1Field — 利用 SM2 素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1 的特殊结构，用 int[8] 小端数组替代 BigInteger，模归约仅需移位+加减法
- wNAF 窗口 w=7 — 预计算 32 个基点奇数倍点，将点加法从 ~37 次降至 ~32 次
- 零 BigInteger 分配 — 域运算内部全部使用 int 数组和 long 累加器，消除约 1500 个/次标量乘法的 BigInteger 临时对象

## 2.1.0 更新内容

使用 opus 全面优化了密钥生成以及加解密运算速度（虽然在 AI 时代可能不太用得上工具类了）

- 1. SM4 以及 SM3 性能与 BC 接近（SM4 CTR 使用了多线程加速，速度比 BC（bcprov-jdk18on 1.76 版本）快三倍）
- 2. SM2 略慢于 BC，后续计划对 SM2 素数做特化模归约和以及增大更大的预计算窗口
