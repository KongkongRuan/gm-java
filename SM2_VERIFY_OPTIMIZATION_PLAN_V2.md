# SM2 验签优化执行方案 V2（修正版）

本文档是 `SM2_VERIFY_OPTIMIZATION_PLAN.md`（下称 V1）的修正执行版。V1 保留为历史记录，不再修改。
V2 纳入了对 V1 的六方独立审计结论，修正了数据口径、边界清单、测试设计和收益预期。

本次执行范围：**Step 0（wnaf_encode 正确性修复）→ Step 1（Phase 0 基线）→ Step 2（Phase 1 项目坐标直接比较）→ Step 3（验收测量与数据回填）**。
Phase 2/3/5/6 只在本文档中给出修正后的定位，不在本次执行范围内。

## 0. 相对 V1 的六条修正

| # | 修正 | 原因（审计证据） |
|---|---|---|
| 1 | 先修 `wnaf_encode` 进位 bug，再谈优化 | `native/native_mul.c:509-511` 进位传播循环在进位越过 `dLen` 时丢弃进位；标量含长段全 1 limbs 时（如 `n-1`、`2^256-1`）编码错误。V1 §5.1 要求测 `r/s = n-1` 边界，一测必然暴露，先修 |
| 2 | 基线统一 JDK 版本与统计口径，同时报告中位数和均值，所有微基准原始输出必须存档 | V1 §1 的 native 微基准（52.3/61.7/77.1/轮换 65–67 us）无日志存档，且与同提交的 `native/README.md:147`（52.1/61.1/78.3）冲突；16.2% 差距是中位数口径且主要来自 BC 尾部抖动，均值口径两者基本持平 |
| 3 | Phase 1 边界清单补充：e 先规约、Montgomery 域一致性、Z==0 语义裁定；测试补充 x0+n 分支合成用例；收益预期从 9%–12% 下调至 8%–10% | e 是 SM3 原始输出，`P(e ≥ n) ≈ 2^-128`，`x0=(r-e) mod n` 前必须条件减 n；比较两侧必须同处 mod-p Montgomery 域（需一次 `to_mont`，候选二需 `x0+n` 的 257 位安全构造）；V1 写 "Z==0 直接返回失败" 与旧实现（映射 x1=0 仍可能通过）语义冲突，且与 V1 自己"新旧完全一致"的验收条款矛盾；`p-n` 只有 128 位，随机端到端差分命中 x0+n 分支的概率约 2^-129，百万随机差分对该分支零覆盖，必须合成构造 |
| 4 | Phase 2 降级：先做 generic 路径验证收益上限，再决定是否做 BMI2 | 当前 CIOS 乘法/归约交错结构使专用平方远比"16→10 个乘积"暗示的难；反汇编证实 BMI2 路径瓶颈在进位链而非 mulx，单次平方真实收益更可能 10%–15%，整体 4.4%–6.6%，卡在 V1 ≥4% 验收门槛边缘 |
| 5 | Phase 3 维持"有证据再做"，先试 `shamir_mul` 级单次分派的低成本变体 | 一次验签约 3126 次间接调用，但每次边际成本仅 1–3 周期 vs 域运算 50–67 周期，现实上限 2%–3%，大概率过不了 V1 自己的 3% 门槛；复制两份完整后端会把 Phase 2 改动面翻倍 |
| 6 | Phase 5 保留（收益口径自洽 15%–22%）；Phase 6 继续押后 | Phase 6 的 2–4 周工作量明显低估（AVX-512 降频、ARM 无收益、百万差分门槛未计入） |

另有一条审计发现的表述修正贯穿全文：profiling 证据（`reports/profiling/PROFILING_REPORT.md:81`，JDK 21）支持的是"约 99% 时间在 nativeVerifyCore（整个 JNI 调用）"，V1 缩窄为"99% 在 Shamir 双标量乘法"属过度引申；模逆占比 9%–12% 目前基于域运算计数（精确值 297S+17M，`native/native_mul.c:371-395`），实测拆分由 Step 1 补齐。

## Step 0：修复 wnaf_encode 进位 bug（前置，正确性修复）

### Bug 描述

`native/native_mul.c` `wnaf_encode` 中，当 digit 为负时 `val = d[0] - digit` 可能 ≥ 2^32 产生 +1 进位，
传播循环 `for (j = 1; carry && j < dLen; j++)` 在 `d[1..dLen-1]` 全为 `0xFFFFFFFF` 时进位到达 `j == dLen` 被丢弃，
编码结果重构值不等于原标量。可复现例：`k = 2^256 - 1`、`k = n - 1`。

### 修法

进位传播循环结束后，若 `carry` 仍非零且 `dLen < 9`（`d` 有 9 个槽位，初始 `d[8]=0` 使 `dLen ≤ 8`），
将进位写入 `d[dLen]` 并 `dLen++`。进位恒 ∈ {0,1}，不会溢出第 9 槽位。

### 测试（先于修复运行，确认复现；修复后必须通过）

在 `native/native_mul_test.c` 新增 `test_wnaf_reconstruction`：

- 对标量做 wNAF 编码（w=7 和 w=6），用 12-limb 有符号累加器重构 `Σ digit_i · 2^i`，与原标量比较。
- 覆盖：`0`、`1`、`n-1`、`n-2`、`2^256-1`、`2^255`、`0xAA/0x55` 交替位型、长段全 1（`2^k-1`，k=64/128/192/256）、随机标量 10000 组。
- 该测试不依赖 BMI2/ADX，放在 CPU 特性门之外运行。

### 验收

- 修复前测试在 `n-1` / `2^256-1` 上失败（确认 bug 真实存在）。
- 修复后全部通过；`test_shamir` 差分（generic/bmi2/bmi2_adx）不回归。

## Step 1（Phase 0）：统一口径的性能基线

### 口径

- JDK：统一使用 JDK 25.0.3（`C:\Program Files\Java\jdk-25.0.3`），与 V1 基线所在版本一致；profiling 历史数据是 JDK 21 的，本轮全部重测。
- 统计：同时记录中位数、均值、最小、最大；结论以中位数为主，但报告中必须披露均值。
- 存档：所有原始输出写入 `reports/`，禁止只转述数字。

### 测量项

1. Java 端到端：`BenchmarkComparison`（SM2 验签 gm-java vs BC），日志与 summary 存档至 `reports/`。
2. native 微基准：`native/test-native.bat`，输出 Shamir 热路径、首次调用、强制 miss、轮换 2/10/50/100 公钥，输出存档至 `reports/`。
3. 模逆占比实测（新增）：在 `native_mul_test.c` 中分别计时 `shamir_mul` 全程与 `felem_inv`+`jac_to_affine` 尾部，给出尾部占比实测值（验证"约 10%"的计数估算）。

### 产出

`reports/baseline-v2-*.log`（或等价命名）+ 回填到本文档"执行记录"节的基线表。Step 0 的代码改动不影响性能路径（wnaf 编码结果修正但成本相同），可在 Step 0 之后测量基线。

## Step 2（Phase 1）：Jacobian 项目坐标直接完成验签比较

### 设计（含审计补充）

1. 拆分 `shamir_mul`：新增 `shamir_mul_jac(s, px, py, t, AX, AY, AZ)`，返回 Montgomery 域 Jacobian `(X,Y,Z)`，不做仿射转换；原 `shamir_mul` 改为调用它再加 `jac_to_affine`（`nativeShamirMul` JNI 与既有测试不受影响）。
2. 新增 `verify_jac_x(X, Z, e, r)`：
   - `Z == 0`：**保留旧语义**——按旧代码 `x1 = 0` 处理，即判断 `modn_add(e, 0) == r`（与 V1 "直接返回失败"不同，保证新旧逐位一致）。
   - e 规约：`e_red = e ≥ n ? e - n : e`（用 `modn_add(e, 0)` 实现；`e < 2^256 < 2n`，一次条件减足够）。
   - `x0 = modn_sub(r, e_red)`（两操作数均 < n，前置条件成立）。
   - Montgomery 域一致性：`x0m = to_mont(x0)`（`x0 < n < p` 可直接按域元素解释）；`Z2 = mont_sqr(Z)`；检查 `X == mont_mul(x0m, Z2)`。
   - 候选二：`xp = x0 + n` 用 257 位安全加法（保留进位）；仅当无进位且 `xp < p` 时检查 `X == mont_mul(to_mont(xp), Z2)`。
   - 两候选均不匹配返回失败。不再计算模逆与仿射 y。
3. `verify_core_impl`、`verify_core_int_impl` 改用 `shamir_mul_jac` + `verify_jac_x`，其余逻辑（t 计算、t==0 检查）不变。
4. 旧仿射路径（`shamir_mul` + 原比较）完整保留，作为测试 oracle。

### 成本核对

新尾部 = 1S + 2~3M（to_mont 1M + 候选各 1M + Z2 1S）+ 廉价 modn 加减，
替代旧尾部 298S + 20M（模逆 297S+17M + `jac_to_affine` 1S+3M）。
净省约 297S + 17M，占整体验签域运算约 9%–10%（S=M 口径 10.2%，计入廉价运算后向 9% 靠拢）。

### 完整边界清单（相对 V1 的增补用 * 标出）

- `Z == 0`（含 `s == t == 0` 使 `maxLen == 0` 的路径）。
- `x0 == 0`（`e ≡ r (mod n)`）。
- *`e ≥ n`（如 `e = 2^256 - 1`），验证 e 规约——随机差分永远碰不到，必须合成。
- `x0 + n < p` 与 `x0 + n ≥ p`。
- *`x0 + n == p - 1`（候选二合法，x1 = p-1）与 *`x0 + n == p`（候选二必须拒绝）。
- *`x0 + n` 产生 256 位进位（`x0 + n ≥ 2^256`，必须拒绝且不溢出）。
- `r/s` 位于 `1`、`n-1` 边界（顺带覆盖 Step 0 修复后的 wnaf 编码）。
- 有效签名、篡改签名、随机无效签名。
- *新旧两条路径（仿射 oracle vs 项目坐标）结果逐位一致。

### 测试与验收门槛

native（`native/native_mul_test.c` 新增）：

| 测试 | 数量 | 说明 |
|---|---:|---|
| `test_wnaf_reconstruction` | 边界 + 随机 10,000 | Step 0 |
| `test_verify_jac_e2e` | ≥ 200,000 | 固定公钥池、随机 (e,r,s)，新旧路径端到端差分；随机差分对 x0+n 分支零覆盖属预期，不靠它验证该分支 |
| `test_verify_jac_synthetic` | ≥ 1,000,000 | 域级合成：随机 Z 与 x1，构造 `X = x1·Z²`，分支 A（x1<n）与分支 B（x1∈[n,p)，强制走 x0+n 候选）均须通过；X 翻转 1 位必须失败；加上面 * 标记的全部边界 |
| `test_shamir` 既有差分 | 128 | 不回归 |

Java 回归：`mvn test -Dtest=CorrectnessTest,Nat256NativeTest` 全绿（含 BC 交叉、篡改用例、native/Java fallback 一致性）。

性能验收：

- 热路径（native Shamir 微基准 + Java 端到端中位数）提升 **≥ 7%**（预期 8%–10%，不按 12% 承诺）。
- 首次调用、强制 miss、轮换公钥回退 **≤ 2%**。
- 验收测量与 Step 1 同 JDK、同机器、同口径，原始输出全部存档。

## Step 3：验收测量与数据回填

1. 重跑 Step 1 的全部测量项（同口径）。
2. 对比表回填到本文档"执行记录"节：前后中位数/均值、提升幅度、是否过门槛。
3. 过门槛：保留实现，Phase 2 按修正 #4 重新评估（先 generic 后 BMI2）。
4. 不过门槛或任何正确性不一致：整体回滚至 Step 0 之后的状态（Step 0 的 bug 修复保留），记录实测数据后结题。

## 后续阶段的修正定位（本次不执行）

- **Phase 2（专用 Montgomery 平方）**：先做 portable generic 路径验证收益上限（generic 瓶颈在乘积段，收益更大且易写对），BMI2 版本只在 generic 实测收益换算后超过门槛时再做；注意 CIOS 交错结构下非对角项乘 2 的进位复杂度，以及 adx-target 变体需要同步处理（当前三条分派路径中 `mont_mul_bmi2_adx` 只是 target attribute 版本）。
- **Phase 3（分派提升）**：默认不做。若做，先试 `shamir_mul` 级单次分派变体（一个函数指针指向整段 Shamir 实现），而非复制完整后端；门槛维持 ≥3% 且需硬件计数器证据。
- **Phase 5（显式验签上下文）**：保留，面向多公钥/多线程场景，收益口径 15%–22% 自洽；JDK 8 无 Cleaner，句柄生命周期管理成本要计入，工作量按 5–8 天估。
- **Phase 6（SIMD 多消息）**：继续押后。2–4 周低估，AVR-512 降频、ARM 无收益、只提吞吐不降延迟，对"追平 BC 单签"目标无帮助。

## 执行记录

执行时间：2026-07-16，Windows x64，gcc 14.2.0（MinGW），JDK 25.0.3（Java 测量）。

### Step 0：wnaf_encode 修复（已完成）

- 复现证据：新增 `test_wnaf_reconstruction` 在修复前于 `n-1` 用例失败（`FAIL: wNAF(w=7) reconstruction mismatch at n-1 case 2`），与审计结论一致。
- 修复：进位传播循环结束后将残余进位写入 `d[dLen++]`（`native/native_mul.c`）。
- 修复后：12 组边界 + 10000 随机标量重构全部通过，Montgomery/Shamir 差分不回归。

### Step 1：基线（JDK 25.0.3，中位数 + 均值双口径）

native 微基准（`reports/baseline-v2-native-20260716-114024.log`）：

| 场景 | 延迟 |
|---|---:|
| Shamir 热路径 | 50.69 us/op |
| felem_inv | 4275.50 ns/op |
| jac_to_affine（含 felem_inv） | 4466.88 ns/op（占 Shamir 约 8.8%，实测证实计数估算的 9%–10%） |
| 首次调用 | 76.63 us |
| 强制 miss | 58.05 us |
| 轮换 2/10/50/100 | 60.96 / 64.99 / 65.45 / 65.51 us |

Java 端到端（Sm2OnlyBench 5000 次/组 × 7 组，`reports/baseline-v2-sm2-20260716-114042.log`）：

| 实现 | 中位数 | 均值 | avg/次 |
|---|---:|---:|---:|
| gm-java 验签 | 268.3 ms | 270.4 ms | 54.09 us |
| BC 验签 | 224.0 ms | 225.4 ms | 45.09 us |
| 差距 | 19.8% | 20.0% | — |

注：本轮 BC 尾部稳定（最大 239.3 ms），两个口径差距一致；V1 引用的 0714 轮 16.2% 中位数差距确实主要来自 BC 尾部抖动，审计结论成立。

### Step 2：Phase 1 实现与测试（已完成）

实现：`shamir_mul` 拆分为 `shamir_mul_jac`（返回 Montgomery Jacobian，不做仿射转换）+ 原签名 wrapper；新增 `verify_jac_x`（e 先条件减 n 规约、`to_mont` 统一 Montgomery 域、`Z == 0` 保留旧 x1=0 语义、候选二 257 位安全构造且不做 mod-p 约减）；`verify_core_impl` 与 `verify_core_int_impl` 改用新路径，旧仿射路径保留为 oracle。

正确性（`reports/phase1-v2-native-20260716-115343.log`）：

- wNAF 重构 12 边界 + 10000 随机：PASS
- Montgomery 差分 1,000,100 组 + 别名：PASS
- Shamir generic/bmi2/bmi2_adx 差分 128 组：PASS
- 验签端到端差分 100,000 有效签名（新旧均接受）+ 100,000 篡改签名（新旧均一致拒绝）：PASS
- 合成域级用例 1,000,000 组（一半强制走 `x0+n` 候选）+ 8 组边界（`Z==0` 三种、`e=2^256-1`、`x0==0`、`x0+n==p`、`x0+n==p-1`、`x0+n==2^256`、`x0+n≥p` 反 mod-p 约减）：PASS
- Java 回归：`CorrectnessTest` + `Nat256NativeTest` 共 33 项全绿（经 classpath 暂存目录确认加载的是新 DLL：205892 字节，sha256[0:8]=68873cbee39cc004）

### Step 3：验收测量（同 JDK、同机器、同口径）

native 热路径（同二进制 A/B，两轮）：

| 轮次 | projective | affine-oracle | 节省 |
|---|---:|---:|---:|
| 第 1 轮（115310 前） | 44.51 us | 49.85 us | 5.34 us = **10.7%** |
| 第 2 轮（`reports/phase1-v2-native-20260716-115343.log`） | 45.51 us | 49.72 us | 4.21 us = **8.5%** |

Java 端到端（`reports/phase1-v2-sm2-20260716-115310.log` vs 基线）：

| 指标 | 基线 | Phase 1 | 变化 |
|---|---:|---:|---:|
| gm-java 验签中位数 | 268.3 ms | 238.6 ms | **-11.1%** |
| gm-java 验签均值 | 270.4 ms | 239.3 ms | **-11.5%** |
| gm-java avg/次 | 54.09 us | 47.87 us | -11.5% |
| 与 BC 中位数差距 | 19.8% | 4.5% | 收窄 15.3 pp |
| 与 BC 均值差距 | 20.0% | 4.1% | 收窄 15.9 pp |

冷路径（native 微基准第 2 轮 vs 基线，这些路径不经过新代码，差异即噪声）：首次调用 -6.5%、强制 miss -0.4%、轮换 2/10/50/100 为 -5.7% / -5.6% / -0.9% / -0.1%，全部无回退。

### 验收结论

- 热路径：native 8.5%–10.7%、Java 端到端约 11%，**≥ 7% 门槛通过**（落在修正后预期 8%–10% 区间上沿）。
- 冷路径：首次调用、强制 miss、多公钥轮换**无回退**（差异均在噪声内）。
- 正确性：全部差分/合成/回归测试通过。
- **结论：Phase 1 通过验收，实现保留。** 与 BC 的验签中位数差距从约 20% 收窄到约 4.5%。
- 后续：Phase 2 按修正 #4 重新评估（先做 portable generic 专用平方验证收益上限，再决定 BMI2）；Phase 3 维持不做，除非先有 shamir 级单次分派变体的测量证据。

### Phase 2：generic 专用平方试点（已完成，结论：放弃）

按修正 #4 先做 portable generic 路径验证收益上限。

实现：SOS 结构专用平方 `mont_sqr_generic`（交叉项 6 个乘积 → t[0..7] 翻倍 → 对角线 4 个乘积 → 与 `DEFINE_MONT_MUL` 相同的 SM2 特形 Montgomery 归约），经新增 `g_mont_sqr_impl` 指针分派；bmi2/bmi2_adx 路径暂以 sqr-via-mul 包装器接分派。实验代码已回退，完整改动存档于 `reports/sm2-phase2-mont-sqr-experiment.patch`（289 行，含测试）。

正确性（通过）：100 万随机 + 7 边界（0、1、p-1、2^255、0xAA/0x55 交替、全 1）与 `mont_mul_generic(a,a)` 差分一致，别名用例通过。

性能（`reports/phase2-v2-native-20260716-sqr.log`，两轮一致）：

| 指标 | 专用平方 | sqr-via-mul | 变化 |
|---|---:|---:|---:|
| 单次平方（500 万轮） | 30.74 ns | 18.19 ns | **-69%（回退）** |
| generic 验签端到端 | 55.78 us | 47.43 us | **-17.6%（回退）** |

分析：SOS 的 t[8] 中间数组在本编译器（gcc 14.2 MinGW, -O3）下无法全部驻留寄存器，溢出到栈的 load/store 加上 t 翻倍环节的 128 位移位进位链，吃掉了 16→10 个乘积的理论收益；CIOS 乘法本身已相当紧凑（本机 generic/bmi2/bmi2_adx 单乘均在 17–18 ns）。verify 阶段计时存在约 ±8–10% 漂移（同轮 bmi2_adx 复测 54–56 us vs generic 47–48 us），故结论锚定 500 万轮微基准——单次平方慢 69%，端到端不可能为正。

决策：generic 试点实测为负（远低于 ≥4% 门槛），按修正 #4 **BMI2 专用平方不再进行，Phase 2 整体放弃**。`native/native_mul.c`、`native/native_mul_test.c` 已回退至 Phase 1 提交状态（回退后测试复跑通过）。

### Phase 3：shamir 级单次分派试点（已完成，结论：关闭）

按修正 #5 实测低成本变体。方法：`native_mul.c` 加编译期钩子 `GM_DIRECT_MONT_MUL`/`GM_DIRECT_MODN_MUL`（`#ifdef` 保护，默认关闭，对正常构建零影响），构造两个对照二进制，10 轮交错 A/B 抗频率漂移（数据：`reports/phase3-v2-dispatch-20260716.log`）：

| 实验 | 配置 | verify projective 中位数 | 相对 normal |
|---|---|---:|---:|
| 1 完全内联上限 | 全 TU `-mbmi2 -madx` + 直调 leaf（ALWAYS_INLINE 强制内联，mulx 指令点 94→492） | 47.38 us | **慢 4.2%** |
| 2 纯分派开销 | noinline 包装器直调 leaf（只去间接调用，不内联） | 46.74 us | +1.3%，剔除离群后 <1%，**噪声内** |

结论：纯间接调用开销测不出（<1%），而完全内联因代码膨胀反而慢 4.2%。shamir 级单次分派不可能达到 ≥3% 门槛，**Phase 3 关闭，不再做**。实验源码留存：`native/phase3_ceiling_test.c`、`native/phase3_direct_test.c`。

### Phase 6：SIMD 多消息可行性验证（已完成，结论：维持押后）

- **CPU 能力**：本机 Core Ultra 7 265K（Arrow Lake）有 AVX2/BMI2/ADX，**无 AVX-512/IFMA**——8 通道 52 位 limb（vpmadd52）这一唯一有明确 2–4× 收益的 SIMD 形态在本机不可用，只剩 AVX2（vpmuludq 32×32→64）路线。
- **机器探针**（`native/phase6_simd_probe.c`，数据：`reports/phase6-v2-simd-probe-20260716.log`）：
  - A 依赖链标量 mont_mul：**19.6 ns/op**（延迟受限）；
  - B 4 路独立标量交错：**12.8 ns/msg**（A 的 65%）——OOO 重叠四条进位链只拿到约 1.5× 吞吐，批量场景的大部分空间连"无新域代码的交错标量"都吃不透；
  - C vpmuludq 吞吐：**0.164 ns/instr**。
- **估算**：AVX2 4 路域乘需 64 个 vpmuludq + 约 150–250 个进位修正向量 op，理论上界约为 B 的 2–3×（仅 raw field-mul）；验签中域乘占比约 60–70%，Amdahl 后批量端到端吞吐约 1.5–2×，且只适用于批量场景。
- **与目标核对**：项目目标是单签**延迟**追平 BC，SIMD 只提吞吐不降延迟；JNI 侧无批量验签 API。结论：**维持押后**。若未来确需吞吐，第一步应是无 SIMD 的交错标量批量（零新域运算代码，约 1.5×），而非直接上 AVX2。

### 遗留事项

- ~~本机有两个 IDE 调试 JVM 持有 `target/classes` 旧 DLL 的文件锁~~（已解决 2026-07-16）：实际为 07-14 残留的两个 JShell 执行进程（PID 28652/27892），经用户确认后结束；`mvn test` 资源拷贝与测试已恢复正常，`target/classes` 中的 DLL 已更新为新构建（205892 字节），CorrectnessTest 15 项、Nat256NativeTest 18 项全部通过。
- ~~`native/README.md` 中的微基准数字（52.1/61.1/78.3 us）与本轮存档值有出入~~（已解决 2026-07-16）：已刷新为 `reports/native-current-20260716.log` 的复测值（51.0/58.4/72.2 us）。
