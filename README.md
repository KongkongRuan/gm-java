# GM-JAVA

GM-JAVA 是一套用 JAVA 开发的支持国密算法的加解密工具包。

## 运行环境

- 本项目发布产物按 Java 8 目标版本构建，`pom.xml` 已显式配置 `maven-compiler-plugin` 的 `source=8` 与 `target=8`
- 作为依赖使用时，推荐运行环境为 JDK 11 / 17 / 21
- 若需要运行在 JDK 8，请尽量使用较新的 8u 版本，不建议使用过老的 JDK 8

### JDK 8 已知说明

- 极老的 JDK 8 运行时可能在 `bcprov-jdk18on` 的 JCE Provider 验签阶段失败，典型报错为 `JCE cannot authenticate the provider BC`
- 这类问题通常不是 `gm-java` 自身算法实现错误，而是旧 JDK 8 对 Provider 签名链的兼容性不足
- 如果你的运行环境必须停留在旧 JDK 8，建议优先升级到更新的 8u 版本；若无法升级，再考虑回退相关 Bouncy Castle 版本并单独验证

## 项目引入

- pom 引入（已上传中央仓库）

```xml
<dependency>
    <groupId>io.github.kongkongruan</groupId>
    <artifactId>gm-java</artifactId>
    <version>3.2.3</version>
</dependency>
```

- 下载源码编译之后引入或者直接下载 gm-java-3.2.2.jar 引入

### Netty TLS 功能（可选依赖）

从 `3.2.2` 起，`gm-java` 核心算法模块不再强制依赖 `netty`。默认作为加密工具包引入时，Maven 不会传递 `netty-all`：

```xml
<dependency>
    <groupId>io.github.kongkongruan</groupId>
    <artifactId>gm-java</artifactId>
    <version>3.2.3</version>
</dependency>
```

如果需要使用 `NettyTlsClient` / `NettyTlsServer` 进行 TLS 握手密钥协商，请在自身项目的 `pom.xml` 中显式引入 `netty-all`：

```xml
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-all</artifactId>
    <version>5.0.0.Alpha2</version>
</dependency>
```

## 主要功能

### 密码算法

- 对称密码算法 SM4（ECB/CBC/CFB/OFB/CTR/GCM）
- 非对称密码算法 SM2（加解密/签名验签）
- Hash 算法 SM3
- 消息认证码 HMAC-SM3（直接调用 / JCA `Mac`）
- 基于 SM3 实现的随机数生成器（多线程加速）

### 证书

- 证书解析以及证书 SHA1 指纹计算
- SM2 证书生成

### 密钥协商

- 模拟 TLS 握手协议，通信双方协商会话密钥

## 整体功能基准测试

### test 目录下 com.yxj.gm 包 Benchmarking 类

## 快速使用

```java
String msg = "gm-java-1.0";
```

### SM2 密钥对生成

```java
KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
```

### SM2 加解密

```java
SM2Cipher sm2Cipher = new SM2Cipher();
byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), keyPair.getPublic().getEncoded());
byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, keyPair.getPrivate().getEncoded());
System.out.println("SM2解密结果：" + new String(ming));
```

### SM2 签名验签

```java
SM2Signature signature = new SM2Signature();
byte[] signature1 = signature.signature(msg.getBytes(), null, keyPair.getPrivate().getEncoded());
boolean b = signature.verify(msg.getBytes(), null, signature1, keyPair.getPublic().getEncoded());
System.out.println("SM2验签结果：" + b);
```

#### SM2 输入与性能配置

- `SM2Signature` 的签名值使用固定 64 字节裸格式 `r || s`，私钥和公钥分别使用固定 32 字节、64 字节编码。公钥还必须是规范编码的 SM2 曲线点。验签遇到空值、错误长度、非法公钥点、越界 `r/s` 或超过 8191 字节的 ID 时返回 `false`；签名参数不合法时抛出 `IllegalArgumentException`。
- SM2 签名和验签默认启用单条目的线程本地 ZA 缓存。同一工作线程反复使用相同 ID 和公钥时可省去 ZA 重算；缓存保存调用参数的内容快照，调用方修改原数组不会复用旧结果。
- 如需禁用 ZA 缓存，在 JVM 启动时添加 `-Dgm.sm2.zaCache=false`。该参数在 `SM2Signature` 类初始化时读取。

### 制作 SM2 证书

```java
// ca 证书密钥
KeyPair caKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
// 终端证书密钥
KeyPair equipKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();

SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";
CertTest certTest = new CertTest();
byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(), false, 0);
try {
    FileUtils.writeFile("D:/certtest/java-ca-3.cer", rootCert);
} catch (Exception e) {
    throw new RuntimeException(e);
}
byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, caKeyPair.getPrivate().getEncoded(), equipKeyPair.getPublic().getEncoded(), false, 0);
try {
    FileUtils.writeFile("D:/certtest/java-ownerCert-3.cer", ownerCert);
} catch (Exception e) {
    throw new RuntimeException(e);
}
// 使用 HSM 签名制作 SM2 证书
int hsmSigPriIndex = 0;
rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(), true, hsmSigPriIndex);
```

### SM3 摘要计算

```java
SM3Digest sm3Digest = new SM3Digest();
sm3Digest.update(msg.getBytes());
byte[] md = sm3Digest.doFinal();
byte[] md2 = sm3Digest.doFinal(msg.getBytes());
sm3Digest.update("gm-java-".getBytes());
sm3Digest.update("1.0".getBytes());
byte[] md3 = sm3Digest.doFinal();
System.out.println(Hex.toHexString(md));
System.out.println(Hex.toHexString(md2));
System.out.println(Hex.toHexString(md3));
```

### HMAC-SM3（直接调用）

```java
byte[] key = "1234567890abcdef".getBytes();
SM3HMac sm3HMac = new SM3HMac(key);
sm3HMac.update(msg.getBytes());
byte[] tag = sm3HMac.doFinal();
System.out.println(Hex.toHexString(tag));
```

### HMAC-SM3（JCA）

```java
Security.addProvider(new XaProvider());
Mac mac = Mac.getInstance("HmacSM3", "XaProvider");
SecretKeySpec keySpec = new SecretKeySpec("1234567890abcdef".getBytes(), "HmacSM3");
mac.init(keySpec);
mac.update(msg.getBytes());
byte[] tag = mac.doFinal();
System.out.println(Hex.toHexString(tag));
```

如果源码目录下直接运行 JCA `Mac` 遇到 `JCE cannot authenticate the provider`，优先使用上面的直接调用方式；这是 JCE Provider 认证限制，不影响 `SM3HMac` 直接 API。

### 随机数生成（通过 SM3 实现）

```java
byte[] random = Random.RandomBySM3(16);
System.out.println(Hex.toHexString(random));
```

### SM4 加解密

```java
SecureRandom secureRandom = new SecureRandom();
byte[] key = new byte[16];
byte[] iv = new byte[16];
secureRandom.nextBytes(key);
secureRandom.nextBytes(iv);
// ECB 模式
SM4Cipher sm4CipherECB = new SM4Cipher(ModeEnum.ECB);
byte[] ecbmi = sm4CipherECB.cipherEncrypt(key, msg.getBytes(), null);
byte[] ecbming = sm4CipherECB.cipherDecrypt(key, ecbmi, iv);
System.out.println("ECB明文：" + new String(ecbming));
// CBC 模式
SM4Cipher sm4CipherCBC = new SM4Cipher(ModeEnum.CBC);
byte[] cbcmi = sm4CipherCBC.cipherEncrypt(key, msg.getBytes(), iv);
byte[] cbcming = sm4CipherCBC.cipherDecrypt(key, cbcmi, iv);
System.out.println("CBC明文：" + new String(cbcming));
// CTR 模式
SM4Cipher sm4CipherCTR = new SM4Cipher(ModeEnum.CTR);
byte[] ctrmi = sm4CipherCTR.cipherEncrypt(key, msg.getBytes(), iv);
byte[] ctrming = sm4CipherCTR.cipherDecrypt(key, ctrmi, iv);
System.out.println("CTR明文：" + new String(ctrming));
// GCM 模式
SM4Cipher sm4_gcm = new SM4Cipher();
AEADExecution aeadExecution = sm4_gcm.cipherEncryptGCM(key, msg, new byte[12], "aad".getBytes(), 16);
System.out.println("GCM密文：" + Hex.toHexString(aeadExecution.getCipherText()));
System.out.println("GCMtag：" + Hex.toHexString(aeadExecution.getTag()));
byte[] ming_gcm = sm4_gcm.cipherDecryptGCM(key, aeadExecution.getCipherText(), new byte[12], "aad".getBytes(), aeadExecution.getTag());
System.out.println("GCM明文：" + new String(ming_gcm));
```

#### 性能相关配置

- **内部多线程**：ECB、CTR、CBC 解密、GCM-GCTR 等可并行模式在处理 **≥256 个分组（4 KB）** 的数据时会自动使用内部线程池加速；分组数较小时自动退化为单线程，避免线程调度开销。
- **关闭内部并行**：业务层若希望自己管理线程池，或运行在线程敏感的容器/Serverless 环境，可添加 JVM 参数 `-Dgm.sm4.parallel=false`，强制所有模式走单线程路径；关闭后内部线程池不会被创建。

### 模拟 TLS 握手进行密钥协商（Netty）

#### 服务端（默认使用 4433 端口）

```java
NettyTlsServer nettyTlsServer = new NettyTlsServer(4432);
new Thread(() -> {
    try {
        nettyTlsServer.start();
    } catch (Exception e) {
        e.printStackTrace();
    }
}).start();
new Thread(() -> {
    while (true) {
        System.out.println("server sleep");
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        if (nettyTlsServer.getRandom() != null) {
            System.out.println("netty server random：" + Hex.toHexString(nettyTlsServer.getRandom()));
            break;
        }
    }
    nettyTlsServer.shutdown();
}).start();
```

#### 客户端

```java
NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost", 4432);
new Thread(() -> {
    try {
        nettyTlsClient.start();
    } catch (Exception e) {
        throw new RuntimeException(e);
    }
}).start();
new Thread(() -> {
    while (true) {
        try {
            Thread.sleep(1000);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        if (nettyTlsClient.getRandom() != null) {
            System.out.println("netty client random：" + Hex.toHexString(nettyTlsClient.getRandom()));
            break;
        }
    }
    nettyTlsClient.shutdown();
    System.out.println(i.incrementAndGet() + "---------TLS握手测试通过（NETTY）---------");
}).start();
```

#### 服务端（使用私有服务端证书以及自定义端口）

```java
NettyTlsServer nettyTlsServer = new NettyTlsServer(4432, cert, pri);
```

#### 客户端

```java
NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost", 4432);
```

#### 客户端（使用固定 sessionId 可以获取固定的 key，在 Server 中缓存，存在被窃听风险，自行选择是否开启，默认关闭）

```java
NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost", 4432, true, Hex.decode("1234567812345678"));
```

### 模拟 TLS 握手进行密钥协商（Socket）

#### 服务端（默认使用 4433 端口）

```java
TlsServer tlsServer = new TlsServer();
tlsServer.setDEBUG(true);
tlsServer.start();
System.out.println("握手完成！");
System.out.println("服务端随机数：" + Hex.toHexString(tlsServer.getRandom()));
```

#### 客户端

```java
TlsClient tlsClient = new TlsClient("127.0.0.1");
tlsClient.setDEBUG(true);
tlsClient.start();
System.out.println("握手完成！");
System.out.println("客户端随机数：" + Hex.toHexString(tlsClient.getRandom()));
```

#### 服务端（使用私有服务端证书以及自定义端口）

```java
TlsServer tlsServer = new TlsServer(serverCert, serverCertPriKey, 447);
tlsServer.setDEBUG(true);
tlsServer.start();
System.out.println("握手完成！");
System.out.println("服务端随机数：" + Hex.toHexString(tlsServer.getRandom()));
```

#### 客户端

```java
TlsClient tlsClient = new TlsClient("127.0.0.1", 447);
tlsClient.setDEBUG(true);
tlsClient.start();
System.out.println("握手完成！");
System.out.println("客户端随机数：" + Hex.toHexString(tlsClient.getRandom()));
```

## 更新日志

[查看完整更新日志](CHANGELOG.md)
