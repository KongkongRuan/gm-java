# GM-JAVA
GM-JAVA是一套用JAVA开发的支持国密算法的加解密工具包。

## 项目引入

 - pom引入（已上传中央仓库）
```xml
<dependency>
    <groupId>io.github.KongkongRuan</groupId>
    <artifactId>gm-java</artifactId>
    <version>2.2.1</version>
</dependency>
```
 - 下载源码编译之后引入或者直接下载gm-java-2.2.1.jar引入
### 2.2.1更新内容
#### SM3性能优化了20%

### 2.2.0更新内容
#### SM2底层重构
#### 优化后的结果(BC（bcprov-jdk18on 1.76版本）)
- 密钥生成比BC快 1.63x
- 加密比BC快 2.24x
- 解密比BC快 3.14x
- 签名比BC快 2.80x
- 验签比BC快 1.54x
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


### 2.1.0更新内容
使用opus全面优化了密钥生成以及加解密运算速度（虽然在AI时代可能不太用得上工具类了）
- 1.SM4以及SM3性能与BC接近（SM4CTR使用了多线程加速，速度比BC（bcprov-jdk18on 1.76版本）快三倍）
- 2.SM2略慢于BC，后续计划对 SM2 素数做特化模归约和以及增大更大的预计算窗口
## 主要功能
### 密码算法

 - 对称密码算法 SM4（ECB/CBC/CTR/GCM）
 - 非对称密码算法 SM2（加解密/签名验签）
 - Hash算法 SM3
 - 基于SM3实现的随机数生成器（多线程加速）
### 证书
 - 证书解析以及证书SHA1指纹计算
 - SM2证书生成
### 密钥协商
- 模拟TLS握手协议，通信双方协商会话密钥

## 整体功能基准测试
### test目录下com.yxj.gm包Benchmarking类

## 快速使用
```java
        String msg = "gm-java-1.0";
```
### SM2密钥对生成
```java
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
```
### SM2加解密
```java 
        SM2Cipher sm2Cipher = new SM2Cipher();
        byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), keyPair.getPublic().getEncoded());
        byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, keyPair.getPrivate().getEncoded());
        System.out.println("SM2解密结果："+new String(ming));
```
### SM2签名验签
```java
        SM2Signature signature = new SM2Signature();
        byte[] signature1 = signature.signature(msg.getBytes(), null, keyPair.getPrivate().getEncoded());
        boolean b = signature.verify(msg.getBytes(), null, signature1, keyPair.getPublic().getEncoded());
        System.out.println("SM2验签结果："+b);
```
### 制作SM2证书
```java
        //ca证书密钥
        KeyPair caKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        //终端证书密钥
        KeyPair equipKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();

        SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
        String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
        String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";
        CertTest certTest = new CertTest();
        byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ca-3.cer",rootCert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, caKeyPair.getPrivate().getEncoded(), equipKeyPair.getPublic().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ownerCert-3.cer",ownerCert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //使用HSM签名制作SM2证书
        int hsmSigPriIndex=0;
        rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(),true,hsmSigPriIndex);
```
### SM3摘要计算
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
### 随机数生成（通过SM3实现）
```java
        byte[] random = Random.RandomBySM3(16);
        System.out.println(Hex.toHexString(random));
```
### SM4加解密
```java
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(iv);
        //ECB模式
        SM4Cipher sm4CipherECB = new SM4Cipher(ModeEnum.ECB);
        byte[] ecbmi = sm4CipherECB.cipherEncrypt(key, msg.getBytes(), null);
        byte[] ecbming = sm4CipherECB.cipherDecrypt(key, ecbmi, iv);
        System.out.println("ECB明文："+new String(ecbming));
        //CBC模式
        SM4Cipher sm4CipherCBC = new SM4Cipher(ModeEnum.CBC);
        byte[] cbcmi = sm4CipherCBC.cipherEncrypt(key, msg.getBytes(), iv);
        byte[] cbcming = sm4CipherCBC.cipherDecrypt(key, cbcmi, iv);
        System.out.println("CBC明文："+new String(cbcming));
        //CTR模式
        SM4Cipher sm4CipherCTR = new SM4Cipher(ModeEnum.CTR);
        byte[] ctrmi = sm4CipherCTR.cipherEncrypt(key, msg.getBytes(), iv);
        byte[] ctrming = sm4CipherCTR.cipherDecrypt(key, ctrmi, iv);
        System.out.println("CTR明文："+new String(ctrming));
        //GCM模式
        SM4Cipher sm4_gcm = new SM4Cipher();
        AEADExecution aeadExecution = sm4_gcm.cipherEncryptGCM(key, msg, new byte[12], "aad".getBytes(), 16);
        System.out.println("GCM密文："+Hex.toHexString(aeadExecution.getCipherText()));
        System.out.println("GCMtag："+Hex.toHexString(aeadExecution.getTag()));
        byte[] ming_gcm = sm4_gcm.cipherDecryptGCM(key, aeadExecution.getCipherText(), new byte[12], "aad".getBytes(), aeadExecution.getTag());
        System.out.println("GCM明文："+new String(ming_gcm));
```

### 模拟TLS握手进行密钥协商（Netty）
#### 服务端（默认使用4433端口）
```java
        NettyTlsServer nettyTlsServer = new NettyTlsServer(4432);
        new Thread(()->{
            try {
                nettyTlsServer.start();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
        new Thread(()->{
            while (true){
                System.out.println("server sleep");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                if(nettyTlsServer.getRandom()!=null){
                    System.out.println("netty server random："+Hex.toHexString(nettyTlsServer.getRandom()));
                    break;
                }
            }
            nettyTlsServer.shutdown();
        }).start();
```
#### 客户端
```java
        NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost", 4432);
        new Thread(()->{
            try {
                nettyTlsClient.start();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).start();
        new Thread(()->{
            while (true){
                try {
                    Thread.sleep(1000);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                if(nettyTlsClient.getRandom()!=null){
                    System.out.println("netty client random："+Hex.toHexString(nettyTlsClient.getRandom()));
                    break;
                }
            }
            nettyTlsClient.shutdown();
            System.out.println(i.incrementAndGet() +"---------TLS握手测试通过（NETTY）---------");

        }).start();
```

#### 服务端（使用私有服务端证书以及自定义端口）
```java
NettyTlsServer nettyTlsServer = new NettyTlsServer(4432,cert,pri);
```
#### 客户端
```java
        NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost",4432);
```
#### 客户端（使用固定sessionId可以获取固定的key，在Server中缓存，存在被窃听风险,自行选择是否开启，默认关闭）
```java
        NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost",4432,true,Hex.decode("1234567812345678"));
```

### 模拟TLS握手进行密钥协商（Socket）
#### 服务端（默认使用4433端口）
```java
        TlsServer tlsServer = new TlsServer();
        tlsServer.setDEBUG(true);
        tlsServer.start();
        System.out.println("握手完成！");
        System.out.println("服务端随机数："+Hex.toHexString(tlsServer.getRandom()));
```
#### 客户端
```java
        TlsClient tlsClient = new TlsClient("127.0.0.1");
        tlsClient.setDEBUG(true);
        tlsClient.start();
        System.out.println("握手完成！");
        System.out.println("客户端随机数："+Hex.toHexString(tlsClient.getRandom()));
```

#### 服务端（使用私有服务端证书以及自定义端口）
```java
        TlsServer tlsServer = new TlsServer(serverCert,serverCertPriKey,447);
        tlsServer.setDEBUG(true);
        tlsServer.start();
        System.out.println("握手完成！");
        System.out.println("服务端随机数："+Hex.toHexString(tlsServer.getRandom()));
```
#### 客户端
```java
        TlsClient tlsClient = new TlsClient("127.0.0.1",447);
        tlsClient.setDEBUG(true);
        tlsClient.start();
        System.out.println("握手完成！");
        System.out.println("客户端随机数："+Hex.toHexString(tlsClient.getRandom()));
```
