# GM-JAVA
GM-JAVA是一套用JAVA开发的支持国密算法的加解密工具包。

## 项目引入

 - 下载源码编译之后引入或者直接下载gm-java-1.0.jar引入
 - ~~pom引入~~ （未上传中央仓库）
 

```xml
<dependency>
    <groupId>io.github.KongkongRuan</groupId>
    <artifactId>gm-java</artifactId>
    <version>1.0</version>
</dependency>
```
## 主要功能
### 密码算法

 - 对称密码算法 SM4（ECB/CBC/CTR）
 - 非对称密码算法 SM2（加解密/签名验签）
 - Hash算法 SM3
### 证书
 - 证书解析以及证书SHA1指纹计算
 - SM2证书生成（未实现）

