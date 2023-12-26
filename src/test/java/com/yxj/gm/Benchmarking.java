package com.yxj.gm;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.cert.CertParseVo;
import com.yxj.gm.cert.SM2CertGenerator;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.random.Random;
import com.yxj.gm.tls.TlsClient;
import com.yxj.gm.tls.TlsServer;
import com.yxj.gm.tls.netty.NettyTlsClient;
import com.yxj.gm.tls.netty.NettyTlsServer;
import com.yxj.gm.util.CertResolver;
import com.yxj.gm.util.FileUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.security.KeyPair;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicInteger;

public class Benchmarking {
    public static void main(String[] args) throws ExecutionException, InterruptedException {
        String msg = "gm-java-1.0";
        AtomicInteger i= new AtomicInteger();
        System.out.println("---------SM2密钥对生成开始---------");
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        System.out.println(Hex.toHexString(keyPair.getPublic().getEncoded()));
        System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));
        System.out.println(i.incrementAndGet() +"---------SM2密钥对生成通过---------");
        System.out.println("---------SM2加解密开始---------");
        SM2Cipher sm2Cipher = new SM2Cipher();
        byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), keyPair.getPublic().getEncoded());
        byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, keyPair.getPrivate().getEncoded());
        System.out.println("SM2解密结果："+new String(ming));
        System.out.println(i.incrementAndGet() +"---------SM2加解密通过---------");
        System.out.println("---------SM2签名验签开始---------");
        SM2Signature signature = new SM2Signature();
        byte[] signature1 = signature.signature(msg.getBytes(), null, keyPair.getPrivate().getEncoded());
        boolean b = signature.verify(msg.getBytes(), null, signature1, keyPair.getPublic().getEncoded());
        System.out.println("SM2验签结果："+b);
        System.out.println(i.incrementAndGet() +"---------SM2签名验签通过---------");
        System.out.println("---------SM2证书制作开始---------");
        String certPathStr = "D:/certtest/";
        String property = System.getProperty("os.name");
        if(property.toLowerCase().contains("linux")){
            certPathStr = "/home/certtest/";
        }
        File certFolder = new File(certPathStr);
        if(!certFolder.exists()){
            certFolder.mkdirs();
        }
        //ca证书密钥
        KeyPair caKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        //终端证书密钥
        KeyPair equipKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();

        SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
        String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
        String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";

        byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded());
        try {
            FileUtils.writeFile(certPathStr+"/java-ca.cer",rootCert);
            FileUtils.writeFile(certPathStr+"/java-ca.pri",caKeyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, caKeyPair.getPrivate().getEncoded(), equipKeyPair.getPublic().getEncoded());
        try {
            FileUtils.writeFile(certPathStr+"/java-ownerCert.cer",ownerCert);
            FileUtils.writeFile(certPathStr+"/java-ownerCert.pri",equipKeyPair.getPrivate().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        System.out.println("证书存放路径："+certPathStr);
        System.out.println(i.incrementAndGet() +"---------SM2证书制作通过---------");
        System.out.println("---------SM2证书解析开始---------");
        CertParseVo certParseVo = CertResolver.parseCert(rootCert);
        System.out.println("rootCert解析完成");
        System.out.println(certParseVo);
        System.out.println(i.incrementAndGet() +"---------SM2证书解析通过---------");
        System.out.println("---------SM3摘要计算---------");
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(msg.getBytes());
        byte[] md = sm3Digest.doFinal();
        byte[] md2 = sm3Digest.doFinal(msg.getBytes());
        sm3Digest.update("gm-java-".getBytes());
        sm3Digest.update("1.0".getBytes());
        byte[] md3 = sm3Digest.doFinal();
        System.out.println("update:        "+Hex.toHexString(md));
        System.out.println("直接doFinal:   "+Hex.toHexString(md2));
        System.out.println("多次分开update: "+Hex.toHexString(md3));
        System.out.println(i.incrementAndGet() +"---------SM3摘要计算通过---------");

        System.out.println("---------随机数生成开始---------");
        byte[] random = Random.RandomBySM3(16);
        System.out.println(Hex.toHexString(random));
        System.out.println(i.incrementAndGet() +"---------随机数生成通过---------");

        System.out.println("---------SM4加解密开始---------");
        byte[] key = Random.RandomBySM3(16);
        byte[] iv = Random.RandomBySM3(16);
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
        AEADExecution aeadExecution = sm4_gcm.cipherEncryptGCM(key, msg.getBytes(), new byte[12], "aad".getBytes(), 16);
        System.out.println("GCM密文："+Hex.toHexString(aeadExecution.getCipherText()));
        System.out.println("GCMtag："+Hex.toHexString(aeadExecution.getTag()));
        byte[] ming_gcm = sm4_gcm.cipherDecryptGCM(key, aeadExecution.getCipherText(), new byte[12], "aad".getBytes(), aeadExecution.getTag());
        System.out.println("GCM明文："+new String(ming_gcm));
        System.out.println(i.incrementAndGet() +"---------SM4加解密通过---------");

        System.out.println("---------TLS握手测试开始（SOCKET）---------");
        TlsServerCallable tlsServerCallable = new TlsServerCallable();
        FutureTask serverFutureTask = new FutureTask<>(tlsServerCallable);
        new Thread(serverFutureTask).start();
        TlsClientCallable tlsClientCallable = new TlsClientCallable();
        FutureTask clientFutureTask = new FutureTask<>(tlsClientCallable);
        new Thread(clientFutureTask).start();
        String serverResultRandom = (String)serverFutureTask.get();
        System.out.println("serverResultRandom:"+serverResultRandom);
        String clientResultRandom = (String)clientFutureTask.get();
        System.out.println("clientResultRandom:"+clientResultRandom);
        System.out.println(i.incrementAndGet() +"---------TLS握手测试通过（SOCKET）---------");

        System.out.println("---------TLS握手测试开始（NETTY）---------");
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


    }
     static class TlsServerCallable implements Callable{

        TlsServerCallable(){};
        int port=4433;
        TlsServerCallable( int port){
            this.port = port;
        }
        @Override
        public Object call() throws Exception {
            TlsServer tlsServer = new TlsServer(port);
            tlsServer.start();
            return Hex.toHexString(tlsServer.getRandom());
        }
    }
    static class TlsClientCallable implements Callable{
        TlsClientCallable(){};
        String ip;
        int port;
        TlsClientCallable(String ip, int port){
            this.ip = ip;
            this.port = port;
        }
        TlsClientCallable(String ip){
            this.ip = ip;
        }
        @Override
        public Object call() throws Exception {
            if(ip==null){
                ip="127.0.0.1";
            }
            TlsClient tlsClient = new TlsClient(ip);
            tlsClient.start();
            return Hex.toHexString(tlsClient.getRandom());
        }
    }
}
