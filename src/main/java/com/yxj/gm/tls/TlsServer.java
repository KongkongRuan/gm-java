package com.yxj.gm.tls;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.random.Random;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.FileUtils;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.TLSUtil;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class TlsServer {
    int tlsPort = 443;
    byte[] random;
    public TlsServer() throws IOException {
        Security.addProvider(new XaProvider());
        byte[] cert = FileUtils.readFileToByteArray(new File("D:\\certtest\\ca\\java-caCert-add0.cer"));
        byte[] priKey = FileUtils.readFileToByteArray(new File("D:\\certtest\\ca\\priKey.key"));

        System.out.println("serverStart");
        ServerSocket serverSocket=new ServerSocket(tlsPort);
        Socket socket = serverSocket.accept();
        // 建立好连接后，从socket中获取输入流，并建立缓冲区进行读取
        InputStream inputStream = socket.getInputStream();

        byte[] content = ASN1Util.GetContent(inputStream);

        ClientHello clientHello = JSON.parseObject(new String(content), ClientHello.class);

        System.out.println("server:serverHello"+clientHello);
        //todo 生成serverHello(选择适当的版本及算法)
        ServerHello serverHello = new ServerHello();
        serverHello.setVersion(clientHello.getVersion());
        byte[] randomS = Random.RandomBySM3(32);
        serverHello.setRandomS(randomS);
        serverHello.setSessionId(null);
        serverHello.setCipherSuites(clientHello.getCipherSuites());
        serverHello.setCompressionMethods(null);
        DEROctetString derOctetString = new DEROctetString(JSON.toJSONString(serverHello).getBytes());
        socket.getOutputStream().write(derOctetString.getEncoded());
        System.out.println("server:serverHello发送完毕");
        byte[] encoded = new DEROctetString(cert).getEncoded();
        socket.getOutputStream().write(encoded);
        System.out.println("server:serverCert发送完毕");
        //ECDHE（E为ephemeral（临时性的）
        KeyPair serverKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(serverKeyPairTemp.getPublic().getEncoded());
        byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();

        byte[] signature = new SM2Signature().signature(serverKeyExchangeBytes, null, priKey);
        ServerKeyExchangeECDHE serverKeyExchangeECDHE = new ServerKeyExchangeECDHE(serverKeyExchange, signature);
        byte[] serverKeyExchangeECDHEBytes = JSON.toJSONString(serverKeyExchangeECDHE).getBytes();

        socket.getOutputStream().write(new DEROctetString(serverKeyExchangeECDHEBytes).getEncoded());
        System.out.println("server:serverKeyExchangeECDHEBytes发送完毕");
        socket.getOutputStream().write(new DEROctetString("ServerHelloDone".getBytes()).getEncoded());
        System.out.println("server:ServerHelloDone发送完毕");
        byte[] clientKeyExchangeBytes = ASN1Util.GetContent(inputStream);
        ClientKeyExchange clientKeyExchange = JSON.parseObject(new String(clientKeyExchangeBytes), ClientKeyExchange.class);
        System.out.println("server:clientKeyExchange:"+clientKeyExchange);
        byte[] PreMaster = SM2Util.KeyExchange(clientKeyExchange.getClientPubKey(), serverKeyPairTemp.getPrivate().getEncoded(), 16);
        System.out.println("server:PreMaster:"+Hex.toHexString(PreMaster));

        MessageDigest xaMd = null;
        try {
            xaMd = MessageDigest.getInstance("SM3", "XaProvider");
            random=TLSUtil.prf(xaMd,PreMaster,"master secret".getBytes(), DataConvertUtil.byteArrAdd(clientHello.getRandomC(),randomS),16);

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        inputStream.close();
        socket.close();
        serverSocket.close();
    }

    public static void main(String[] args) throws IOException {
        TlsServer tlsServer = new TlsServer();
        System.out.println("握手完成！");
        System.out.println("服务端随机数："+Hex.toHexString(tlsServer.random));
    }
}
