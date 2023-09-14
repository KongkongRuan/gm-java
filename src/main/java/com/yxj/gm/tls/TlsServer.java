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
    private int tlsPort = 443;
    private byte[] random;

    private byte[] serverCert;
    private byte[] serverPriKey;
    private boolean DEBUG =false;
    public TlsServer() throws IOException {
        Security.addProvider(new XaProvider());
        this.serverCert = ("-----BEGIN CERTIFICATE-----\n" +
                "MIIBxjCCAWygAwIBAgIIP/aSt00fQz8wCgYIKoEcz1UBg3UwZjERMA8GA1UEAwwI\n" +
                "RGlnaWNlcnQxETAPBgNVBAsMCERpZ2ljZXJ0MREwDwYDVQQKDAhEaWdpY2VydDEP\n" +
                "MA0GA1UEBwwGTGludG9uMQ0wCwYDVQQIDARVdGFoMQswCQYDVQQGEwJVUzAeFw0y\n" +
                "MzAzMjIwNjUzNDlaFw0zMzAzMTkwNjUzNDlaMFgxDzANBgNVBAMMBlRFU1RDQTEL\n" +
                "MAkGA1UECwwCREQxCzAJBgNVBAoMAkREMQ8wDQYDVQQHDAZMaW50b24xDTALBgNV\n" +
                "BAgMBFV0YWgxCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n" +
                "RAEMvj4XhVoAd82+gsi9y8WsF2M6k8Q5JVWkT2yepKlfU5OlSqtXDJUsDKv2H+Yl\n" +
                "Ueyw0/wmwp/0+crz/scoaqMSMBAwDgYDVR0PAQH/BAQDAgKEMAoGCCqBHM9VAYN1\n" +
                "A0gAMEUCIQCA6wJ+LI9JpEuixkv08hTsRfp7EiS3YEMC2wchH0QFIAIgQgiaagM3\n" +
                "L5rTNfhPCxVTI6GwweppYkIQ3vyp2KPYP0A=\n" +
                "-----END CERTIFICATE-----").getBytes();
        this.serverPriKey = Hex.decode("47aaf29d5dde9956f0784a1f17778eede518a03171b36ff8992f226929c48504");
    }

    public TlsServer(int port) throws IOException {
        Security.addProvider(new XaProvider());
        this.serverCert = ("-----BEGIN CERTIFICATE-----\n" +
                "MIIBxjCCAWygAwIBAgIIP/aSt00fQz8wCgYIKoEcz1UBg3UwZjERMA8GA1UEAwwI\n" +
                "RGlnaWNlcnQxETAPBgNVBAsMCERpZ2ljZXJ0MREwDwYDVQQKDAhEaWdpY2VydDEP\n" +
                "MA0GA1UEBwwGTGludG9uMQ0wCwYDVQQIDARVdGFoMQswCQYDVQQGEwJVUzAeFw0y\n" +
                "MzAzMjIwNjUzNDlaFw0zMzAzMTkwNjUzNDlaMFgxDzANBgNVBAMMBlRFU1RDQTEL\n" +
                "MAkGA1UECwwCREQxCzAJBgNVBAoMAkREMQ8wDQYDVQQHDAZMaW50b24xDTALBgNV\n" +
                "BAgMBFV0YWgxCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n" +
                "RAEMvj4XhVoAd82+gsi9y8WsF2M6k8Q5JVWkT2yepKlfU5OlSqtXDJUsDKv2H+Yl\n" +
                "Ueyw0/wmwp/0+crz/scoaqMSMBAwDgYDVR0PAQH/BAQDAgKEMAoGCCqBHM9VAYN1\n" +
                "A0gAMEUCIQCA6wJ+LI9JpEuixkv08hTsRfp7EiS3YEMC2wchH0QFIAIgQgiaagM3\n" +
                "L5rTNfhPCxVTI6GwweppYkIQ3vyp2KPYP0A=\n" +
                "-----END CERTIFICATE-----").getBytes();
        this.serverPriKey = Hex.decode("47aaf29d5dde9956f0784a1f17778eede518a03171b36ff8992f226929c48504");
        this.tlsPort = port;
    }

    public byte[] getRandom() {
        return random;
    }

    public TlsServer(byte[] serverCert, byte[] serverPriKey, int port){
        Security.addProvider(new XaProvider());
        this.serverCert = serverCert;
        this.serverPriKey = serverPriKey;
        this.tlsPort = port;
    }
    public void start(){
        System.out.println("gm-java server:server start");
        ServerSocket serverSocket= null;
        try {
            serverSocket = new ServerSocket(tlsPort);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 建立好连接后，从socket中获取输入流，并建立缓冲区进行读取
        InputStream inputStream = null;
        try {
            inputStream = socket.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] content = ASN1Util.GetContent(inputStream);

        ClientHello clientHello = JSON.parseObject(new String(content), ClientHello.class);

        if(DEBUG) System.out.println("server:serverHello"+clientHello);
        //todo 生成serverHello(选择适当的版本及算法)
        ServerHello serverHello = new ServerHello();
        serverHello.setVersion(clientHello.getVersion());
        byte[] randomS = Random.RandomBySM3(32);
        serverHello.setRandomS(randomS);
        serverHello.setSessionId(null);
        serverHello.setCipherSuites(clientHello.getCipherSuites());
        serverHello.setCompressionMethods(null);
        DEROctetString derOctetString = new DEROctetString(JSON.toJSONString(serverHello).getBytes());
        try {
            socket.getOutputStream().write(derOctetString.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("server:serverHello发送完毕");
        byte[] encoded = new byte[0];
        try {
            encoded = new DEROctetString(serverCert).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            socket.getOutputStream().write(encoded);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("server:serverCert发送完毕");
        //ECDHE（E为ephemeral（临时性的）
        KeyPair serverKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(serverKeyPairTemp.getPublic().getEncoded());
        byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();

        byte[] signature = new SM2Signature().signature(serverKeyExchangeBytes, null, serverPriKey);
        ServerKeyExchangeECDHE serverKeyExchangeECDHE = new ServerKeyExchangeECDHE(serverKeyExchange, signature);
        byte[] serverKeyExchangeECDHEBytes = JSON.toJSONString(serverKeyExchangeECDHE).getBytes();

        try {
            socket.getOutputStream().write(new DEROctetString(serverKeyExchangeECDHEBytes).getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("server:serverKeyExchangeECDHEBytes发送完毕");
        try {
            socket.getOutputStream().write(new DEROctetString("ServerHelloDone".getBytes()).getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("server:ServerHelloDone发送完毕");
        byte[] clientKeyExchangeBytes = ASN1Util.GetContent(inputStream);
        ClientKeyExchange clientKeyExchange = JSON.parseObject(new String(clientKeyExchangeBytes), ClientKeyExchange.class);
        if(DEBUG) System.out.println("server:clientKeyExchange:"+clientKeyExchange);
        byte[] PreMaster = SM2Util.KeyExchange(clientKeyExchange.getClientPubKey(), serverKeyPairTemp.getPrivate().getEncoded(), 16);
        if(DEBUG) System.out.println("server:PreMaster:"+Hex.toHexString(PreMaster));

        MessageDigest xaMd = null;
        try {
            xaMd = MessageDigest.getInstance("SM3", "XaProvider");
            random=TLSUtil.prf(xaMd,PreMaster,"master secret".getBytes(), DataConvertUtil.byteArrAdd(clientHello.getRandomC(),randomS),16);

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        try {
            inputStream.close();
            socket.close();
            serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setDEBUG(boolean DEBUG) {
        this.DEBUG = DEBUG;
    }

    public static void main(String[] args) throws IOException {
        byte[] cert = FileUtils.readFileToByteArray(new File("D:\\certtest\\ca\\java-caCert-add0.cer"));
        byte[] priKey = FileUtils.readFileToByteArray(new File("D:\\certtest\\ca\\priKey.key"));

        TlsServer tlsServer = new TlsServer(cert,priKey,447);
        tlsServer.setDEBUG(true);
        tlsServer.start();
        System.out.println("握手完成！");
        System.out.println("服务端随机数："+Hex.toHexString(tlsServer.getRandom()));




    }
}
