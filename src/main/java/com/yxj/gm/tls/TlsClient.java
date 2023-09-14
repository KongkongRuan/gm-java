package com.yxj.gm.tls;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.cert.CertParseVo;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.random.Random;
import com.yxj.gm.util.CertResolver;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.TLSUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.*;

public class TlsClient {
    private int tlsPort = 443;
    private byte[] random;
    private String serverIp = "";
    private boolean DEBUG =false;
    public TlsClient(String serverIp) throws IOException {
        Security.addProvider(new XaProvider());

    }
    public TlsClient(String serverIp,int serverPort) throws IOException {
        Security.addProvider(new XaProvider());
        this.serverIp = serverIp;
        this.tlsPort = serverPort;
    }
    public void start(){
        System.out.println("gm-java client:clientStart");
        Socket socket = null;
        try {
            socket = new Socket(serverIp, tlsPort);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        ClientHello clientHello = new ClientHello();
        clientHello.setVersion("v1");
        byte[] randomC = Random.RandomBySM3(32);
        clientHello.setRandomC(randomC);
        clientHello.setSessionId(null);
        CipherSuites cipherSuites = new CipherSuites("SM4", "SM2", "SM3");
        clientHello.setCipherSuites(cipherSuites);
        clientHello.setCompressionMethods(null);
        OutputStream outputStream = null;
        try {
            outputStream = socket.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        DEROctetString derOctetString = new DEROctetString(JSON.toJSONString(clientHello).getBytes());
        try {
            outputStream.write(derOctetString.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("client:clientHello发送完毕");


        InputStream inputStream = null;
        try {
            inputStream = socket.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] content = ASN1Util.GetContent(inputStream);
        ServerHello serverHello = JSON.parseObject(new String(content), ServerHello.class);
        if(DEBUG) System.out.println("client:serverHello"+serverHello);

        byte[] serverCert = ASN1Util.GetContent(inputStream);

        if(DEBUG) System.out.println("client:serverCert"+new String(serverCert));
        byte[] serverKeyExchangeECDHEBytes = ASN1Util.GetContent(inputStream);
        //todo verify certificate
        ServerKeyExchangeECDHE serverKeyExchangeECDHE = JSON.parseObject(new String(serverKeyExchangeECDHEBytes), ServerKeyExchangeECDHE.class);
        if(DEBUG) System.out.println("client:serverKeyExchangeECDHE"+serverKeyExchangeECDHE);

        byte[] signature = serverKeyExchangeECDHE.getSignature();
        ServerKeyExchange serverKeyExchange = serverKeyExchangeECDHE.getServerKeyExchange();
        byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();
        CertParseVo ServerCertParseVo = CertResolver.parseCert(serverCert);
        boolean verify = new SM2Signature().verify(serverKeyExchangeBytes, null, signature, ServerCertParseVo.getPubKey());
        if(!verify){
            throw new RuntimeException("serverKeyExchangeECDHE verify failed");
        }
        byte[] serverHelloDoneBytes = ASN1Util.GetContent(inputStream);
        if(DEBUG) System.out.println("client:serverHelloDone"+new String(serverHelloDoneBytes));
        //ECDHE（E为ephemeral（临时性的）
        KeyPair clientKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(clientKeyPairTemp.getPublic().getEncoded());
        byte[] clientKeyExchangeBytes = JSON.toJSONString(clientKeyExchange).getBytes();
        try {
            outputStream.write(new DEROctetString(clientKeyExchangeBytes).getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("client:clientKeyExchange发送完毕");
        byte[] PreMaster = SM2Util.KeyExchange(serverKeyExchange.getServerPubKey(), clientKeyPairTemp.getPrivate().getEncoded(), 16);
        if(DEBUG) System.out.println("client:PreMaster"+Hex.toHexString(PreMaster));
        MessageDigest xaMd = null;
        try {
            xaMd = MessageDigest.getInstance("SM3", "XaProvider");
            random=TLSUtil.prf(xaMd,PreMaster,"master secret".getBytes(), DataConvertUtil.byteArrAdd(randomC,serverHello.getRandomS()),16);

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("client:结束");
        try {
            inputStream.close();
            outputStream.close();
            socket.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
    public void setDEBUG(boolean DEBUG) {
        this.DEBUG = DEBUG;
    }
    public byte[] getRandom() {
        return random;
    }


    public static void main(String[] args) throws IOException {
        TlsClient tlsClient = new TlsClient("127.0.0.1",447);
        tlsClient.setDEBUG(true);
        tlsClient.start();
        System.out.println("握手完成！");
        System.out.println("客户端随机数："+Hex.toHexString(tlsClient.getRandom()));
    }
}
