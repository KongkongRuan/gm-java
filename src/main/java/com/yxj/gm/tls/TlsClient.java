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
import java.nio.charset.StandardCharsets;
import java.security.*;

public class TlsClient {
    private int tlsPort = 4433;
    private byte[] random;
    private String serverIp = "";
    private boolean DEBUG =false;

    private boolean FirstPrint = true;
    public TlsClient(String serverIp)  {
        this.serverIp = serverIp;
        Security.addProvider(new XaProvider());

    }
    public TlsClient(String serverIp,int serverPort)  {
        Security.addProvider(new XaProvider());
        this.serverIp = serverIp;
        this.tlsPort = serverPort;
    }
    private final byte[] clientHead = "gm-java-tls-client".getBytes(StandardCharsets.UTF_8);
    public void start(){
        if(FirstPrint)System.out.println("gm-java client:clientStart");
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
//            writeAddHead(outputStream,derOctetString.getEncoded());
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
//            writeAddHead(outputStream,new DEROctetString(clientKeyExchangeBytes).getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if(DEBUG) System.out.println("client:clientKeyExchange发送完毕");
        /**
         * sPub* cPri = G* sPri * cPri
         */
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
    private void writeAddHead(OutputStream outputStream,byte[] bytes) throws IOException {
        byte[] bytes1 = DataConvertUtil.byteArrAdd(clientHead, bytes);
        outputStream.write(bytes1);

    }
    public void setDEBUG(boolean DEBUG) {
        this.DEBUG = DEBUG;
    }

    public void setFirstPrint(boolean firstPrint) {
        FirstPrint = firstPrint;
    }

    public byte[] getRandom() {
        return random;
    }


    public static void main(String[] args) throws IOException {
         String clientHead = "gm-java-tls-client";
        System.out.println(clientHead.length());
    }
}
