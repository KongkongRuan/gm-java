package com.yxj.gm.tls.netty.handler.server;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.random.Random;
import com.yxj.gm.tls.*;
import com.yxj.gm.tls.netty.NettyConstant;
import com.yxj.gm.tls.netty.TlsMessage;
import com.yxj.gm.tls.netty.handler.DataRecive;
import com.yxj.gm.tls.netty.handler.enums.TlsMessageType;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.TLSUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.CharsetUtil;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

@ChannelHandler.Sharable
public class NettyTlsServerHandler extends SimpleChannelInboundHandler<ByteBuf> {
    static {
        Security.addProvider(new XaProvider());
    }
    private Map<String,byte[]> currentKeyMap = new HashMap<>();
    DataRecive dataRecive = new DataRecive();
    private final boolean DEBUG = NettyConstant.DEBUG;
    private byte[] serverCert;
    private byte[] serverPriKey;
    private String tempCert = "-----BEGIN CERTIFICATE-----\n" +
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
            "-----END CERTIFICATE-----";
    private String tempPriKey = "47aaf29d5dde9956f0784a1f17778eede518a03171b36ff8992f226929c48504";
    public NettyTlsServerHandler(){
        Security.addProvider(new XaProvider());
        this.serverCert = tempCert.getBytes();
        this.serverPriKey = Hex.decode(tempPriKey);
    }
    public NettyTlsServerHandler(byte[] serverCert, byte[] serverPriKey){
        Security.addProvider(new XaProvider());
        this.serverCert = serverCert;
        this.serverPriKey = serverPriKey;
    }

//    @Override
//    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf bf) throws Exception {
//        ASN1Util.GetContent(bf,dataRecive);
//        ClientHello clientHello;
//        if(dataRecive.isComplete()){
//             clientHello = JSON.parseObject(new String(dataRecive.getCurrentContent()), ClientHello.class);
//        }else {
//            return;
//        }
//
//        System.out.println("clientHello");
//        System.out.println(clientHello.getVersion());
//        for (int i = 0; i < 10; i++) {
//            int finalI = i;
//            String s = Hex.toHexString(Random.RandomBySM3(10));
//            byte[] encoded = new DEROctetString(s.getBytes()).getEncoded();
//            ctx.writeAndFlush(Unpooled.copiedBuffer(encoded)).addListener(future -> {
//                if(DEBUG) System.out.println("server:server"+ finalI +"发送完毕"+s);
//            });
//        }
//
//    }



    private ServerHello serverHello;
    private ClientHello clientHello;
    private KeyPair serverKeyPairTemp;



    private byte[] random;
    public byte[] getRandom() {
        return random;
    }


    @Override
    public void channelRead0(ChannelHandlerContext ctx, ByteBuf bf) throws Exception {
//        byte[] bytes = ;
         ASN1Util.GetContent(bf, dataRecive);
            TlsMessage tlsMessage  ;
         if(dataRecive.isComplete()){
             tlsMessage = JSON.parseObject(new String(dataRecive.getCurrentContent()), TlsMessage.class);
             dataRecive.reset();
         }else{
             return;
         }
        switch (tlsMessage.getTlsMessageType()){
            case CLIENT_HELLO:
                clientHello(ctx, tlsMessage);
                break;
            case CLIENT_KEY_EXCHANGE:
                clientKeyExchange(ctx, tlsMessage);
                break;
            default:
                throw new RuntimeException("未知的消息类型");
        }
    }
    private void clientKeyExchange(ChannelHandlerContext ctx, TlsMessage tlsMessage) {

        JSONObject jsonObject=(JSONObject)tlsMessage.getObject();
        ClientKeyExchange clientKeyExchange = jsonObject.to(ClientKeyExchange.class);

        /**
         * cPub * sPri = G * cPri * sPri
         */
        byte[] PreMaster = SM2Util.KeyExchange(clientKeyExchange.getClientPubKey(), serverKeyPairTemp.getPrivate().getEncoded(), 16);
        if(DEBUG) System.out.println("server:PreMaster:"+Hex.toHexString(PreMaster));

        MessageDigest xaMd = null;
        try {
            xaMd = MessageDigest.getInstance("SM3", "XaProvider");
            random= TLSUtil.prf(xaMd,PreMaster,"master secret".getBytes(), DataConvertUtil.byteArrAdd(clientHello.getRandomC(),serverHello.getRandomS()),16);
            currentKeyMap.put(Hex.toHexString(tlsMessage.getSessionId()),random);
            if (NettyConstant.ENDPRINT) System.out.println("server Handler Print Random:"+Hex.toHexString(random));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }


    }

    private void clientHello(ChannelHandlerContext ctx, TlsMessage tlsMessage) {
        if(tlsMessage.getSessionId()!=null){
            System.out.println("sessionId:"+Hex.toHexString(tlsMessage.getSessionId()));
            byte[] random = currentKeyMap.get(Hex.toHexString(tlsMessage.getSessionId()));
            if(random!=null){
                TlsMessage tlsMessage1 = new TlsMessage(random, TlsMessageType.SERVER_FINISHED, tlsMessage.getSessionId());
                ctx.writeAndFlush(Unpooled.copiedBuffer(TlsMessage.getEncoded(tlsMessage1))).addListener(future -> {
                    if (DEBUG) System.out.println("server:serverFINISHED发送完毕");
                });
                return;
            }
        }
        JSONObject jsonObject=(JSONObject)tlsMessage.getObject();
        clientHello = jsonObject.to(ClientHello.class);
        System.out.println("clientHello sessionId:"+Hex.toHexString(clientHello.getSessionId()));
        if (DEBUG) System.out.println("server:clientHello" + clientHello);
        //todo 生成serverHello(选择适当的版本及算法)
        serverHello=new ServerHello();
        serverHello.setVersion(clientHello.getVersion());
        byte[] randomS = Random.RandomBySM3(32);
        serverHello.setRandomS(randomS);
        serverHello.setSessionId(null);
        serverHello.setCipherSuites(clientHello.getCipherSuites());
        serverHello.setCompressionMethods(null);
        TlsMessage tlsMessage1 = new TlsMessage(serverHello, TlsMessageType.SERVER_HELLO, clientHello.getSessionId());
        ctx.writeAndFlush(Unpooled.copiedBuffer(TlsMessage.getEncoded(tlsMessage1))).addListener(future -> {
            if (DEBUG) System.out.println("server:serverHello发送完毕");
        });
        TlsMessage tlsMessage2 = new TlsMessage(serverCert, TlsMessageType.SERVER_CERT, clientHello.getSessionId());
        byte[] encoded = TlsMessage.getEncoded(tlsMessage2);
        if(DEBUG) System.out.println("serverCert:"+encoded[0]);
        if(DEBUG) System.out.println("serverCert:"+new String(encoded));
        ctx.writeAndFlush(Unpooled.copiedBuffer(encoded)).addListener(future -> {
            if (DEBUG) System.out.println("server:serverCert发送完毕");
        });
        serverKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(serverKeyPairTemp.getPublic().getEncoded());
        byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();

        byte[] signature = new SM2Signature().signature(serverKeyExchangeBytes, null, serverPriKey);
        ServerKeyExchangeECDHE serverKeyExchangeECDHE = new ServerKeyExchangeECDHE(serverKeyExchange, signature);
        TlsMessage tlsMessage3 = new TlsMessage(serverKeyExchangeECDHE, TlsMessageType.SERVER_KEY_EXCHANGE_ECDHE, clientHello.getSessionId());
        ctx.writeAndFlush(Unpooled.copiedBuffer(TlsMessage.getEncoded(tlsMessage3))).addListener(future -> {
            if (DEBUG) System.out.println("server:serverKeyExchangeECDHEBytes 发送完毕");
        });
        TlsMessage tlsMessage4 = new TlsMessage("ServerHelloDone".getBytes(), TlsMessageType.SERVER_HELLO_DONE, clientHello.getSessionId());
        ctx.writeAndFlush(Unpooled.copiedBuffer(TlsMessage.getEncoded(tlsMessage4))).addListener(future -> {
            if (DEBUG) System.out.println("server:ServerHelloDone发送完毕");
        });

    }
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}

