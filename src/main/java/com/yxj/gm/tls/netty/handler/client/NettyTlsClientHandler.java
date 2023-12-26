package com.yxj.gm.tls.netty.handler.client;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.cert.CertParseVo;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.random.Random;
import com.yxj.gm.tls.*;
import com.yxj.gm.tls.netty.NettyConstant;
import com.yxj.gm.tls.netty.TlsMessage;
import com.yxj.gm.tls.netty.handler.DataRecive;
import com.yxj.gm.tls.netty.handler.enums.TlsMessageType;
import com.yxj.gm.util.CertResolver;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.TLSUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.CharsetUtil;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;

public class NettyTlsClientHandler extends SimpleChannelInboundHandler<ByteBuf> {
    static {
        Security.addProvider(new XaProvider());
    }
    private final boolean DEBUG = NettyConstant.DEBUG;

    private byte[] sessionId;

    public NettyTlsClientHandler(){

    }
    public NettyTlsClientHandler(byte[] sessionId){
        this.sessionId=sessionId;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx)  {
        clientHello = new ClientHello();
        clientHello.setVersion("v1");
        byte[] randomC = Random.RandomBySM3(32);
        if(sessionId==null){
            sessionId = Random.RandomBySM3(32);
        }
        clientHello.setSessionId(sessionId);
        clientHello.setRandomC(randomC);
        CipherSuites cipherSuites = new CipherSuites("SM4", "SM2", "SM3");
        clientHello.setCipherSuites(cipherSuites);
        clientHello.setCompressionMethods(null);
        TlsMessage tlsMessage = new TlsMessage(clientHello, TlsMessageType.CLIENT_HELLO, sessionId);

//        DEROctetString derOctetString = tlsMessage.getEncoded());
        byte[] encoded = TlsMessage.getEncoded(tlsMessage);
        ctx.writeAndFlush(Unpooled.copiedBuffer(encoded)).addListener(future -> {
            if (DEBUG) System.out.println("client:clientHello发送完毕");
                });
//        ctx.writeAndFlush(Unpooled.copiedBuffer(JSON.toJSONString(clientHello), CharsetUtil.UTF_8));
    }
    private byte[] serverCert;
    private ServerKeyExchange serverKeyExchange;
    private KeyPair clientKeyPairTemp;

    private byte[] random;
    public byte[] getRandom() {
        return random;
    }
    private ClientHello clientHello;
    private ServerHello serverHello;

    /**数据分包接收相关参数**/
    DataRecive dataRecive = new DataRecive();

    int count = 0;
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf byteBuf) throws Exception {
        if(DEBUG) System.out.println(count++);
        ASN1Util.GetContent(byteBuf, dataRecive);

        TlsMessage tlsMessage  ;
        if(dataRecive.isComplete()){
            tlsMessage = JSON.parseObject(new String(dataRecive.getCurrentContent()), TlsMessage.class);
            dataRecive.reset();
        }else{
            return;
        }
        switch (tlsMessage.getTlsMessageType()){
            case SERVER_HELLO:
                JSONObject jsonObject=(JSONObject)tlsMessage.getObject();
                serverHello = jsonObject.to(ServerHello.class);
                if(DEBUG) System.out.println("client:serverHello"+serverHello);
                break;
            case SERVER_CERT:
                serverCert = tlsMessage.getContent();
                break;
            case SERVER_KEY_EXCHANGE_ECDHE:
                 jsonObject=(JSONObject)tlsMessage.getObject();
                ServerKeyExchangeECDHE serverKeyExchangeECDHE = jsonObject.to(ServerKeyExchangeECDHE.class);

                if(DEBUG) System.out.println("client:serverKeyExchangeECDHE"+serverKeyExchangeECDHE);
                byte[] signature = serverKeyExchangeECDHE.getSignature();
                serverKeyExchange = serverKeyExchangeECDHE.getServerKeyExchange();
                byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();
                CertParseVo ServerCertParseVo = CertResolver.parseCert(serverCert);
                boolean verify = new SM2Signature().verify(serverKeyExchangeBytes, null, signature, ServerCertParseVo.getPubKey());
                if(!verify){
                    throw new RuntimeException("serverKeyExchangeECDHE verify failed");
                }
                break;
            case SERVER_HELLO_DONE:
                 clientKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
                byte[] clientKeyExchangeBytes = clientKeyPairTemp.getPublic().getEncoded();
                ClientKeyExchange clientKeyExchange = new ClientKeyExchange(clientKeyExchangeBytes);
                TlsMessage tlsMessage1 = new TlsMessage(clientKeyExchange, TlsMessageType.CLIENT_KEY_EXCHANGE, tlsMessage.getSessionId());
                ctx.writeAndFlush(Unpooled.copiedBuffer(TlsMessage.getEncoded(tlsMessage1)));
                if(DEBUG) System.out.println("client:clientKeyExchange发送完毕");
                /**
                 * sPub* cPri = G* sPri * cPri
                 */
                byte[] PreMaster = SM2Util.KeyExchange(serverKeyExchange.getServerPubKey(), clientKeyPairTemp.getPrivate().getEncoded(), 16);
                if(DEBUG) System.out.println("client:PreMaster"+ Hex.toHexString(PreMaster));
                MessageDigest xaMd = null;
                try {
                    xaMd = MessageDigest.getInstance("SM3", "XaProvider");
                    random= TLSUtil.prf(xaMd,PreMaster,"master secret".getBytes(), DataConvertUtil.byteArrAdd(clientHello.getRandomC(),serverHello.getRandomS()),16);
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    throw new RuntimeException(e);
                }
                if(DEBUG) System.out.println("client:结束");
                if (NettyConstant.ENDPRINT)System.out.println("client  Handler Print Random:"+Hex.toHexString(random));
                break;
            case SERVER_FINISHED:
                random = tlsMessage.getContent();
        }



    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }

//    @Override
//    protected void channelRead0(ChannelHandlerContext channelHandlerContext, ByteBuf byteBuf) throws Exception {
//        System.out.println("client:channelRead0");
//        ASN1Util.GetContent(byteBuf,dataRecive);
//        Thread.sleep(1000);
//        byte[] server =new byte[0] ;
//        if(dataRecive.isComplete()){
//            server=dataRecive.getCurrentContent();
//        }
//
//        if(DEBUG) System.out.println("client:server"+"--"+new String(server));
//    }
}

