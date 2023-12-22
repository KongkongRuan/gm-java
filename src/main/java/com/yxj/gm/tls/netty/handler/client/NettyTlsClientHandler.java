package com.yxj.gm.tls.netty.handler.client;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.cert.CertParseVo;
import com.yxj.gm.random.Random;
import com.yxj.gm.tls.*;
import com.yxj.gm.util.CertResolver;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.CharsetUtil;
import org.bouncycastle.asn1.DEROctetString;

import java.security.KeyPair;

public class NettyTlsClientHandler extends SimpleChannelInboundHandler<ByteBuf> {
    boolean DEBUG = true;
    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        ClientHello clientHello = new ClientHello();
        clientHello.setVersion("v1");
        byte[] randomC = Random.RandomBySM3(32);
        byte[] sessionId = Random.RandomBySM3(32);
        clientHello.setSessionId(sessionId);
        clientHello.setRandomC(randomC);
        clientHello.setSessionId(null);
        CipherSuites cipherSuites = new CipherSuites("SM4", "SM2", "SM3");
        clientHello.setCipherSuites(cipherSuites);
        clientHello.setCompressionMethods(null);
        DEROctetString derOctetString = new DEROctetString(JSON.toJSONString(clientHello).getBytes());
        ctx.writeAndFlush(Unpooled.copiedBuffer(derOctetString.getEncoded()));
//        ctx.writeAndFlush(Unpooled.copiedBuffer(JSON.toJSONString(clientHello), CharsetUtil.UTF_8));
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf byteBuf) throws Exception {

        ServerHello serverHello = JSON.parseObject(new String(ASN1Util.GetContent(byteBuf)), ServerHello.class);
        if(DEBUG) System.out.println("client:serverHello"+serverHello);

        byte[] serverCert = ASN1Util.GetContent(byteBuf);
        if(DEBUG) System.out.println("client:serverCert"+new String(serverCert));

        byte[] serverKeyExchangeECDHEBytes = ASN1Util.GetContent(byteBuf);
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
        byte[] serverHelloDoneBytes = ASN1Util.GetContent(byteBuf);
        if(DEBUG) System.out.println("client:serverHelloDone"+new String(serverHelloDoneBytes));

        KeyPair clientKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ClientKeyExchange clientKeyExchange = new ClientKeyExchange(clientKeyPairTemp.getPublic().getEncoded());
        byte[] clientKeyExchangeBytes = JSON.toJSONString(clientKeyExchange).getBytes();
        ctx.writeAndFlush(Unpooled.copiedBuffer(new DEROctetString(clientKeyExchangeBytes).getEncoded()));
        if(DEBUG) System.out.println("client:clientKeyExchange发送完毕");


    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}

