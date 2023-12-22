package com.yxj.gm.tls.netty.handler.server;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.random.Random;
import com.yxj.gm.tls.ClientHello;
import com.yxj.gm.tls.ServerHello;
import com.yxj.gm.tls.ServerKeyExchange;
import com.yxj.gm.tls.ServerKeyExchangeECDHE;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.CharsetUtil;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.Security;

public class NettyTlsServerHandler extends SimpleChannelInboundHandler<ByteBuf> {

    boolean DEBUG = false;
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

    @Override
    public void channelRead0(ChannelHandlerContext ctx, ByteBuf bf) throws Exception {
//        byte[] bytes = ;
        ClientHello clientHello = JSON.parseObject(new String(ASN1Util.GetContent(bf)), ClientHello.class);
        System.out.println("clientHello");
        System.out.println(clientHello.getVersion());
        //todo 生成serverHello(选择适当的版本及算法)
        ServerHello serverHello = new ServerHello();
        serverHello.setVersion(clientHello.getVersion());
        byte[] randomS = Random.RandomBySM3(32);
        serverHello.setRandomS(randomS);
        serverHello.setSessionId(null);
        serverHello.setCipherSuites(clientHello.getCipherSuites());
        serverHello.setCompressionMethods(null);
        DEROctetString derOctetString = new DEROctetString(JSON.toJSONString(serverHello).getBytes());
        ctx.writeAndFlush(Unpooled.copiedBuffer(derOctetString.getEncoded()));
        System.out.println("serverHello send");
        byte[] encoded = new DEROctetString(serverCert).getEncoded();
        ctx.writeAndFlush(Unpooled.copiedBuffer(encoded));
        System.out.println("serverCert send");
        //ECDHE（E为ephemeral（临时性的）
        KeyPair serverKeyPairTemp = SM2KeyPairGenerate.generateSM2KeyPair();
        ServerKeyExchange serverKeyExchange = new ServerKeyExchange(serverKeyPairTemp.getPublic().getEncoded());
        byte[] serverKeyExchangeBytes = JSON.toJSONString(serverKeyExchange).getBytes();

        byte[] signature = new SM2Signature().signature(serverKeyExchangeBytes, null, serverPriKey);
        ServerKeyExchangeECDHE serverKeyExchangeECDHE = new ServerKeyExchangeECDHE(serverKeyExchange, signature);
        byte[] serverKeyExchangeECDHEBytes = JSON.toJSONString(serverKeyExchangeECDHE).getBytes();
        ctx.writeAndFlush(Unpooled.copiedBuffer(new DEROctetString(serverKeyExchangeECDHEBytes).getEncoded()));
        System.out.println("serverKeyExchangeECDHEBytes send");
        ctx.writeAndFlush(Unpooled.copiedBuffer(new DEROctetString("ServerHelloDone".getBytes()).getEncoded()));
        if(DEBUG) System.out.println("server:ServerHelloDone发送完毕");

    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}

