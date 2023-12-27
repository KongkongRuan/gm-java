package com.yxj.gm.tls.netty;

import com.yxj.gm.random.Random;
import com.yxj.gm.tls.netty.handler.client.NettyTlsClientHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import org.bouncycastle.util.encoders.Hex;

public class NettyTlsClient {
    private int tlsPort = 4433;
    private String serverIp = "";
    NettyTlsClientHandler nettyTlsClientHandler = new NettyTlsClientHandler();

    public NettyTlsClient(String serverIp, int tlsPort) {
        this.serverIp = serverIp;
        this.tlsPort = tlsPort;
    }
    public NettyTlsClient(String serverIp) {
        this.serverIp = serverIp;
    }
    public NettyTlsClient(String serverIp, int tlsPort,boolean isCacheKey,byte[] sessionId) {
        this.serverIp = serverIp;
        this.tlsPort = tlsPort;
        nettyTlsClientHandler = new NettyTlsClientHandler(isCacheKey,sessionId);
    }
    EventLoopGroup group = new NioEventLoopGroup();
    public void shutdown(){
        group.shutdownGracefully();
    }
    public void start() throws Exception {

        try {
            Bootstrap bootstrap = new Bootstrap();

            bootstrap.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {

                            ch.pipeline().addLast(new DelimiterBasedFrameDecoder(10240,NettyConstant.Delimiter));
                            ch.pipeline().addLast(nettyTlsClientHandler); // 自定义处理器
                        }
                    })
                    .option(ChannelOption.SO_KEEPALIVE, true);

            ChannelFuture future = bootstrap.connect(serverIp, tlsPort).sync();
            if (NettyConstant.FIRSTPRINT)System.out.println("netty-tls-client:clientStart");

            future.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }
    public byte[] getRandom(){
        return nettyTlsClientHandler.getRandom();
    }

    public static void main(String[] args) throws Exception {
        NettyConstant.setENDPRINT(false);
        NettyConstant.setFIRSTPRINT(false);
        NettyConstant.setDEBUG(false);
        for (int i = 0; i < 20; i++) {
//            byte[] random = Random.RandomBySM3(10);
            byte[] random = Hex.decode("d380db50a88b7191b33b");
            NettyTlsClient nettyTlsClient = new NettyTlsClient("localhost",4432);
            System.out.println("start");
            new Thread(()->{
                try {
                    System.out.println(Thread.currentThread().getName()+"start--"+Hex.toHexString(random));
                    nettyTlsClient.start();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).start();
            while (true){
                try {
                    Thread.sleep(1000);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                if(nettyTlsClient.getRandom()!=null){
                    System.out.println("netty client random："+ Hex.toHexString(nettyTlsClient.getRandom()));
                    break;
                }
            }
        }


//            nettyTlsClient.shutdown();



    }
}

