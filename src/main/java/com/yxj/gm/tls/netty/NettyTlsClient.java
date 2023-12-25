package com.yxj.gm.tls.netty;

import com.yxj.gm.tls.netty.handler.client.NettyTlsClientHandler;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import org.bouncycastle.util.encoders.Hex;

public class NettyTlsClient {
    private int tlsPort = 4433;
    private String serverIp = "";

    public NettyTlsClient(String serverIp) {
        this.serverIp = serverIp;
    }

    public void start() throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();

        try {
            Bootstrap bootstrap = new Bootstrap();
            NettyTlsClientHandler nettyTlsClientHandler = new NettyTlsClientHandler();
            bootstrap.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {
                            ch.pipeline().addLast(nettyTlsClientHandler); // 自定义处理器
                        }
                    })
                    .option(ChannelOption.SO_KEEPALIVE, true);

            ChannelFuture future = bootstrap.connect(serverIp, tlsPort).sync();
            new Thread(()->{
                while (true){
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                    if(nettyTlsClientHandler.random!=null){
                        System.out.println("client:clientStart");
                        System.out.println(Hex.toHexString(nettyTlsClientHandler.random));
                        break;
                    }
                }
            }).start();

            future.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 20; i++) {
            new Thread(()->{
                try {
                    new NettyTlsClient("localhost").start();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }).start();
        }



    }
}

