package com.yxj.netty;

import com.yxj.netty.handler.*;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

public class NettyClient {
    public static void main(String[] args) throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) throws Exception {
                            ChannelPipeline pipeline = ch.pipeline();
                            pipeline.addLast(new OutboundHandler1());
                            pipeline.addLast(new OutboundHandler2());
                            pipeline.addLast(new InboundHandler1());
                            pipeline.addLast(new InboundHandler2());
                            pipeline.addLast(new BusinessHandler());

                        }
                    });

            // 连接到服务器
            ChannelFuture f = b.connect("localhost", 8080).sync();

            // 发送消息到服务器
            f.channel().writeAndFlush("Hello from client!");

            f.channel().closeFuture().sync();
        } finally {
            group.shutdownGracefully();
        }
    }
}

