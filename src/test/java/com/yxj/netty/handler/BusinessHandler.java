package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class BusinessHandler extends ChannelInboundHandlerAdapter {

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        System.out.println("Client connected, sending message to server.");

        // 连接成功后，发送一条消息到服务器
        String message = "Hello, server! Connection established.";
        ctx.writeAndFlush(message);  // 向服务器发送消息
//        ctx.fireChannelRead(message);
        // 调用父类方法继续处理
        super.channelActive(ctx);
    }
}

