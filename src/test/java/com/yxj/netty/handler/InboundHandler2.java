package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class InboundHandler2 extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        System.out.println("InboundHandler2 processing: " + msg);
        // 继续将消息传递给下一个Handler
        ctx.fireChannelRead(msg);
    }
}

