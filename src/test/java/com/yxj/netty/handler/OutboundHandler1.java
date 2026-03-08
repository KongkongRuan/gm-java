package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

public class OutboundHandler1 extends ChannelOutboundHandlerAdapter {
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        System.out.println("OutboundHandler1 processing: " + msg);
        // 继续将消息传递给下一个Handler
        ctx.write(msg, promise);
    }
}

