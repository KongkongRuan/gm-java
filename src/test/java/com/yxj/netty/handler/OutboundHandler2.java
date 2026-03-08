package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;

public class OutboundHandler2 extends ChannelOutboundHandlerAdapter {
    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        System.out.println("OutboundHandler2 processing: " + msg);
        // 继续将消息传递给下一个Handler
        ctx.write(msg, promise);
    }

    @Override
    public void flush(ChannelHandlerContext ctx) throws Exception {
//        System.out.println("OutboundHandler2 flushing.");
        // 调用flush()时触发
        super.flush(ctx);
    }
}

