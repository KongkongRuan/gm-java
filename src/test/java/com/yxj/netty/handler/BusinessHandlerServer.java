package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;

import java.nio.ByteBuffer;

public class BusinessHandlerServer extends SimpleChannelInboundHandler<ByteBuffer> {



    @Override
    protected void messageReceived(ChannelHandlerContext channelHandlerContext, ByteBuffer byteBuffer) throws Exception {
        System.out.println("服务端收到数据"+byteBuffer);
        channelHandlerContext.writeAndFlush("server: hi,client");
    }
}

