package com.yxj.netty.handler;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.SimpleChannelInboundHandler;

import java.nio.ByteBuffer;

public class BusinessHandlerServer extends SimpleChannelInboundHandler<ByteBuffer> {


    @Override
    protected void channelRead0(ChannelHandlerContext channelHandlerContext, ByteBuffer o) throws Exception {
        System.out.println("服务端收到数据"+o);
        channelHandlerContext.writeAndFlush("server: hi,client");
    }
}

