package com.yxj.gm.tls.netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class NettyConstant {
    public static final boolean DEBUG = false;
    public static final boolean FIRSTPRINT = true;
    public static final boolean ENDPRINT = true;
    public static final ByteBuf Delimiter= Unpooled.copiedBuffer("$_@==@_$".getBytes());
}
