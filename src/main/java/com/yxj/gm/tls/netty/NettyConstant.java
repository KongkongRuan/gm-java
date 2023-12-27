package com.yxj.gm.tls.netty;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class NettyConstant {
    public static  boolean DEBUG = false;
    public static  boolean FIRSTPRINT = true;
    public static  boolean ENDPRINT = false;
    public static  ByteBuf Delimiter= Unpooled.copiedBuffer("$_@==@_$".getBytes());

    public static boolean isDEBUG() {
        return DEBUG;
    }

    public static void setDEBUG(boolean DEBUG) {
        NettyConstant.DEBUG = DEBUG;
    }

    public static boolean isFIRSTPRINT() {
        return FIRSTPRINT;
    }

    public static void setFIRSTPRINT(boolean FIRSTPRINT) {
        NettyConstant.FIRSTPRINT = FIRSTPRINT;
    }

    public static boolean isENDPRINT() {
        return ENDPRINT;
    }

    public static void setENDPRINT(boolean ENDPRINT) {
        NettyConstant.ENDPRINT = ENDPRINT;
    }

    public static ByteBuf getDelimiter() {
        return Delimiter;
    }

    public static void setDelimiter(ByteBuf delimiter) {
        Delimiter = delimiter;
    }
}
