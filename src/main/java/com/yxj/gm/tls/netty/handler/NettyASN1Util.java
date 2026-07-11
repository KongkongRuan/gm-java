package com.yxj.gm.tls.netty.handler;

import com.yxj.gm.tls.netty.NettyConstant;
import com.yxj.gm.util.DataConvertUtil;
import io.netty.buffer.ByteBuf;

/**
 * ASN1 解析的 Netty ByteBuf 适配工具。
 *
 * 原 {@link com.yxj.gm.asn1.ca.util.ASN1Util} 中的 ByteBuf 重载方法已迁移至此，
 * 使核心 asn1 包不再依赖 netty，方便使用方按需引入 netty。
 */
public class NettyASN1Util {

    private static final boolean DEBUG = NettyConstant.DEBUG;

    public static void GetContent(ByteBuf byteBuf, DataRecive dataRecive) {
        /**
         * 解决分包问题
         */
        if (!dataRecive.isComplete()) {
            if (DEBUG) System.out.println("分包 GetContent");
            int totalLength = dataRecive.getTotalLength();
            byte[] currentContent = dataRecive.getCurrentContent();
            int remaining = totalLength - currentContent.length;
            int contentLength = Math.min(remaining, 2048);
            byte[] content = new byte[contentLength];
            byteBuf.readBytes(content);
            dataRecive.setCurrentContent(DataConvertUtil.byteArrAdd(currentContent, content));
            dataRecive.setComplete(true);
            return;
        }

        int tag = byteBuf.readByte();
        if (tag != 4) {
            byte[] content = new byte[byteBuf.readableBytes()];
            if (DEBUG) byteBuf.readBytes(content);
            if (DEBUG) System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            if (DEBUG) System.out.println(new String(content));
            throw new RuntimeException("输入的asn1编码有误,tag:" + tag);
        }
        int ltag = byteBuf.readByte();
        byte[] bytes = DataConvertUtil.byteToBitArray((byte) ltag);
        if (bytes[0] != 1) {
            byte[] bytes1 = new byte[ltag];
            byteBuf.readBytes(bytes1);
            if (DEBUG) System.err.println("bytes[0]!=1  小Data------------------");
            if (DEBUG) System.err.println(new String(bytes1));
            dataRecive.setCurrentContent(bytes1);
        } else {
            if (DEBUG) System.err.println("bytes[0]!=1  大Data------------------");
            bytes[0] = 0;
            byte b = DataConvertUtil.BitArrayTobyte(bytes);
            byte[] lenbytes = new byte[b];
            byteBuf.readBytes(lenbytes);
            long len = DataConvertUtil.byteArrayToUnsignedInt(lenbytes);

            byte[] content = new byte[(int) len];
            int remaining = byteBuf.writerIndex() - (b + 2);
            if (len > remaining) {
                dataRecive.setTotalLength((int) len);
                content = new byte[remaining];
                byteBuf.readBytes(content);
                if (DEBUG) System.err.println("len>remaining  分包第一包------------------");
                if (DEBUG) System.err.println(new String(content));
                dataRecive.setCurrentContent(DataConvertUtil.byteArrAdd(dataRecive.getCurrentContent(), content));
                if (dataRecive.getCurrentContent().length == dataRecive.getTotalLength()) {
                    dataRecive.setComplete(true);
                } else {
                    dataRecive.setComplete(false);
                }
                return;
            }

            byteBuf.readBytes(content);
            if (DEBUG) System.err.println("bytes[0]!=1  大Data------------------");
            if (DEBUG) System.err.println(new String(content));
            dataRecive.setCurrentContent(content);
            dataRecive.setComplete(true);
        }
    }
}
