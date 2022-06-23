package com.yxj.gm.util;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DataConvertUtil {



    //byte[] 循环左移
    public static byte[] bitCycleLeft(byte[] tmp, int bitLen)
    {
        bitLen %= 32;//要位移的位数对32取余
//        byte[] tmp = intToBytes(n);//把int转成byte
        int byteLen = bitLen / 8;//要位移的位数对32取余后除以8
        int len = bitLen % 8;//要位移的位数对32取余后除以8后对8取余
        if (byteLen > 0)
        {
            //如果位移位数大于8
            tmp = byteCycleLeft(tmp, byteLen);
        }

        if (len > 0)
        {
            tmp = bitSmall8CycleLeft(tmp, len);
        }

        return tmp;
    }
    //int 循环左移
    private static int bitCycleLeft(int n, int bitLen)
    {
        bitLen %= 32;//要位移的位数对32取余
        byte[] tmp = intToBytes(n);//把int转成byte
        int byteLen = bitLen / 8;//要位移的位数对32取余后除以8
        int len = bitLen % 8;//要位移的位数对32取余后对8取余
        if (byteLen > 0)
        {
            //如果位移位数大于8
            tmp = byteCycleLeft(tmp, byteLen);
        }

        if (len > 0)
        {
            tmp = bitSmall8CycleLeft(tmp, len);
        }

        return bytesToInt(tmp,0,false);
    }


    private static byte[] bitSmall8CycleLeft(byte[] in, int len)
    {
        byte[] tmp = new byte[in.length];
        int t1, t2, t3;
        for (int i = 0; i < tmp.length; i++)
        {
            t1 = (byte) ((in[i] & 0x000000ff) << len);
            t2 = (byte) ((in[(i + 1) % tmp.length] & 0x000000ff) >> (8 - len));
            t3 = (byte) (t1 | t2);
            tmp[i] = (byte) t3;
        }

        return tmp;
    }

    private static byte[] byteCycleLeft(byte[] in, int byteLen)
    {
        byte[] tmp = new byte[in.length];
        System.arraycopy(in, byteLen, tmp, 0, in.length - byteLen);
        System.arraycopy(in, 0, tmp, in.length - byteLen, byteLen);
        return tmp;
    }
    /**
     * 字节数组逆序
     *
     * @param in
     * @return
     */
    private static byte[] back(byte[] in)
    {
        byte[] out = new byte[in.length];
        for (int i = 0; i < out.length; i++)
        {
            out[i] = in[out.length - i - 1];
        }

        return out;
    }
    public static byte[] rotateRight(byte[] sourceBytes, int n) {
        int i = bytesToInt(sourceBytes, 0, false);
        int i1 = i >> n;
        return intToBytes(i1);
    }

    //与
    public static byte[] byteArrayAND(byte[] bytes1, byte[] bytes2){
        int length = bytes1.length;
        if(bytes1.length != bytes2.length){
            throw new IllegalArgumentException("不同长度数据无法进行AND运算");
        }
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i]=(byte)(bytes1[i]&bytes2[i]);
        }
        return bytes;
    }
    //或
    public static byte[] byteArrayOR(byte[] bytes1, byte[] bytes2){
        int length = bytes1.length;
        if(bytes1.length != bytes2.length){
            throw new IllegalArgumentException("不同长度数据无法进行OR运算");
        }
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i]=(byte)(bytes1[i]|bytes2[i]);
        }
        return bytes;
    }
    //异或
    public static byte[] byteArrayXOR(byte[] bytes1, byte[] bytes2){
        int length = bytes1.length;
        if(bytes1.length != bytes2.length){
            throw new IllegalArgumentException("不同长度数据无法进行XOR运算");
        }
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i]=(byte)(bytes1[i]^bytes2[i]);
        }

        return bytes;
    }
    //非
    public static byte[] byteArrayNOT(byte[] bytes1){
        int length = bytes1.length;
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i]=(byte)~bytes1[i];
        }
        return bytes;
    }

    /**
     * 利用 {@link java.nio.ByteBuffer}实现byte[]转long
     * @param input
     * @param offset
     * @param littleEndian 输入数组是否小端模式
     * @return
     */
    public static long bytesToLong(byte[] input, int offset, boolean littleEndian) {
        if(offset <0 || offset+8>input.length)
            throw new IllegalArgumentException(String.format("less than 8 bytes from index %d  is insufficient for long",offset));
        ByteBuffer buffer = ByteBuffer.wrap(input,offset,8);
        if(littleEndian){
            // ByteBuffer.order(ByteOrder) 方法指定字节序,即大小端模式(BIG_ENDIAN/LITTLE_ENDIAN)
            // ByteBuffer 默认为大端(BIG_ENDIAN)模式
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        return buffer.getLong();
    }
    public static byte[] longToBytes(long value) {

        return ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(value).array();
    }


    public static int bytesToInt(byte[] input, int offset, boolean littleEndian) {


        if(offset <0 || offset+4>input.length)
            throw new IllegalArgumentException(String.format("less than 4 bytes from index %d  is insufficient for long",offset));
        ByteBuffer buffer = ByteBuffer.wrap(input,offset,4);
        if(littleEndian){
            // ByteBuffer.order(ByteOrder) 方法指定字节序,即大小端模式(BIG_ENDIAN/LITTLE_ENDIAN)
            // ByteBuffer 默认为大端(BIG_ENDIAN)模式
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        return buffer.getInt();


    }

    public static byte[] intToBytes(int value) {

        return ByteBuffer.allocate(Integer.SIZE / Byte.SIZE).putInt(value).array();
    }

    static BigInteger x,y;
    static BigInteger zero = new BigInteger("0");
    //扩展欧几里得算法求逆元
    private static BigInteger ex_gcd(BigInteger a,BigInteger b){
        if(b.equals(zero)){
            x=new BigInteger("1");
            y=zero;
            return a;
        }
        BigInteger[] bigIntegers = a.divideAndRemainder(b);
        BigInteger ans = ex_gcd(b,bigIntegers[1]);
        BigInteger tem = y;
        y=x.subtract(a.divide(b).multiply(y));
        x=tem;
        return ans;
    }
    //对计算结果进行处理
    public static BigInteger ex_gcd_ny(BigInteger a,BigInteger b){
        BigInteger d =ex_gcd(a,b);
        BigInteger t = b.divide(d);
        BigInteger[] bigIntegers = x.divideAndRemainder(t);
        x=(bigIntegers[1].add(t)).divideAndRemainder(t)[1];
        //部分计算结果是真实结果的相反数，此处只是简单的判断是否为负值
        //如果是则取相反数
        if(x.compareTo(zero) < 0){
            x=x.multiply(new BigInteger("-1"));
        }
        return x;
    }
    public static byte[] byteTo32(byte[] src){
        byte[] x=new byte[32];
        //计算结束后对计算结果进处理
        if(src.length==33){
            //如果头部带有00则去出头部的00
            System.arraycopy(src,1,x,0,32);
        }else if(src.length<32){
            //如果计算结束后不足32字节则补齐
            System.arraycopy(src,0,x,32-src.length,src.length);
        }else if(src.length==32) {
            x=src;
        }
        return x;
    }
    //第一字节补0
    public static byte[] oneAdd(byte[] src){

        byte[] result = new byte[src.length+1];
        System.arraycopy(src,0,result,1,src.length);
        return result;

    }
    //删除第一个字节
    public static byte[] oneDel(byte[] src){

        byte[] result = new byte[src.length-1];
        System.arraycopy(src,1,result,0,src.length-1);
        return result;
    }
    //short数组转换成byte
    public static byte[] shortToBytes(short[] shorts) {
        if(shorts==null){
            return null;
        }
        byte[] bytes = new byte[shorts.length * 2];
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).asShortBuffer().put(shorts);

        return bytes;
    }

    public static void main(String[] args) {

//        long a=511;
//        long b=13;
//        byte[] bytes = byteArrayXOR(longToBytes(a), longToBytes(b));
//        System.out.println(bytesToLong(bytes, 0,false));
//
//
//        int ia=511;
//        int i = ia << 2;
//        System.out.println(i);

        String ss1 = "abcd";
        byte[] bytes = ss1.getBytes();

        byte[] bytes1 = bitCycleLeft(bytes, 2);
        System.out.println(Hex.toHexString(bytes1));

        System.out.println(15/8);

    }



}


