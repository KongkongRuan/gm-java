package com.yxj.gm.util;

import com.kms.common.utils.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DataConvertUtil {

    /**
     * Byte转Bit
     */
    public static String byteToBit(byte b) {
        return "" +(byte)((b >> 7) & 0x1) +
                (byte)((b >> 6) & 0x1) +
                (byte)((b >> 5) & 0x1) +
                (byte)((b >> 4) & 0x1) +
                (byte)((b >> 3) & 0x1) +
                (byte)((b >> 2) & 0x1) +
                (byte)((b >> 1) & 0x1) +
                (byte)((b) & 0x1);
    }

    /**
     * Byte转Bit
     */
//    public static byte[] byteToBitArray(byte b) {
//        if(b==0)return new byte[]{0,0,0,0,0,0,0,0};
//        String string = new BigInteger(b+"").toString(2);
//        if(string.length()<7){
//            int length = 7 - string.length();
//            for(int i=0;i<length;i++){
//                string = "0"+string;
//            }
//        }
//        if(b>0){
//            string= "1"+string;
//        }else {
//            string= "0"+string;
//        }
//
//        char[] charArray = string.toCharArray();
//        byte[] bytes = new byte[charArray.length];
//        for (int i = 0; i < charArray.length; i++) {
//            if(charArray[i]=='1'){
//                bytes[i] = 1;
//            }else {
//                bytes[i] = 0;
//            }
//        }
//        return bytes;
//    }

    public static byte[] byteToBitArray(byte b) {
        byte[] bytes = new byte[8];
        bytes[0]=(byte)((b >> 7) & 0x1);
        bytes[1]=(byte)((b >> 6) & 0x1);
        bytes[2]=(byte)((b >> 5) & 0x1);
        bytes[3]=(byte)((b >> 4) & 0x1);
        bytes[4]=(byte)((b >> 3) & 0x1);
        bytes[5]=(byte)((b >> 2) & 0x1);
        bytes[6]=(byte)((b >> 1) & 0x1);
        bytes[7]=(byte)((b) & 0x1);
        return bytes;
    }
    public static byte BitArrayTobyte(byte[] bytes) {
        String s="";
        for (byte b:bytes) {
            s+=b;
        }
        return BitToByte(s);
    }


    public static void main(String[] args) throws IOException {
//        byte[] bytes = byteToBitArray(130);
        String s = "02b1";
        byte[] decode = Hex.decode(s);
        System.out.println(byteArrayToUnsignedInt(decode));
        int result = ( (  (decode[0] & 0xFF)|(decode[1] & 0xFF) << 8));
        System.out.println(result);
        //130
        //-126
        //+256
        System.out.println();
        Long aLong = new Long(System.currentTimeMillis());

    }

    public static long byteArrayToUnsignedInt(byte[] byteArray) {
        if (byteArray.length == 0) {
            throw new IllegalArgumentException("字节数组不能为空");
        }
        long result = 0;
        for (int i = 0; i < byteArray.length; i++) {
            result = (result << 8) | (byteArray[i] & 0xFF);
        }
        return result;
    }
    /**
     * Bit转Byte
     */
    public static byte BitToByte(String byteStr) {
        int re, len;
        if (null == byteStr) {
            return 0;
        }
        len = byteStr.length();
        if (len != 4 && len != 8) {
            return 0;
        }
        if (len == 8) {// 8 bit处理
            if (byteStr.charAt(0) == '0') {// 正数
                re = Integer.parseInt(byteStr, 2);
            } else {// 负数
                re = Integer.parseInt(byteStr, 2) - 256;
            }
        } else {//4 bit处理
            re = Integer.parseInt(byteStr, 2);
        }
        return (byte) re;
    }


    public static byte[] byteArrAdd(byte[]... bytesArr){
        int allLength=0;
        for (byte[] value : bytesArr) {
            if(value==null){
                continue;
            }
            allLength += value.length;
        }
        byte[] resultBytes = new byte[allLength];
        int count =0;
        for (byte[] bytes : bytesArr) {
            if(bytes==null){
                continue;
            }
            System.arraycopy(bytes, 0, resultBytes, count, bytes.length);
            count += bytes.length;
        }
        return resultBytes;
    }

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
        //定义一个和输入长度一致的byte数组
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

    public static byte[] byteArrayLeft(byte[] in, int len)
    {
        BigInteger bigInteger = new BigInteger(in).shiftLeft(len);
        return byteToN(bigInteger.toByteArray(), in.length);
    }

    public static double log2(double N) {

        return Math.log10(N) / Math.log10(2);

    }
    public static byte[] byteArrayRight(byte[] in, int len)
    {
        byte[] tempByteArr = null;
        for (byte b:in) {
            tempByteArr = byteArrAdd(tempByteArr,byteToBitArray(b));
        }

        byte[] tempByteArr2 = new byte[tempByteArr.length];
        System.arraycopy(tempByteArr, 0, tempByteArr2, len, tempByteArr.length-len);


        byte[] result = new byte[in.length];

        for (int i = 0; i < tempByteArr2.length/8; i++) {
            byte temp = 0;
            for (int j = 0; j < 8; j++) {
                temp= (byte) (tempByteArr2[8*i+j]<<(7-j)^temp);
            }
            result[i] = temp;
        }
        return result;




//        BigInteger bigInteger = new BigInteger(in).shiftRight(len);
//        return byteToN(bigInteger.toByteArray(), in.length);
    }


    public static String ToByteString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(b);
        }
        return sb.toString();
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

    public static void fastByteArrayXOR(byte[] bytes1, byte[] bytes2){
//        for (int i = 0; i < bytes1.length; i++) {
//            bytes1[i]=(byte)(bytes1[i]^bytes2[i]);
//
//        }

        int i=0;
        do {
            bytes1[i]^=bytes2[i];i++;
            bytes1[i]^=bytes2[i];i++;
            bytes1[i]^=bytes2[i];i++;
            bytes1[i]^=bytes2[i];i++;
        }while (i<bytes1.length);

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

//    static BigInteger x,y;
//    static BigInteger zero = new BigInteger("0");
//    //扩展欧几里得算法求逆元
//    private static  BigInteger ex_gcd(BigInteger a,BigInteger b){
//        if(b.equals(zero)){
//            x=new BigInteger("1");
//            y=zero;
//            return a;
//        }
//        BigInteger[] bigIntegers = a.divideAndRemainder(b);
//        BigInteger ans = ex_gcd(b,bigIntegers[1]);
//        BigInteger tem = y;
//        y=x.subtract(a.divide(b).multiply(y));
//        x=tem;
//        return ans;
//    }
//    //对计算结果进行处理
//    public static synchronized  BigInteger ex_gcd_ny(BigInteger a,BigInteger b){
//        BigInteger d =ex_gcd(a,b);
//        BigInteger t = b.divide(d);
//        BigInteger[] bigIntegers = x.divideAndRemainder(t);
//        x=(bigIntegers[1].add(t)).divideAndRemainder(t)[1];
//        //部分计算结果是真实结果的相反数，此处只是简单的判断是否为负值
//        //如果是则取相反数
//        if(x.compareTo(zero) < 0){
//            x=x.multiply(new BigInteger("-1"));
//        }
//        return x;
//    }

    //扩展欧几里得算法求逆元
    private static  BigInteger[] ex_gcd(BigInteger a,BigInteger b,BigInteger x,BigInteger y){
        BigInteger[] bigArr = new BigInteger[3];
        if(b.equals(BigInteger.ZERO)){
            x=new BigInteger("1");
            y=BigInteger.ZERO;
            bigArr[0]=a;
            bigArr[1]=x;
            bigArr[2]=y;
            return bigArr;
        }
        BigInteger[] bigIntegers = a.divideAndRemainder(b);
        BigInteger[] bigArrDg = ex_gcd(b, bigIntegers[1], x, y);
        BigInteger ans = bigArrDg[0];
        y=bigArrDg[2];
        x=bigArrDg[1];
        BigInteger tem = y;
        y=x.subtract(a.divide(b).multiply(y));
        x=tem;
        bigArr[0]=ans;
        bigArr[1]=x;
        bigArr[2]=y;
        return bigArr;
    }
    //对计算结果进行处理
    public static   BigInteger ex_gcd_ny(BigInteger a,BigInteger b){
        BigInteger x = null,y = null;
        BigInteger[] bigArr = ex_gcd(a, b, x, y);
        BigInteger d =bigArr[0];
        x=bigArr[1];
//        y=bigArr[2];
        BigInteger t = b.divide(d);
        BigInteger[] bigIntegers = x.divideAndRemainder(t);
        x=(bigIntegers[1].add(t)).divideAndRemainder(t)[1];
        //部分计算结果是真实结果的相反数，此处只是简单的判断是否为负值
        //如果是则取相反数
        if(x.compareTo(BigInteger.ZERO) < 0){
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
    public static byte[] byteToN(byte[] src,int n){
        byte[] x=new byte[n];
        //计算结束后对计算结果进处理
        if(src.length==n+1){
            //如果头部带有00则去出头部的00
            System.arraycopy(src,1,x,0,n);
        }else if(src.length<n){
            //如果计算结束后不足32字节则补齐
            System.arraycopy(src,0,x,n-src.length,src.length);
        }else if(src.length==n) {
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

    public static void main1(String[] args) {

//        long a=511;
//        long b=13;
//        byte[] bytes = byteArrayXOR(longToBytes(a), longToBytes(b));
//        System.out.println(bytesToLong(bytes, 0,false));
//
//
//        int ia=511;
//        int i = ia << 2;
//        System.out.println(i);

        String str1 = "123";
        System.out.println(Hex.toHexString(str1.getBytes()));

        String str2 = "456";
        System.out.println(Hex.toHexString(str2.getBytes()));

        byte[] bytes = byteArrAdd(str1.getBytes(), str2.getBytes());
        System.out.println(Hex.toHexString(bytes));

    }



}


