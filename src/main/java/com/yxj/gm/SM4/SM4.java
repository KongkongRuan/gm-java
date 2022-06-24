package com.yxj.gm.SM4;

import com.yxj.gm.constant.SM4Constant;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.ArrayList;

public class SM4 {
    /**Mode
     * 0 ECB
     * 1 CBC
     * 2 CFB
     * 3 OFB
     * 4 CTR
     */
    private int Mode =0;

    /**Padding
     * 0 Pkcs7
     * 1 Pkcs5
     */
    private int Padding =0;

    public static void main(String[] args) {
        byte[] msg = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10};
        byte[] key = new byte[]{(byte)0x01,(byte)0x23,(byte)0x45,(byte)0x67,(byte)0x89,(byte)0xAB,(byte)0xCD,(byte)0xEF,(byte)0xFE,(byte)0xDC,(byte)0xBA,(byte)0x98,(byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10};
        SM4 sm4 = new SM4();
        byte[][] rks = sm4.ext_key_L(key);
        for (int i = 0; i < rks.length; i++) {
            System.out.println("rks["+i+"]:"+Hex.toHexString(rks[i]));
        }
        byte[] mi = sm4.cipher(msg, rks);
        System.out.println("密文："+Hex.toHexString(mi));

        byte[] ming = sm4.decrypt(mi, rks);
        System.out.println("明文: "+Hex.toHexString(ming));
    }
    public byte[] cipher(byte[] in,byte[][] rks){
        byte[] x0 = new byte[4];
        byte[] x1 = new byte[4];
        byte[] x2 = new byte[4];
        byte[] x3 = new byte[4];
        System.arraycopy(in,0,x0,0,4);
        System.arraycopy(in,4,x1,0,4);
        System.arraycopy(in,8,x2,0,4);
        System.arraycopy(in,12,x3,0,4);
        byte[][] Xs = new byte[36][4];
        Xs[0]=x0;
        Xs[1]=x1;
        Xs[2]=x2;
        Xs[3]=x3;
        for (int i = 0; i < 32; i++) {
            Xs[i+4]=F(Xs[i],Xs[i+1],Xs[i+2],Xs[i+3],rks[i]);
//            System.out.println("X["+(i+4)+"]:"+Hex.toHexString(Xs[i+4]));
        }
        return R(Xs[32],Xs[33],Xs[34],Xs[35]);
    }
    public byte[] decrypt(byte[] in,byte[][] rks){
        byte[] x0 = new byte[4];
        byte[] x1 = new byte[4];
        byte[] x2 = new byte[4];
        byte[] x3 = new byte[4];
        System.arraycopy(in,0,x0,0,4);
        System.arraycopy(in,4,x1,0,4);
        System.arraycopy(in,8,x2,0,4);
        System.arraycopy(in,12,x3,0,4);
        byte[][] Xs = new byte[36][4];
        Xs[0]=x0;
        Xs[1]=x1;
        Xs[2]=x2;
        Xs[3]=x3;
        for (int i = 0; i < 32; i++) {
            Xs[i+4]=F(Xs[i],Xs[i+1],Xs[i+2],Xs[i+3],rks[31-i]);
//            System.out.println("X["+(i+4)+"]:"+Hex.toHexString(Xs[i+4]));
        }
        return R(Xs[32],Xs[33],Xs[34],Xs[35]);
    }
    public byte[] R(byte[] b1,byte[] b2,byte[] b3,byte[] b4){
        byte[] out = new byte[4*b1.length];
        System.arraycopy(b4,0,out,0,4);
        System.arraycopy(b3,0,out,4,4);
        System.arraycopy(b2,0,out,8,4);
        System.arraycopy(b1,0,out,12,4);
        return out;
    }

    //轮密钥扩展
    public byte[][] ext_key_L(byte[] in){
        byte[] MK0 = new byte[4];
        byte[] MK1 = new byte[4];
        byte[] MK2 = new byte[4];
        byte[] MK3 = new byte[4];
        if(in.length!=16){
            //TODO error
        }
        System.arraycopy(in,0,MK0,0,4);
        System.arraycopy(in,4,MK1,0,4);
        System.arraycopy(in,8,MK2,0,4);
        System.arraycopy(in,12,MK3,0,4);
        byte[] K0=DataConvertUtil.byteArrayXOR(MK0,new BigInteger(Integer.toString(SM4Constant.FK[0])).toByteArray());
        byte[] K1=DataConvertUtil.byteArrayXOR(MK1,new BigInteger(Integer.toString(SM4Constant.FK[1])).toByteArray());
        byte[] K2=DataConvertUtil.byteArrayXOR(MK2,new BigInteger(Integer.toString(SM4Constant.FK[2])).toByteArray());
        byte[] K3=DataConvertUtil.byteArrayXOR(MK3,new BigInteger(Integer.toString(SM4Constant.FK[3])).toByteArray());
        byte[][] rks = new byte[32][4];
        byte[][] Ks = new byte[36][4];
        Ks[0]=K0;
        Ks[1]=K1;
        Ks[2]=K2;
        Ks[3]=K3;
        for (int i = 0; i < 32; i++) {
            byte[] ck=new BigInteger(Integer.toString(SM4Constant.CK[i])).toByteArray();
            if(ck.length==3){
                byte[] temp = new byte[4];
                System.arraycopy(ck,0,temp,1,ck.length);
                ck=temp;
            }
            rks[i]=Ks[i+4]=DataConvertUtil.byteArrayXOR(Ks[i],T_(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(Ks[i+1],Ks[i+2]),Ks[i+3]),ck)));
        }
        return rks;
    }
    //轮函数
    public byte[] F(byte[] x0,byte[] x1,byte[] x2,byte[] x3,byte[] rk){
        return DataConvertUtil.byteArrayXOR(x0,T(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(x1,x2),x3),rk)));
    }
    public byte[] T(byte[] in){
        return L(tau(in));
    }
    public byte[] T_(byte[] in){
        return L_(tau(in));
    }
    public byte[] L(byte[] in){
        byte[] t1=DataConvertUtil.bitCycleLeft(in,2);
        byte[] t2=DataConvertUtil.bitCycleLeft(in,10);
        byte[] t3=DataConvertUtil.bitCycleLeft(in,18);
        byte[] t4=DataConvertUtil.bitCycleLeft(in,24);
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(in,t1),t2),t3),t4);
    }
    public byte[] L_(byte[] in){
        byte[] t1=DataConvertUtil.bitCycleLeft(in,13);
        byte[] t2=DataConvertUtil.bitCycleLeft(in,23);
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(in,t1),t2);
    }
    public byte[] tau(byte[] in){

        if(in.length!=4){
            //TODO error
            System.err.println("tau err");
        }

//        byte[] b0 = Sbox(a0);
//        byte[] b1 = Sbox(a1);
//        byte[] b2 = Sbox(a2);
//        byte[] b3 = Sbox(a3);
//        byte[] out = new byte[16];
//        System.arraycopy(b0,0,out,0,4);
//        System.arraycopy(b1,0,out,4,4);
//        System.arraycopy(b2,0,out,8,4);
//        System.arraycopy(b3,0,out,12,4);
        byte[] out = new byte[in.length];
        for (int j = 0; j < in.length; j++) {
            out[j]=Sbox(in[j]);
        }
        return out;
    }
    public byte Sbox(byte in){
        byte out ;
        byte[] bs = new byte[] {(byte) 0x0,in};
        int i=new BigInteger(bs).intValue();
        out= SM4Constant.SboxTable[i];
        return out;
    }

    public int getPadding() {
        return Padding;
    }

    public void setPadding(int padding) {
        Padding = padding;
    }

    public int getMode() {
        return Mode;
    }

    public void setMode(int mode) {
        Mode = mode;
    }

}
