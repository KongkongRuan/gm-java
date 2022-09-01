package com.yxj.gm.SM3;//import com.kms.jca.UseKey;
import com.yxj.gm.util.DataConvertUtil;

import java.nio.ByteBuffer;

public class SM3 {

    private static final byte[] IVbyte =new byte[]{(byte) 0x73,(byte) 0x80,(byte) 0x16,(byte) 0x6f,(byte) 0x49,(byte) 0x14,(byte) 0xb2,(byte) 0xb9,(byte) 0x17
            ,(byte) 0x24,(byte) 0x42,(byte) 0xd7,(byte) 0xda,(byte) 0x8a,(byte) 0x06,(byte) 0x00,(byte) 0xa9,(byte) 0x6f,(byte) 0x30,(byte) 0xbc
            ,(byte) 0x16,(byte) 0x31,(byte) 0x38,(byte) 0xaa,(byte) 0xe3,(byte) 0x8d,(byte) 0xee,(byte) 0x4d,(byte) 0xb0,(byte) 0xfb,(byte) 0x0e,(byte) 0x4e};

    private static final byte[] T1byte =new byte[]{(byte) 0x79,(byte) 0xcc,(byte) 0x45,(byte) 0x19};
    private static final byte[] T2byte = new byte[]{(byte) 0x7a,(byte) 0x87,(byte) 0x9d,(byte) 0x8a};

    private static final byte[][] WAArray= new byte[68][4];
    private static final byte[][] WBArray= new byte[64][4];

//    static String strM = "616263";
    private static byte[] msgAll=null;
    

    //0-15
    private static byte[] FF1(byte[] X,byte[] Y,byte[] Z){
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(X, Y), Z);
    }
    //16-63
    private static byte[] FF2(byte[] X,byte[] Y,byte[] Z){
        return DataConvertUtil.byteArrayOR(DataConvertUtil.byteArrayOR(DataConvertUtil.byteArrayAND(X,Y), DataConvertUtil.byteArrayAND(X,Z)),DataConvertUtil.byteArrayAND(Y,Z));
    }
    //0-15
    private static byte[] GG1(byte[] X,byte[] Y,byte[] Z){
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(X, Y), Z);
    }
    //16-63
    private static byte[] GG2(byte[] X,byte[] Y,byte[] Z){
        return DataConvertUtil.byteArrayOR(DataConvertUtil.byteArrayAND(X,Y),DataConvertUtil.byteArrayAND(DataConvertUtil.byteArrayNOT(X), Z));
    }
    private static byte[] P0(byte[] X){
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(X,DataConvertUtil.bitCycleLeft(X,9)),DataConvertUtil.bitCycleLeft(X,17));
    }

    private static byte[] P1(byte[] X){
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(X,DataConvertUtil.bitCycleLeft(X,15)),DataConvertUtil.bitCycleLeft(X,23));
    }

    //1.填充
    private static byte[] append(byte[] m){
        //System.out.println("ivlen:"+IVbyte.length);
        long l = m.length* 8L;
        //System.out.println("l:"+l);
        //计算k
        long k = 448-((l+1)%512);
        long length = (l+1+k+64)/8;
        //System.out.println("length:"+length);
        byte[] append = new byte[(int)length];
        int mLen = m.length;
        //System.out.println("mLen:"+mLen);
        //先把 m system.copopy到首部
        System.arraycopy(m,0,append,0,mLen);
        //填充1
        System.arraycopy(new byte[]{-128},0,append,mLen,1);
        //填充64位bit 长度是l的二进制表达式
        byte[] array = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(l).array();
        System.arraycopy(array,0,append,(int)length-array.length,array.length);
        return append;
    }





    //压缩函数
    private static byte[] CF(byte[] V,byte[] BI){
        if(V==null){
            V=IVbyte;
        }
        expand(BI);
        byte[] SS1,SS2,TT1,TT2,T;
        byte[] VIABC;
        byte[] A=new byte[4];
        System.arraycopy(V, 0, A, 0, 4);
        byte[] B=new byte[4];
        System.arraycopy(V, 4, B, 0, 4);
        byte[] C=new byte[4];
        System.arraycopy(V, 4*2, C, 0, 4);
        byte[] D=new byte[4];
        System.arraycopy(V, 4*3, D, 0, 4);
        byte[] E=new byte[4];
        System.arraycopy(V, 4*4, E, 0, 4);
        byte[] F=new byte[4];
        System.arraycopy(V, 4*5, F, 0, 4);
        byte[] G=new byte[4];
        System.arraycopy(V, 4*6, G, 0, 4);
        byte[] H=new byte[4];
        System.arraycopy(V, 4*7, H, 0, 4);

        for (int j = 0; j < 64; j++) {

                int l1,l2,l3;
                l1=DataConvertUtil.bytesToInt(DataConvertUtil.bitCycleLeft(A,12),0,false);
                l2=DataConvertUtil.bytesToInt(E,0,false);
                if(j<16){
                    T=T1byte;
                }else{
                    T=T2byte;
                }
                l3=DataConvertUtil.bytesToInt(DataConvertUtil.bitCycleLeft(T,(j%32)),0,false);
                SS1 = DataConvertUtil.bitCycleLeft(DataConvertUtil.intToBytes(l1+l2+l3), 7);
                SS2=DataConvertUtil.byteArrayXOR(SS1, DataConvertUtil.bitCycleLeft(A,12));

                int l4,l5,l6,l7;
                if(j<16){
                    l4=DataConvertUtil.bytesToInt(FF1(A,B,C),0,false);
                }else{
                    l4=DataConvertUtil.bytesToInt(FF2(A,B,C),0,false);
                }
                l5=DataConvertUtil.bytesToInt(D,0,false);
                l6=DataConvertUtil.bytesToInt(SS2,0,false);
                l7=DataConvertUtil.bytesToInt(WBArray[j],0,false);
                TT1=DataConvertUtil.intToBytes(l4+l5+l6+l7);

                int l8,l9,l10,l11;
                if(j<16){
                    l8=DataConvertUtil.bytesToInt(GG1(E,F,G),0,false);
                }else {
                    l8=DataConvertUtil.bytesToInt(GG2(E,F,G),0,false);
                }
                l9 = DataConvertUtil.bytesToInt(H,0,false);
                l10 = DataConvertUtil.bytesToInt(SS1,0,false);
                l11 = DataConvertUtil.bytesToInt(WAArray[j],0,false);
                TT2 = DataConvertUtil.intToBytes(l8+l9+l10+l11);
                D=C;
                C=DataConvertUtil.bitCycleLeft(B,9);
                B=A;
                A=TT1;
                H=G;
                G=DataConvertUtil.bitCycleLeft(F,19);
                F=E;
                E=P0(TT2);
        }
        VIABC=DataConvertUtil.byteArrAdd(A,B,C,D,E,F,G,H);


        return DataConvertUtil.byteArrayXOR(VIABC, V);
    }
    //扩展(压缩函数需要调用扩展)
    private static void expand(byte[] BI){
        //第一步将消息分组B划分为16个字
        for (int i = 0; i <16 ; i++) {
            byte[] temByte = new byte[4];
            System.arraycopy(BI, i*4, temByte,0,4);
            WAArray[i]=temByte;
        }
        //第二步
        for (int j = 16; j < 68; j++) {
            WAArray[j]= DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(P1(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(WAArray[j-16],WAArray[j-9]),DataConvertUtil.bitCycleLeft(WAArray[j-3],15))),DataConvertUtil.bitCycleLeft(WAArray[j-13], 7)),WAArray[j-6]);
        }
        for (int j = 0; j <64 ; j++) {
            WBArray[j]=DataConvertUtil.byteArrayXOR(WAArray[j], WAArray[j+4]);
        }
    }



    //2.迭代
    private static byte[] iteration(){
        if(msgAll==null){
            throw new RuntimeException("请添加要计算的值");
        }
        byte[] append = append(msgAll);
        byte[] sm3Hash=null;
        long n = append.length / 64;
        //System.out.println("n:"+n);
        byte[][] BArray = new byte[(int) n][64];
        for (int i = 0; i < n; i++) {
            System.arraycopy(append, i*64, BArray[i],0,64);
            //System.out.println("第"+i+"轮压缩");
            //压缩函数
            sm3Hash=CF(sm3Hash, BArray[i]);
        }
        //计算完成后清空上次的消息值
        msgAll=null;
        return sm3Hash;
    }
    public void update(byte[] msg){
        if(msgAll==null){
            msgAll=msg;
        }else {
            msgAll=DataConvertUtil.byteArrAdd(msgAll,msg);
        }
    }
    public byte[] doFinal(){
        return iteration();
    }

    public void msgAllReset(){
        msgAll=null;
    }




}
