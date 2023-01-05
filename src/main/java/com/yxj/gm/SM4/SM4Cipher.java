package com.yxj.gm.SM4;

import com.yxj.gm.constant.SM4Constant;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.util.DataConvertUtil;

import java.math.BigInteger;

import static com.yxj.gm.enums.ModeEnum.CTR;

/**
 * 国密SM4对称加密算法
 *      默认为CTR模式
 *      PKCS7填充
 */
public class SM4Cipher {

    /**Mode
     * 0 ECB
     * 1 CBC
     * 2 CFB
     * 3 OFB
     * 4 CTR
     */
    private ModeEnum Mode = CTR;

    /**Padding
     * 0 Pkcs7
     * 1 Pkcs5
     */
    private PaddingEnum Padding =PaddingEnum.Pkcs7;

    public ModeEnum getMode() {
        return Mode;
    }

    public void setMode(ModeEnum mode) {
        Mode = mode;
    }

    public PaddingEnum getPadding() {
        return Padding;
    }

    public void setPadding(PaddingEnum padding) {
        Padding = padding;
    }

    public SM4Cipher(){}

    public SM4Cipher(PaddingEnum padding, ModeEnum mode){
        this.Padding=padding;
        this.Mode=mode;
    }
    public SM4Cipher(PaddingEnum padding){
        this.Padding=padding;
    }
    public SM4Cipher(ModeEnum mode){
        this.Mode=mode;
    }
    public byte[] cipherEncrypt(byte [] key,byte[] ming,byte[] iv){
        //生成轮密钥
        byte[][] rks = ext_key_L(key);
        byte[] result=null;
        switch (Mode){
            case ECB:
                result = blockEncryptECB(ming,rks);
                break;
            case CBC:
                result = blockEncryptCBC(ming,iv,rks);
                break;
            case CFB:
            case OFB:
                break;
            case CTR:
                result= blockEncryptCTR(ming,iv,rks);
                break;
            default:
                throw new RuntimeException("加密模式错误："+Mode);
        }
        return result;
    }
    public byte[] cipherDecrypt(byte [] key,byte[] mi,byte[] iv){
        //iv设置默认值
        if(iv==null){
            iv="1234567812345678".getBytes();
        }
        //生成轮密钥
        byte[][] rks = ext_key_L(key);

        byte[] result=null;
        switch (Mode){
            case ECB:
                result = blockDecryptECB(mi,rks);
                break;
            case CBC:
                result = blockDecryptCBC(mi,iv,rks);
                break;
            case CFB:
            case OFB:
                break;
            case CTR:
                result= blockEncryptCTR(mi,iv,rks);
                break;
            default:
                throw new RuntimeException("解密模式错误："+Mode);
        }
        return result;
    }
    //1.填充
    private byte[] padding(byte[] m){
        int SM4length = 16;
        int Pkcs5length = 8;
        int blockLength;
        //PKCS7
        if(Padding==PaddingEnum.Pkcs7){
            blockLength=SM4length;
        }else if(Padding==PaddingEnum.Pkcs5){
            //PKCS5
            blockLength=Pkcs5length;
        }else {
            throw new RuntimeException("未识别的填充算法");
        }
        int y=m.length%blockLength;
        int t=blockLength-y;
        byte[] padding = new byte[t];
        for (int i = 0; i < t; i++) {
            padding[i]= (byte) t;
        }
        byte[] result = new byte[m.length+t];
        System.arraycopy(m,0,result,0,m.length);
        System.arraycopy(padding,0,result,m.length,padding.length);
        return result;
    }
    private byte[] unPadding(byte[] m){
        int count = m[m.length-1];
        byte[] result = new byte[m.length-count];
        System.arraycopy(m,0,result,0,result.length);
        return result;
    }
    //2. 分组然后根据模式并行加密
    //ECB
    public byte[] blockEncryptECB(byte[] m, byte[][] rks){
        //1 填充
        m=padding(m);
        //2 分块
        byte[][] block = block(m);
        //3 加密
        byte[][] result = new byte[block.length][16];
        for (int i = 0; i < block.length; i++) {
            result[i]=cipher(block[i], rks);
        }
        //4 合并
        //5 去除填充
        return merge(result);
    }
    //CBC
    public byte[] blockEncryptCBC(byte[] m, byte[] iv, byte[][] rks){
        //1 填充
        m=padding(m);
        //2 分块
        byte[][] block = block(m);
        //3 加密
        byte[][] result = new byte[block.length][16];
        byte[] xorTemp = iv;
        for (int i = 0; i < block.length; i++) {
            //明文先和中间变量XOR再加密
            result[i]=cipher(DataConvertUtil.byteArrayXOR(block[i],xorTemp), rks);
            //第一次的中间变量为iv，后面的中间变量为上次加密的密文
            xorTemp=result[i];
        }
        //4 合并
        return merge(result);
    }
    //CRT
    public byte[] blockEncryptCTR(byte[] m, byte[] iv, byte[][] rks){
        if(iv.length!=16){
            throw new RuntimeException("iv 长度错误 iv len="+iv.length);
        }
        byte[][] blocks = block(m);
        byte[][] mis = new byte[blocks.length][16];
        for (int i = 0; i < blocks.length; i++) {
            byte[] cipher = cipher(iv, rks);
            if(blocks[i].length!=cipher.length){
                byte[] tempCipher = new byte[blocks[i].length];
                System.arraycopy(cipher,0,tempCipher,0,blocks[i].length);
                cipher=tempCipher;
            }
            mis[i]=DataConvertUtil.byteArrayXOR(blocks[i],cipher);
            iv=byteArrAdd(iv);
        }
        return merge(mis);
    }
    private byte[] byteArrAdd(byte[] iv){
        iv = DataConvertUtil.oneAdd(iv);
        BigInteger temp  = new BigInteger(iv);
        temp=temp.add(new BigInteger("1"));
        return DataConvertUtil.byteToN(temp.toByteArray(),16);
    }
    private byte[] cipher(byte[] in,byte[][] rks){
        byte[][] Xs=SM4Pretreatment(in);
        for (int i = 0; i < 32; i++) {
            Xs[i+4]=F(Xs[i],Xs[i+1],Xs[i+2],Xs[i+3],rks[i]);
        }
        return R(Xs[32],Xs[33],Xs[34],Xs[35]);
    }

    //解密
    //ECB
    public byte[] blockDecryptECB(byte[] m, byte[][] rks){
        //1 分块
        byte[][] block = block(m);
        //2 解密
        byte[][] result = new byte[block.length][16];
        for (int i = 0; i < block.length; i++) {
            result[i]=decrypt(block[i], rks);
        }
        //3 合并
        byte[] merge = merge(result);
        //4 去除填充
        return unPadding(merge);
    }
    //CBC
    public byte[] blockDecryptCBC(byte[] m, byte[] iv, byte[][] rks){
        //1 分块
        byte[][] block = block(m);
        //2 解密
        byte[][] result = new byte[block.length][16];
        byte[] xorTemp = iv;
        for (int i = 0; i < block.length; i++) {
            result[i]=DataConvertUtil.byteArrayXOR(decrypt(block[i], rks),xorTemp);
            xorTemp=block[i];
        }
        //3 合并
        byte[] merge = merge(result);
        //4 去除填充
        return unPadding(merge);
    }
    private byte[] decrypt(byte[] in,byte[][] rks){

        byte[][] Xs=SM4Pretreatment(in);
        for (int i = 0; i < 32; i++) {
            Xs[i+4]=F(Xs[i],Xs[i+1],Xs[i+2],Xs[i+3],rks[31-i]);
        }
        return R(Xs[32],Xs[33],Xs[34],Xs[35]);
    }

    private byte[][] SM4Pretreatment(byte[] in) {
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
        return Xs;
    }

    //分组
    private  byte[][] block(byte[] m){
        int count = m.length/16;
        int last = m.length%16;
        if(last!=0)count++;
        byte[][] result = new byte[count][16];
        for (int i = 0; i < count; i++) {
            byte[] temp;
            if(i==count-1&&last!=0){
                 temp= new byte[last];
            }else {
                 temp = new byte[16];
            }
            System.arraycopy(m,i*16,temp,0,temp.length);
            result[i]=temp;
        }
        return result;
    }
    //合并
    private byte[] merge(byte[][] ms){
        int len = (ms.length-1)*16+ms[ms.length-1].length;
        byte[] result = new byte[len];
        for (int i = 0; i < ms.length; i++) {
            System.arraycopy(ms[i],0,result,i*16,ms[i].length);
        }
        return result;
    }
    private byte[] R(byte[] b1,byte[] b2,byte[] b3,byte[] b4){
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
            // error
            throw new RuntimeException("KEY length!=16");
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
    private byte[] F(byte[] x0,byte[] x1,byte[] x2,byte[] x3,byte[] rk){
        return DataConvertUtil.byteArrayXOR(x0,T(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(x1,x2),x3),rk)));
    }
    private byte[] T(byte[] in){
        return L(tau(in));
    }
    private byte[] T_(byte[] in){
        return L_(tau(in));
    }
    private byte[] L(byte[] in){
        byte[] t1=DataConvertUtil.bitCycleLeft(in,2);
        byte[] t2=DataConvertUtil.bitCycleLeft(in,10);
        byte[] t3=DataConvertUtil.bitCycleLeft(in,18);
        byte[] t4=DataConvertUtil.bitCycleLeft(in,24);
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(in,t1),t2),t3),t4);
    }
    private byte[] L_(byte[] in){
        byte[] t1=DataConvertUtil.bitCycleLeft(in,13);
        byte[] t2=DataConvertUtil.bitCycleLeft(in,23);
        return DataConvertUtil.byteArrayXOR(DataConvertUtil.byteArrayXOR(in,t1),t2);
    }
    private byte[] tau(byte[] in){

        if(in.length!=4){
            //TODO error
            System.err.println("tau err");
        }

        byte[] out = new byte[in.length];
        for (int j = 0; j < in.length; j++) {
            out[j]=Sbox(in[j]);
        }
        return out;
    }
    private byte Sbox(byte in){
        byte out ;
        byte[] bs = new byte[] {(byte) 0x0,in};
        int i=new BigInteger(bs).intValue();
        out= SM4Constant.SboxTable[i];
        return out;
    }





}
