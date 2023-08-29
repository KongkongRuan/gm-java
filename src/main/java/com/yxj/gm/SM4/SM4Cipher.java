package com.yxj.gm.SM4;

import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.constant.SM4Constant;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.*;

import static com.yxj.gm.enums.ModeEnum.CTR;

/**
 * 国密SM4对称加密算法
 *      默认为CTR模式
 *      PKCS7填充
 */
public class SM4Cipher {
    /**
     * 创建线程池
     */
    ExecutorService executorService = Executors.newFixedThreadPool(10);
    ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) executorService;

    /**
     * 线程数
     */
    private int processors = 2 * Runtime.getRuntime().availableProcessors() + 1;
//    private int processors = Runtime.getRuntime().availableProcessors();
    /**Mode
     * 0 ECB
     * 1 CBC
     * 2 CFB
     * 3 OFB
     * 4 CTR
     */
    private ModeEnum Mode = CTR;

    private byte[][] VBox = new byte[129][16];

    /**Padding
     * 0 Pkcs7
     * 1 Pkcs5
     */
    private PaddingEnum Padding =PaddingEnum.Pkcs7;


    private boolean DEBUG = false;
    private boolean TIME = false;

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
        long l = System.currentTimeMillis();
        byte[][] rks = ext_key_L(key);
        //System.out.println("生成轮密钥耗时："+(System.currentTimeMillis()-l));
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
        Arrays.fill(padding, (byte) t);
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
    public byte[] blockEncryptCTR(byte[] m, byte[] iv, byte[][] rks)  {
        if(iv.length!=16){
            throw new RuntimeException("iv 长度错误 iv len="+iv.length);
        }
        byte[][] blocks = block(m);
        //System.out.println("分块耗时："+(System.currentTimeMillis()-l));
        byte[][] mis = new byte[blocks.length][16];

        ////System.out.println(processors);
        if (blocks.length < processors) {
            processors = blocks.length;
        }
        //确定每个线程处理的数据量
        long size = blocks.length / processors;
        //确定最后一个线程处理的数据量
        long remainder = blocks.length % processors;
        processors++;
//        System.out.println("processors:"+processors+",size:"+size+",remainder:"+remainder);
        CountDownLatch countDownLatch = new CountDownLatch(processors);
        for (int i = 0; i < processors; i++) {
            long start = i * size;
            long end = 0;
            if (i == processors - 1) {
                end =(i*size)+remainder;
            }else {
                end = (i + 1) * size;
            }
            long finalEnd = end;
            long finalStart = start;
            if(i!=0){
                iv = byteArrAdd(iv,size);
            }
            byte[] finalIv = iv;
            threadPoolExecutor.execute(new Runnable() {
                @Override
                public void run() {
                    byte[] startIv = finalIv;
//                    System.out.println(Thread.currentThread().getName()+"start:"+finalStart+" end:"+ finalEnd + " count:"+(finalEnd-finalStart));
                    for (int i = (int) finalStart; i < finalEnd; i++) {


                        byte[] cipher = cipher(startIv, rks);
                        if(blocks[i].length!=cipher.length){
                            byte[] tempCipher = new byte[blocks[i].length];
                            System.arraycopy(cipher,0,tempCipher,0,blocks[i].length);
                            cipher=tempCipher;
                        }
//                        System.out.println(Thread.currentThread().getName()+",i:"+i);
                        mis[i]=DataConvertUtil.byteArrayXOR(blocks[i],cipher);
                        startIv=byteArrAdd(startIv);
                        //System.out.println(i+"分块加密耗时："+(System.currentTimeMillis()-l2));
                    }
                    countDownLatch.countDown();
                }
            });
        }
        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        threadPoolExecutor.shutdown();

        //System.out.println(blocks.length);
        //System.out.println("分块加密总耗时："+(System.currentTimeMillis()-l1));
        return merge(mis);
    }
    private byte[] byteArrAdd(byte[] iv){
        iv = DataConvertUtil.oneAdd(iv);
        BigInteger temp  = new BigInteger(iv);
        temp=temp.add(new BigInteger("1"));
        return DataConvertUtil.byteToN(temp.toByteArray(),16);
    }
    private byte[] byteArrAdd(byte[] a,long b){
        BigInteger add = new BigInteger(a).add(new BigInteger(String.valueOf(b)));
        return DataConvertUtil.byteToN(add.toByteArray(),16);
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
        long count = m.length/16;
        long last = m.length%16;
        if(last!=0)count++;
        byte[][] result = new byte[(int) count][16];
        for (int i = 0; i < count; i++) {
            byte[] temp;
            if(i==count-1&&last!=0){
                temp= new byte[(int) last];
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
        long len = (ms.length-1)*16+ms[ms.length-1].length;
        byte[] result = new byte[(int) len];
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



    /************************************GCM相关代码*******************************************/
    private byte[] byteArrayMultiplePoint(byte[] X ){





//        byte[][] ZArray = new byte[129][16];
//        ZArray[0]=new byte[16];
        byte[] Y0 = new byte[16];
        for (int i = 0; i < 128; i++) {

            /**
             * 1.用位移直接计算出x每一比特位
             * 2.Y128直接用Y0循环异或取最后一个Y0
             * 旧代码
             *         计算X的每一比特位极其耗时（优化后提速96%）
             *         byte[] XBiteArray =null;
             *         for (byte b:X) {
             *             byte[] bytes = DataConvertUtil.byteToBitArray(b);
             *             XBiteArray = DataConvertUtil.byteArrAdd(XBiteArray, bytes);
             *         }
             *
             *             if(XBiteArray[i]==0){
             *                 ZArray[i+1]=ZArray[i];
             *
             *             }else
             *             {
             *                 ZArray[i+1]=DataConvertUtil.byteArrayXOR(ZArray[i],VBox[i]);
             *             }
             */
            if((byte)((X[i/8] >> 7-i%8) & 0x1)==1){
//                Y0=DataConvertUtil.byteArrayXOR(Y0,VBox[i]);
                DataConvertUtil.fastByteArrayXOR(Y0,VBox[i]);
            }

        }
//        return ZArray[128];
        return Y0;

    }

    public static void main1(String[] args) {

//        //System.out.println("/****************************byteArrayMultiplePoint***************************************/");
//        byte[] ghash_key=Hex.decode("00BA5F76F3D8982B199920E3221ED05F");
//        byte[] ghash_ivin =Hex.decode("384C3CEDE5CBC5560F002F94A8E4205A");
//        byte[] ghash_din =Hex.decode("3BEA3321BDA9EBF02D5459BCE4295E3A");
//
//        SM4Cipher sm4Cipher = new SM4Cipher();
//        sm4Cipher.byteArrayMultiplePoint(DataConvertUtil.byteArrayXOR(ghash_din,ghash_ivin),ghash_key);
//
//
//
////            GCMUtil.multiply(bytes,H);
////            Y0=bytes;
//        Tables4kGCMMultiplier tables4kGCMMultiplier = new Tables4kGCMMultiplier();
//        tables4kGCMMultiplier.init(DataConvertUtil.byteArrayXOR(ghash_din,ghash_ivin));
////            GCMUtil.xor(Y0, blockX[i - 1]);
////            //System.out.println("YO:"+Hex.toHexString(Y0));
//        //System.out.println("-----------");
//        //System.out.println(Hex.toHexString(ghash_key));
//            tables4kGCMMultiplier.multiplyH(ghash_key);
//        //System.out.println("@@"+Hex.toHexString(ghash_key));
//        //System.out.println("/****************************byteArrayMultiplePoint***************************************/");



    }


    private void initVBox(byte[] H){
        /**初始化VBox*/
        byte[] R = DataConvertUtil.byteArrAdd(new byte[]{(byte) 225},new byte[15]);
        VBox[0]=H;
        for (int i = 0; i < 128; i++) {
            byte b = (DataConvertUtil.byteToBitArray(VBox[i][15]))[7];
            if(b==0){
                VBox[i+1]=DataConvertUtil.byteArrayRight(VBox[i],1);
            }
            if(b==1){
                byte[] tempRight = DataConvertUtil.byteArrayRight(VBox[i], 1);
                VBox[i+1]=DataConvertUtil.byteArrayXOR(tempRight,R);
            }

        }
    }
    private byte[] GHASH(byte[] X,byte[] H){
        if(X.length%16!=0){
            throw new  RuntimeException("X.length%16!=0");
        }

        byte[][] blockX = block(X);
        long m = X.length/16;
        byte[] Y0 = new byte[16];
        Tables4kGCMMultiplier tables4kGCMMultiplier = new Tables4kGCMMultiplier();
        tables4kGCMMultiplier.init(H);
        for (int i = 1; i <= m; i++) {
            DataConvertUtil.fastByteArrayXOR(Y0,blockX[i-1]);
            Y0=byteArrayMultiplePoint(Y0);

            //--------------------------------------------------------
//            byte[] bytes = DataConvertUtil.byteArrayXOR(Y0, blockX[i - 1]);
//            //System.out.println("bytes:"+Hex.toHexString(bytes));
////            GCMUtil.multiply(bytes,H);
////            Y0=bytes;
//
            //            //System.out.println("YO:"+Hex.toHexString(Y0));

//            GCMUtil.xor(Y0, blockX[i - 1]);
//            tables4kGCMMultiplier.multiplyH(Y0);

            //--------------------------------------------------------

        }
        return Y0;
    }

    private  byte[] GCTR(byte[] ICB,byte[] X,byte[][] rks){
        if (DEBUG)System.out.println("ICB:"+new BigInteger(ICB));
        if(X==null){
            return null;
        }
        long n = (X.length/16);
        if(X.length%16!=0){
            n++;
        }
        long l = System.currentTimeMillis();

        byte[][] blockX = block(X);
        if(TIME){
            System.out.println("--GCTR blockX:"+ (System.currentTimeMillis()-l));
            l = System.currentTimeMillis();
        }
//        byte[][] CBArray = new byte[blockX.length+1][16];

        byte[][] YArray = new byte[(int) n][16];


//        CBArray[1]=ICB;
//        for (int i = 2; i <= n; i++) {
//            //todo inc
//            CBArray[i]=byteArrAdd(CBArray[i-1]);
//        }
//        for (int i = 1; i <= n - 1; i++) {
//            YArray[i]=DataConvertUtil.byteArrayXOR(blockX[i],cipher(CBArray[i+1],rks));
//        }


        ////System.out.println(processors);
        if (blockX.length < processors) {
            processors = blockX.length;
        }
        /**
         * 2  3140
         * 3  2540
         * 4  2229
         * 5  1963
         * 7  1892  1975 1894
         * 8  1814  1786 1811 1746 1745 1758 1799 1818 1880 2390
         * 9  1894  1823 1805 1841 1743 1806 1818 1822
         * 10 1900
         * 14 1898 2092
         * 17 1859 1854 1831 1806 1842
         */
        //确定每个线程处理的数据量
        long size = blockX.length / processors;
        //确定最后一个线程处理的数据量
        long remainder = blockX.length % processors;
        CountDownLatch countDownLatch = new CountDownLatch(processors);
        for (int j = 0; j < processors; j++) {
            if(DEBUG) {
                System.out.println("外i:" + j);
                System.out.println("外size:" + size);
                System.out.println("外processors:" + processors);
            }
            long start = j * size;
            long end = (j + 1) * size;
            if (j == processors - 1) {


                end += remainder;
            }
            long finalEnd = end;
            long finalStart = start;
            //todo iv计算可能有问题
            byte[] finalIv = byteArrAdd(ICB,start);
            threadPoolExecutor.execute(new Runnable() {
                @Override
                public void run() {

                    byte[] startIv = finalIv;
                    //System.out.println(Thread.currentThread().getName()+"start:"+finalStart+" end:"+ finalEnd + " count:"+(finalEnd-finalStart));
                    for (int i = (int) finalStart; i < finalEnd; i++) {


                        byte[] cipher = cipher(startIv, rks);

                        if(DEBUG){
                            System.out.println(Thread.currentThread().getName()+"--i:"+i);
                            System.out.println(Thread.currentThread().getName()+"--finalStart:"+finalStart);
                            System.out.println(Thread.currentThread().getName()+"--startIv:"+new BigInteger(startIv));
                            System.out.println(Thread.currentThread().getName()+"--cipher:"+Hex.toHexString(cipher));
                            System.out.println(Thread.currentThread().getName()+"--blockX[i]:"+Hex.toHexString(blockX[i]));
                        }

                        if(blockX[i].length!=cipher.length){
                            if (DEBUG) System.out.println(Thread.currentThread().getName()+"###last--cipher:"+Hex.toHexString(cipher));
                            if (DEBUG) System.out.println(Thread.currentThread().getName()+"###last--blockX[i]:"+Hex.toHexString(blockX[i]));
                            byte[] tempCipher = new byte[blockX[i].length];
                            System.arraycopy(cipher,0,tempCipher,0,blockX[i].length);
                            cipher=tempCipher;
                            if (DEBUG) System.out.println(Thread.currentThread().getName()+"###last--tempCipher:"+Hex.toHexString(tempCipher));
                        }
                        YArray[i]=DataConvertUtil.byteArrayXOR(blockX[i],cipher);
                        if(DEBUG) System.out.println(Thread.currentThread().getName()+"--YArray[i]:"+Hex.toHexString(YArray[i]));
                        startIv=byteArrAdd(startIv);
                        //System.out.println(i+"分块加密耗时："+(System.currentTimeMillis()-l2));
                    }
                    countDownLatch.countDown();
                }
            });
        }
        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        threadPoolExecutor.shutdown();
        if(TIME){
            System.out.println("--GCTR cipher:"+(System.currentTimeMillis()-l));
        }





//        long length = blockX[n-1].length;
//        byte[] cipherCbN = cipher(CBArray[(int) n], rks);
//        byte[] cipherCbN1 = new byte[length];
//        System.arraycopy(cipherCbN, 0, cipherCbN1, 0, length);
//        YArray[n-1]=DataConvertUtil.byteArrayXOR(blockX[ n-1],cipherCbN1);

        return DataConvertUtil.byteArrAdd(YArray);

    }

    //GCM加密
    public AEADExecution cipherEncryptGCM(byte[]key,byte[] ming , byte[] iv, byte[] aad, int tagLen){
        long l = System.currentTimeMillis();
        byte[][] rks = ext_key_L(key);
        if (TIME) {
            System.out.println("ext_key_L:"+(System.currentTimeMillis()-l));
            l=System.currentTimeMillis();
        }
        byte[] H = cipher(new byte[16], rks);
        if (DEBUG) System.out.println("H:"+Hex.toHexString(H));
        if (TIME) {
            System.out.println("generateH:"+(System.currentTimeMillis()-l));
            l=System.currentTimeMillis();
        }
        initVBox(H);
        if (TIME) {
            System.out.println("initVBox:"+(System.currentTimeMillis()-l));

        }
        byte[] J0 ;
        if(iv.length==12){
            J0 = DataConvertUtil.byteArrAdd(iv, new byte[]{0x00,0x00,0x00,0x01});
        }else {
            long s1 = (iv.length/16);
            if(iv.length%16!=0){
                s1++;
            }
            long s = 16*s1-iv.length;

            J0 = GHASH(DataConvertUtil.byteArrAdd(iv,new byte[(int) s+8],DataConvertUtil.byteToN(DataConvertUtil.intToBytes(iv.length),8)),H);
        }
        l=System.currentTimeMillis();
        byte[] C = GCTR(byteArrAdd(J0),ming,rks);
        if(DEBUG) System.out.println("C hex:"+Hex.toHexString(C));

        if (TIME) {
            System.out.println("GCTR C:"+(System.currentTimeMillis()-l));
            l=System.currentTimeMillis();
        }

        int ceilC = (int) Math.ceil(C.length/16.0);
        int ceilAad = (int) Math.ceil(aad.length/16.0);

        byte[] u = 16 * ceilC - C.length == 0 ? null : new byte[16 * ceilC - C.length];
        byte[] v = 16 * ceilAad - aad.length == 0 ? null : new byte[16 * ceilAad - aad.length];

        byte[] S = GHASH(DataConvertUtil.byteArrAdd(aad,v,C,u,DataConvertUtil.byteToN(DataConvertUtil.intToBytes(8*aad.length),8),DataConvertUtil.byteToN(DataConvertUtil.intToBytes(8*C.length),8)),H);

        if(TIME){
            System.out.println("GHASH S:"+(System.currentTimeMillis()-l));
            l=System.currentTimeMillis();
        }


        byte[] T = new byte[tagLen];
        System.arraycopy(GCTR(J0,S,rks),0,T,0,tagLen);

        if(TIME){
            System.out.println("GCTR T:"+(System.currentTimeMillis()-l));
        }

        return new AEADExecution(C,T);
    }
    public byte[] cipherDecryptGCM(byte[] key,byte[] mi, byte[] iv, byte[] aad, byte[] tag){
        byte[][] rks = ext_key_L(key);
        byte[] H = cipher(new byte[16], rks);
        initVBox(H);
        byte[] J0 ;
        if(iv.length==12){
            J0 = DataConvertUtil.byteArrAdd(iv, new byte[]{0x00,0x00,0x00,0x01});
        }else {
            long s1 = (iv.length/16);
            if(iv.length%16!=0){
                s1++;
            }
            long s = 16*s1-iv.length;
            J0 = GHASH(DataConvertUtil.byteArrAdd(iv,new byte[(int) s+8],DataConvertUtil.byteToN(DataConvertUtil.intToBytes(iv.length),8)),H);
        }
        byte[] P =  GCTR(byteArrAdd(J0),mi,rks);
        int ceilC = (int) Math.ceil(mi.length/16.0);
        int ceilAad = (int) Math.ceil(aad.length/16.0);
        byte[] u = 16 * ceilC - mi.length == 0 ? null : new byte[16 * ceilC - mi.length];
        byte[] v = 16 * ceilAad - aad.length == 0 ? null : new byte[16 * ceilAad - aad.length];

        byte[] S = GHASH(DataConvertUtil.byteArrAdd(aad,v,mi,u,DataConvertUtil.byteToN(DataConvertUtil.intToBytes(aad.length*8),8),DataConvertUtil.byteToN(DataConvertUtil.intToBytes(mi.length*8),8)),H);
        byte[] T = new byte[tag.length];
        System.arraycopy(GCTR(J0,S,rks),0,T,0,tag.length);
        if(!Arrays.equals(T,tag)){
            throw new RuntimeException("tag不匹配");
        }
        return P;
    }






}
