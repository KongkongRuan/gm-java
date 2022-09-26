package com.yxj.gm.SM2.Signature;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;



public class SM2Signature {

    byte[] Za;
    byte[] Xa;
    byte[] Ya;


    private void initXaYa(byte[] pubKey){
        Xa = new byte[32];
        Ya = new byte[32];
        System.arraycopy(pubKey,0,Xa,0,32);
        System.arraycopy(pubKey,32,Ya,0,32);
    }

    private void initZa(byte[] IDa){
        if(IDa==null){
            IDa="1234567812345678".getBytes();
        }
        short ENTLa  = (short) (IDa.length*8);
        byte[] ENTLaBytes = DataConvertUtil.shortToBytes(new short[]{ENTLa});
        byte[] ta = DataConvertUtil.oneDel(SM2Constant.getA());
        byte[] tb = DataConvertUtil.oneDel(SM2Constant.getB());
        byte[] txg = DataConvertUtil.oneDel(SM2Constant.getXG());
        byte[] tyg = DataConvertUtil.oneDel(SM2Constant.getYG());

        byte[] ZaMsg = new byte[ENTLaBytes.length+IDa.length+ta.length+tb.length+txg.length+tyg.length+Xa.length+Ya.length];
        byte[][] ZaByteS = new byte[][]{ENTLaBytes,IDa,ta,tb,txg,tyg,Xa,Ya};
        int index=0;
        for (byte[] zaByte : ZaByteS) {
            System.arraycopy(zaByte, 0, ZaMsg, index, zaByte.length);
            index += zaByte.length;
        }
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(ZaMsg);

        Za = sm3Digest.doFinal();

    }

    private byte[][] internalSignature(byte[] msg,byte[] dA){
        byte[] M_= new byte[Za.length+msg.length];
        System.arraycopy(Za,0,M_,0,Za.length);
        System.arraycopy(msg,0,M_,Za.length,msg.length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(M_);
        byte[] e = sm3Digest.doFinal();
        //转biginteger之前补0
        e=DataConvertUtil.oneAdd(e);
        BigInteger bigE = new BigInteger(e);
        BigInteger bigN = new BigInteger(SM2Constant.getN());
        BigInteger r = new BigInteger("0");
        byte[] k =new byte[32];
        while (r.compareTo(new BigInteger("0"))==0||bigN.compareTo(r.add(new BigInteger(k)))==0){
            byte[][] keyPairBytes = SM2Util.generatePubKey();
            k=keyPairBytes[0];
            byte[][] bytes = new byte[2][32];
            bytes[0]=keyPairBytes[1];
            bytes[1]=keyPairBytes[2];
            k=DataConvertUtil.oneAdd(k);

            // 倍点运算出来的x1需要补0
            BigInteger bigx1 = new BigInteger(DataConvertUtil.oneAdd(bytes[0]));


            BigInteger r1=bigE.add(bigx1);
            r = r1.mod(bigN);

        }
        // 如果是生成的密钥k，则需要补0
        BigInteger bigK = new BigInteger(k);
        // 如果是传过来的A的私钥，则需要补0
        dA=DataConvertUtil.oneAdd(dA);
        BigInteger bigDa = new BigInteger(dA);
        BigInteger ts0=new BigInteger("1").add(bigDa);
        ts0=ts0.mod(bigN);
        BigInteger ts1 = DataConvertUtil.ex_gcd_ny(ts0, bigN);
        ts1=ts1.mod(bigN);

        BigInteger ts2 = r.multiply(bigDa);
        ts2=ts2.mod(bigN);
        BigInteger ts3 = bigK.subtract(ts2);
        ts3=ts3.mod(bigN);
        BigInteger s =ts1.multiply(ts3);
        s=s.mod(bigN);
        byte[] rbytes = r.toByteArray();
        byte[] sbytes = s.toByteArray();
        rbytes=DataConvertUtil.byteToN(rbytes,32);
        sbytes=DataConvertUtil.byteToN(sbytes,32);
        return new byte[][]{rbytes,sbytes};
    }

    private boolean internalVerify(byte[] M,byte[][] rs){

        byte[] radd = DataConvertUtil.oneAdd(rs[0]);
        byte[] sadd = DataConvertUtil.oneAdd(rs[1]);
        byte[] paxadd = DataConvertUtil.oneAdd(Xa);
        byte[] payadd = DataConvertUtil.oneAdd(Ya);
        byte[] M_= new byte[Za.length+M.length];

        System.arraycopy(Za,0,M_,0,Za.length);
        System.arraycopy(M,0,M_,Za.length,M.length);

        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(M_);
        byte[] e = sm3Digest.doFinal();
        BigInteger bigE = new BigInteger(DataConvertUtil.oneAdd(e));
        BigInteger bigR = new BigInteger(radd);
        BigInteger bigS = new BigInteger(sadd);
        BigInteger bigT = bigR.add(bigS);
        bigT=bigT.mod(new BigInteger(SM2Constant.getN()));
        if(bigT.compareTo(new BigInteger("0"))==0){
            return false;
        }

        byte[][] temp1 = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), sadd, SM2Constant.getA(), SM2Constant.getP());
        byte[][] temp2 = SM2Util.MultiplePointOperation(paxadd, payadd, bigT.toByteArray(), SM2Constant.getA(), SM2Constant.getP());
        byte[] x1 = DataConvertUtil.oneAdd(temp1[0]);
        byte[] y1 = DataConvertUtil.oneAdd(temp1[1]);


        byte[] x2 = DataConvertUtil.oneAdd(temp2[0]);
        byte[] y2 = DataConvertUtil.oneAdd(temp2[1]);


        byte[][] temp3 = SM2Util.PointAdditionOperation(x1, y1, x2, y2, SM2Constant.getA(), SM2Constant.getP());
        byte[] x1_=DataConvertUtil.oneAdd(DataConvertUtil.byteToN(temp3[0],32));

        BigInteger bigX1_=new BigInteger(x1_);
        BigInteger R = bigE.add(bigX1_);


        R=R.mod(new BigInteger(SM2Constant.getN()));
        return R.compareTo(bigR) == 0;
    }

    public byte[] signature(byte[] msg,byte[] id,byte[] priKey){

        byte[][] puba = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), priKey, SM2Constant.getA(), SM2Constant.getP());
        Xa=puba[0];
        Ya=puba[1];
        initZa(id);
        byte[][] bytes = internalSignature(msg, priKey);
        byte[] temp = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,temp,0,bytes[0].length);
        System.arraycopy(bytes[1],0,temp,bytes[0].length,bytes[1].length);
        return temp;
    }
    public byte[] signatureByHSM(byte[] msg,int index){
        return new byte[0];
    }
    public  boolean verify(byte[] msg,byte[] id,byte[] signature,byte[] pubKey){
        initXaYa(pubKey);
        initZa(id);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature,0,r,0,32);
        System.arraycopy(signature,32,s,0,32);
        return internalVerify(msg,new byte[][]{r,s});
    }



}
