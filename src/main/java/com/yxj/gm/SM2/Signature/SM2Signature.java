package com.yxj.gm.SM2.Signature;

import com.yxj.gm.SM2.Key.SM2;
import com.yxj.gm.SM3.SM3;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;

import java.math.BigInteger;

import static com.yxj.gm.SM2.Key.SM2.MultiplePointOperation;
import static com.yxj.gm.SM2.Key.SM2.PointAdditionOperation;


public class SM2Signature {

    byte[] Za;
    byte[] Xa;
    byte[] Ya;
    //TODO DEBUG parameter
    private byte[] se;
    private byte[] sr;
    private byte[] ve;
    private byte[] vr;

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
        // System.out.println("IDa hex");
        // System.out.println(Hex.toHexString(IDa));
        // System.out.println(IDa.length);
        Short ENTLa  = (short) (IDa.length*8);
        byte[] ENTLaBytes = DataConvertUtil.shortToBytes(new short[]{ENTLa});
        byte[] ta = DataConvertUtil.oneDel(SM2Constant.getA());
        byte[] tb = DataConvertUtil.oneDel(SM2Constant.getB());
        byte[] txg = DataConvertUtil.oneDel(SM2Constant.getXG());
        byte[] tyg = DataConvertUtil.oneDel(SM2Constant.getYG());

        byte[] ZaMsg = new byte[ENTLaBytes.length+IDa.length+ta.length+tb.length+txg.length+tyg.length+Xa.length+Ya.length];
        byte[][] ZaByteS = new byte[][]{ENTLaBytes,IDa,ta,tb,txg,tyg,Xa,Ya};
        int index=0;
        // System.out.println("-------------------------------------------------拼接数据------------------------------------------------------------------------------------");
        for (int i = 0; i < ZaByteS.length; i++) {
            System.arraycopy(ZaByteS[i],0,ZaMsg,index,ZaByteS[i].length);
            index+=ZaByteS[i].length;
            // System.out.println(Hex.toHexString(ZaByteS[i]));
        }
        // System.out.println("-------------------------------------------------拼接数据------------------------------------------------------------------------------------");
        // System.out.println("ZaMsg");
        // System.out.println(Hex.toHexString(ZaMsg));
        SM3 sm3 = new SM3();
        sm3.update(ZaMsg);

        Za = sm3.doFinal();

        // System.out.println("计算Za：");
        // System.out.println(Hex.toHexString(Za));
        // System.out.println(Za.length*8);
    }

    private byte[][] internalSignature(byte[] msg,byte[] dA){
        byte[] M_= new byte[Za.length+msg.length];
        System.arraycopy(Za,0,M_,0,Za.length);
        System.arraycopy(msg,0,M_,Za.length,msg.length);
        // System.out.println("签名 msg");
        // System.out.println(Hex.toHexString(msg));
        // System.out.println("M_");
        // System.out.println(Hex.toHexString(M_));
        SM3 sm3 = new SM3();
        sm3.update(M_);
        byte[] e = sm3.doFinal();
        this.se=e;
        // System.out.println("e");
        // System.out.println(Hex.toHexString(e));
        //转biginteger之前补0
        e=DataConvertUtil.oneAdd(e);
        // System.out.println(Hex.toHexString(e));
        BigInteger bigE = new BigInteger(e);
        // System.out.println("bigE");
        // System.out.println(bigE);
        BigInteger bigN = new BigInteger(SM2Constant.getN());
        // System.out.println("N");
        // System.out.println(Hex.toHexString(SM2Constant.getN()));
        BigInteger r = new BigInteger("0");
        byte[] k =new byte[32];
        while (r.compareTo(new BigInteger("0"))==0||bigN.compareTo(r.add(new BigInteger(k)))==0){
            byte[][] keyPairBytes = SM2.generatePubKey();
            k=keyPairBytes[0];
            byte[][] bytes = new byte[2][32];
            bytes[0]=keyPairBytes[1];
            bytes[1]=keyPairBytes[2];
//            new SecureRandom().nextBytes(k);
            k=DataConvertUtil.oneAdd(k);

            // System.out.println("倍点运算x1");
            // System.out.println(Hex.toHexString(bytes[0]));
            // 倍点运算出来的x1需要补0
            BigInteger bigx1 = new BigInteger(DataConvertUtil.oneAdd(bytes[0]));


            BigInteger r1=bigE.add(bigx1);
            r = r1.mod(bigN);
            // System.out.println("r");
            // System.out.println(Hex.toHexString(r.toByteArray()));
        }
        //TODO 如果是生成的密钥k，则需要补0
        BigInteger bigK = new BigInteger(k);
        //TODO 如果是传过来的A的私钥，则需要补0
        dA=DataConvertUtil.oneAdd(dA);
        BigInteger bigDa = new BigInteger(dA);
        BigInteger ts0=new BigInteger("1").add(bigDa);
        ts0=ts0.mod(bigN);
        BigInteger ts1 = DataConvertUtil.ex_gcd_ny(ts0, bigN);
        ts1=ts1.mod(bigN);
        // System.out.println("1+Da逆元：");
        // System.out.println(Hex.toHexString(ts1.toByteArray()));

        BigInteger ts2 = r.multiply(bigDa);
        ts2=ts2.mod(bigN);
        BigInteger ts3 = bigK.subtract(ts2);
        ts3=ts3.mod(bigN);
        BigInteger s =ts1.multiply(ts3);
        s=s.mod(bigN);
        // System.out.println("s");
        // System.out.println(Hex.toHexString(s.toByteArray()));
        byte[] rbytes = r.toByteArray();
        byte[] sbytes = s.toByteArray();
        rbytes=DataConvertUtil.byteToN(rbytes,32);
        sbytes=DataConvertUtil.byteToN(sbytes,32);
        byte[][] rs = new byte[][]{rbytes,sbytes};
        this.sr=rbytes;
        return rs;
    }

    private boolean internalVerify(byte[] M,byte[][] rs){

        byte[] radd = DataConvertUtil.oneAdd(rs[0]);
        byte[] sadd = DataConvertUtil.oneAdd(rs[1]);
        byte[] paxadd = DataConvertUtil.oneAdd(Xa);
        byte[] payadd = DataConvertUtil.oneAdd(Ya);
        byte[] M_= new byte[Za.length+M.length];

        System.arraycopy(Za,0,M_,0,Za.length);
        System.arraycopy(M,0,M_,Za.length,M.length);
        // System.out.println("验签 M");
        // System.out.println(Hex.toHexString(M));
        // System.out.println("验签 M_");
        // System.out.println(Hex.toHexString(M_));
        SM3 sm3 = new SM3();
        sm3.update(M_);
        byte[] e = sm3.doFinal();
        this.ve=e;
        // System.out.println("验签 e");
        // System.out.println(Hex.toHexString(e));
        BigInteger bigE = new BigInteger(DataConvertUtil.oneAdd(e));
        BigInteger bigR = new BigInteger(radd);
        BigInteger bigS = new BigInteger(sadd);
        BigInteger bigT = bigR.add(bigS);
        bigT=bigT.mod(new BigInteger(SM2Constant.getN()));
        if(bigT.compareTo(new BigInteger("0"))==0){
            return false;
        }
        // System.out.println("验签 t");
        // System.out.println(Hex.toHexString(bigT.toByteArray()));
        byte[][] temp1 = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), sadd, SM2Constant.getA(), SM2Constant.getP());
        byte[][] temp2 = MultiplePointOperation(paxadd, payadd, bigT.toByteArray(), SM2Constant.getA(), SM2Constant.getP());
        byte[] x1 = DataConvertUtil.oneAdd(temp1[0]);
        byte[] y1 = DataConvertUtil.oneAdd(temp1[1]);
        // System.out.println("验签 x1G");
        // System.out.println(Hex.toHexString(x1));
        // System.out.println("验签 y1G");
        // System.out.println(Hex.toHexString(y1));

        byte[] x2 = DataConvertUtil.oneAdd(temp2[0]);
        byte[] y2 = DataConvertUtil.oneAdd(temp2[1]);
        // System.out.println("验签 x2PA");
        // System.out.println(Hex.toHexString(x2));
        // System.out.println("验签 x2PA");
        // System.out.println(Hex.toHexString(y2));

        byte[][] temp3 = PointAdditionOperation(x1, y1, x2, y2, SM2Constant.getA(), SM2Constant.getP());
        byte[] x1_=DataConvertUtil.oneAdd(DataConvertUtil.byteToN(temp3[0],32));
        // System.out.println("验签 x1相加");
        // System.out.println(Hex.toHexString(x1_));

        BigInteger bigX1_=new BigInteger(x1_);
        BigInteger R = bigE.add(bigX1_);


        R=R.mod(new BigInteger(SM2Constant.getN()));
        // System.out.println("验签 R");
        // System.out.println(Hex.toHexString(R.toByteArray()));
        this.vr=R.toByteArray();
        return R.compareTo(bigR) == 0;
    }

    public byte[] signature(byte[] msg,byte[] id,byte[] priKey){

        byte[][] puba = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), priKey, SM2Constant.getA(), SM2Constant.getP());
        // System.out.println("签名生成的公钥");
        // System.out.println(Hex.toHexString(puba[0]));
        // System.out.println(Hex.toHexString(puba[1]));
//        byte[] pubKey = new byte[64];
//        sm2Signature.initXaYa();
        Xa=puba[0];
        Ya=puba[1];
        initZa(id);
        byte[][] bytes = internalSignature(msg, priKey);
        byte[] temp = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,temp,0,bytes[0].length);
        System.arraycopy(bytes[1],0,temp,bytes[0].length,bytes[1].length);
        return temp;
    }
    public  boolean verify(byte[] msg,byte[] id,byte[] signature,byte[] pubKey){
        // System.out.println(signature.length);
        initXaYa(pubKey);
        initZa(id);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature,0,r,0,32);
        System.arraycopy(signature,32,s,0,32);
        return internalVerify(msg,new byte[][]{r,s});
    }
    public static void main(String[] args) {

//
////        sm2Signature.initXaYa(SM2Constant.getdA());
//        sm2Signature.initZa("ALICE123@YAHOO.COM".getBytes());
//        byte[][] rs = sm2Signature.signature("message digest".getBytes(), SM2Constant.getdA());
//
//        // System.out.println(sm2Signature.verify("message digest".getBytes(),rs,new byte[][]{SM2Constant.getxA(),SM2Constant.getyA()}));


    }



}
