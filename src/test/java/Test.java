

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2;
import com.yxj.gm.SM2.Signature.SM2Signature;
import org.bouncycastle.util.encoders.Hex;
import java.security.KeyPair;
public class Test {
    public static void main(String[] args) {
        String msg = "message digest";
        System.out.println("密钥生成");
        KeyPair keyPair = SM2.generateSM2KeyPair();
        System.out.println("公钥："+Hex.toHexString(keyPair.getPublic().getEncoded()));
        System.out.println("私钥："+Hex.toHexString(keyPair.getPrivate().getEncoded()));
        System.out.println("签名验签测试");
            SM2Signature sm2Signature = new SM2Signature();
            byte[] signature = sm2Signature.signature(msg.getBytes(), null, keyPair.getPrivate().getEncoded());
            SM2Signature sm2Verify = new SM2Signature();
            boolean verify = sm2Verify.verify(msg.getBytes(), null, signature, keyPair.getPublic().getEncoded());
            if(!verify){
                System.err.println("错误");
            }else {
                System.out.println("java 验签通过");
            }

        System.out.println("加解密测试");
        SM2Cipher sm2Cipher = new SM2Cipher();
        byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), keyPair.getPublic().getEncoded());
        System.out.println("java加密后密文："+Hex.toHexString(mi));
        byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, keyPair.getPrivate().getEncoded());
        System.out.println("java解密后明文："+new String(ming));
    }

//    public static void main(String[] args) {
//        int sum = 100;
//        String msg = "message digest";
//        int javacount =0;
//        int ccount = 0;
//        int count = 0;
//        KeyPair keyPair = SM2.generateSM2KeyPair();
//        System.out.println("公钥："+Hex.toHexString(keyPair.getPublic().getEncoded()));
//        System.out.println("私钥："+Hex.toHexString(keyPair.getPrivate().getEncoded()));
//
//
//        /*******************************************************************************************测速*****************************************************************/
//            byte[] priKey = Hex.decode("DE960E60B70E61CF9F567D08544C488D1DBDE06603F1999DBD1B6BC85DD3283E");
//            byte[] pubkey = Hex.decode("51E3B4E62B8B63CAD2ABC65302E88E542DF0EEFA6913E78B3AFCFDFEB1CB926801C6676BF71A85059AD83A266E1D641B8D69F3EDEE0B524D18154FBD19BD4214");
//            KeyPair keyPair1 = new KeyPair(new SM2PublicKey(pubkey),new SM2PrivateKey(priKey));
//        long start = System.currentTimeMillis();
//        for (int i = 0; i < sum; i++) {
//            SM2Signature sm2Signature = new SM2Signature();
//            byte[] signature = sm2Signature.signature(msg.getBytes(), null, priKey);
////            SM2Signature sm2Verify = new SM2Signature();
////            boolean verify = sm2Verify.verify(msg.getBytes(), null, signature, pubkey);
////            if(!verify){
////                System.err.println("错误");
////            }
//        }
//        System.out.println("JAVA签名:"+(System.currentTimeMillis()-start));
//
//
////         start = System.currentTimeMillis();
////        for (int i = 0; i < sum; i++) {
////
////            UseKey useKey = new UseKey();
////            byte[] signature = useKey.signature(keyPair1,msg.getBytes());
//////
//////            boolean verify = useKey.verifySignature(keyPair1.getPublic(), msg.getBytes(), signature);
//////            if(!verify){
//////                System.err.println("错误");
//////            }
////        }
////        System.out.println("C签名:"+(System.currentTimeMillis()-start));
//
//
//         start = System.currentTimeMillis();
//        SM2Signature sm2Signature = new SM2Signature();
//        byte[] signature = sm2Signature.signature(msg.getBytes(), null, priKey);
//        for (int i = 0; i < sum; i++) {
//            SM2Signature sm2Verify = new SM2Signature();
//            boolean verify = sm2Verify.verify(msg.getBytes(), null, signature, pubkey);
//            if(!verify){
//                System.err.println("错误");
//            }
//        }
//        System.out.println("JAVA验签:"+(System.currentTimeMillis()-start));
//
////        start = System.currentTimeMillis();
////        UseKey useKey = new UseKey();
////         signature = useKey.signature(keyPair1,msg.getBytes());
////        for (int i = 0; i < sum; i++) {
////            boolean verify = useKey.verifySignature(keyPair1.getPublic(), msg.getBytes(), signature);
////            if(!verify){
////                System.err.println("错误");
////            }
////        }
////        System.out.println("C验签:"+(System.currentTimeMillis()-start));
//        /*******************************************************************************************测速*****************************************************************/
//
/////*******************************************************************************************正确性验证*****************************************************************/
////        for (int i = 0; i < 1000; i++) {
////            // System.out.println("*****************************************************************************************开始****************************************************************************************************************");
////            SM2Signature sm2Signature = new SM2Signature();
////            UseKey useKey = new UseKey();
//////            byte[] priKey = Hex.decode("DE960E60B70E61CF9F567D08544C488D1DBDE06603F1999DBD1B6BC85DD3283E");
//////            byte[] pubkey = Hex.decode("51E3B4E62B8B63CAD2ABC65302E88E542DF0EEFA6913E78B3AFCFDFEB1CB926801C6676BF71A85059AD83A266E1D641B8D69F3EDEE0B524D18154FBD19BD4214");
//////            KeyPair keyPair1 = new KeyPair(new ZyxxPublicKey(pubkey),new ZyxxPrivateKey(priKey));
////
////            KeyPair keyPair1 = SM2.generateSM2KeyPair();
////
////            // // System.out.println("生成的公钥："+Hex.toHexString(keyPair1.getPublic().getEncoded()));
////            // // System.out.println("生成的私钥："+Hex.toHexString(keyPair1.getPrivate().getEncoded()));
////             // System.out.println("**************************************************JAVA签名********************************************************************************************");
////            byte[] signature = sm2Signature.signature(msg.getBytes(), null, keyPair1.getPrivate().getEncoded());
////            // // System.out.println("java signature HEX:"+Hex.toHexString(signature));
////            // // System.out.println(signature.length);
////
////             // System.out.println("**************************************************JAVA签名组件化验签********************************************************************************************");
////            boolean b = useKey.verifySignature(keyPair1.getPublic(), msg.getBytes(), signature);
////            if(b){
////                ccount++;
////            }
////            else {
////                System.err.println("**************************************************JAVA签名组件化验签********************************************************************************************");
////                System.err.println("java签名C验签失败");
////                 System.err.println("生成的公钥："+Hex.toHexString(keyPair1.getPublic().getEncoded()));
////                 System.err.println("生成的私钥："+Hex.toHexString(keyPair1.getPrivate().getEncoded()));
////            }
////            // // System.out.println(b);
////            SM2Signature sm2Verify = new SM2Signature();
////
////             // System.out.println("**************************************************JAVA签名JAVA验签********************************************************************************************");
////            // // System.out.println();
////            boolean javaB = sm2Verify.verify(msg.getBytes(), null, signature, keyPair1.getPublic().getEncoded());
////            if(javaB){
////                javacount++;
////            }
////            else {
////                 System.err.println("**************************************************JAVA验签失败********************************************************************************************");
////                System.err.println("java签名java验签失败");
////                System.err.println("生成的公钥："+Hex.toHexString(keyPair1.getPublic().getEncoded()));
////                System.err.println("生成的私钥："+Hex.toHexString(keyPair1.getPrivate().getEncoded()));
////            }
////
////            byte[] signature1 = useKey.signature(keyPair1, msg.getBytes());
////            sm2Verify = new SM2Signature();
////            boolean verify = sm2Verify.verify(msg.getBytes(), null, signature1, keyPair1.getPublic().getEncoded());
////            if(verify){
////                count++;
////            }else {
////                 System.err.println("**************************************************C签名JAVA验签********************************************************************************************");
////                System.err.println("C签名java验签失败");
////                System.err.println("生成的公钥："+Hex.toHexString(keyPair1.getPublic().getEncoded()));
////                System.err.println("生成的私钥："+Hex.toHexString(keyPair1.getPrivate().getEncoded()));
////                System.err.println("c验签");
////                boolean b1 = useKey.verifySignature(keyPair1.getPublic(), msg.getBytes(), signature1);
////                System.out.println("b1:"+b1);
////            }
////             System.out.println("java签名C验签："+ccount+"--java签名java验签："+javacount+"--C签名java验签："+count+"--总数："+(i+1));
////
////        }
////
////        /*******************************************************************************************正确性验证*****************************************************************/
//
//    }



//    public static void main(String[] args) {
//        String msg = "message digest";
//
//        SM2Signature sm2Signature = new SM2Signature();
//        UseKey useKey = new UseKey();
//        byte[] pubKey = new byte[64];
//        System.arraycopy(DataConvertUtil.oneDel(SM2Constant.getxA()),0,pubKey,0,32);
//        System.arraycopy(DataConvertUtil.oneDel(SM2Constant.getyA()),0,pubKey,32,32);
//
////        KeyPair keyPair1 = SM2.generateSM2KeyPair();
//
//        // // System.out.println("**************************************************JAVA签名********************************************************************************************");
//        byte[] signature = sm2Signature.signature(msg.getBytes(), "ALICE123@YAHOO.COM".getBytes(), SM2Constant.getdA());
//        // // System.out.println("java signature HEX:"+Hex.toHexString(signature));
//        // // System.out.println(signature.length);
//        KeyPair keyPair = new KeyPair(new ZyxxPublicKey(pubKey),new ZyxxPrivateKey(SM2Constant.getdA()));
//
////        byte[] signature1 = useKey.signature(keyPair, msg.getBytes());
////        // // System.out.println("C signature    HEX:"+Hex.toHexString(signature1));
////        // // System.out.println(signature1.length);
//
//        // // System.out.println("**************************************************组件化验签********************************************************************************************");
//        boolean b = useKey.verifySignature(new ZyxxPublicKey(pubKey), msg.getBytes(), signature);
////        // // System.out.println(b);
//         sm2Signature = new SM2Signature();
//
//        // // System.out.println("**************************************************JAVA验签********************************************************************************************");
//        // // System.out.println(sm2Signature.verify("message digest".getBytes(),"ALICE123@YAHOO.COM".getBytes(),signature,pubKey));
//
////        // // System.out.println(Hex.toHexString("1234567812345678".getBytes()));
//
//    }


}