package java.math;

import java.io.IOException;
import java.util.Arrays;

public class Test {

    public static void main(String[] args) throws IOException {
//        String msg = "abc";
//        byte[] pub = Hex.decode("4D4C6890A3BD008AA20C6694AB28E0556E2A49832A3EBD0E06B416B0025D55768807077EE0B563841D6E6891444838741B0A2CEA96D65D7D2A77499037D31415");
//        byte[] pri = Hex.decode("0D1805602EA892948ABDB78AA7414BAEE1B5F4787D35B66A6A3FFAC3551F6840");
//
//        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
//        pub=keyPair.getPublic().getEncoded();
//        pri=keyPair.getPrivate().getEncoded();
//
//
//        SM2Signature signature = new SM2Signature();
//        byte[] signature1 = signature.signature(msg.getBytes(), null, pri);
//        System.out.println(Hex.toHexString(signature1));
////        ASN1SM2Signature asn1SM2Signature = ASN1Util.SM2SignatureToASN1SM2Signature(signature1);
////        System.out.println(Hex.toHexString(asn1SM2Signature.getEncoded()));
//        boolean verify = signature.verify(msg.getBytes(), null, signature1, pub);
//        System.out.println(verify);
        //2147483647
        BigInteger bigInteger = new BigInteger("-"+(Integer.MAX_VALUE) + "");//2147483647
        BigInteger bigInteger2 = new BigInteger("-2147483648");
        BigInteger bigInteger22 = new BigInteger("+2147483648");

        byte[] byteArray = bigInteger2.toByteArray();
        int[] mag = bigInteger2.mag;
        int[] mag2 = bigInteger22.mag;
        System.out.println(Arrays.equals(mag, mag2));


        BigInteger bigInteger3 = new BigInteger("-2147483649");
        BigInteger bigInteger4 = new BigInteger("-5147483648");



        System.out.println();


    }
}
