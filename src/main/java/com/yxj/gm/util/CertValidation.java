package com.yxj.gm.util;

import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.cert.CertParseVo;

public class CertValidation {
    public static boolean selfSignedCaValidation(byte[] cert){
        CertParseVo certParseVo = CertPaser.parseCert(cert);
        SM2Signature signature = new SM2Signature();
        return signature.verify(certParseVo.getTbsCert(), null, certParseVo.getSignatureValue(), certParseVo.getPubKey());
    }
    //Certificate II
    public static boolean CertificateChainValidation(byte[]... certs){
        SM2Signature signature = new SM2Signature();
        for (int i = 0; i < certs.length-1; i++) {
            CertParseVo certParseVo1 = CertPaser.parseCert(certs[i]);
            CertParseVo certParseVo2 = CertPaser.parseCert(certs[i+1]);
            if(!signature.verify(certParseVo2.getTbsCert(),null,certParseVo2.getSignatureValue(), certParseVo1.getPubKey())){
                return false;
            }
        }
        return true;
    }
}
