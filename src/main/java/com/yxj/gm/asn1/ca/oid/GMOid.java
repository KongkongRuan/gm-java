package com.yxj.gm.asn1.ca.oid;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;

/**
 * GM/T0010-2012 SM2密码算法加密签名消息语法规范 第六章OID定义
 */
public interface GMOid extends GMObjectIdentifiers {
    //SM2密码算法加密签名消息语法规范
    ASN1ObjectIdentifier base_scheme = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2");
    ASN1ObjectIdentifier data = base_scheme.branch("1");
    ASN1ObjectIdentifier signedData = base_scheme.branch("2");
    ASN1ObjectIdentifier envelopedData = base_scheme.branch("3");
    ASN1ObjectIdentifier signedAndEnvelopedData = base_scheme.branch("4");
    ASN1ObjectIdentifier encryptedData = base_scheme.branch("5");
    ASN1ObjectIdentifier keyAgreementInfo = base_scheme.branch("6");
}
