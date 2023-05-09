//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.yxj.gm.util;

import java.util.HashMap;
import java.util.Map;

public class SunOidMap {
    private static final long serialVersionUID = 8622598936488630849L;
    static Map<Object, Object> map = new HashMap();

    public static String get(String key) {
        return (String)map.get(key);
    }

    public SunOidMap() {
        map.put("SecureRandom.Windows-PRNG", "sun.security.mscapi.PRNG");
        map.put("KeyStore.Windows-MY", "sun.security.mscapi.CKeyStore$MY");
        map.put("KeyStore.Windows-ROOT", "sun.security.mscapi.CKeyStore$ROOT");
        map.put("Signature.NONEwithRSA", "sun.security.mscapi.CSignature$NONEwithRSA");
        map.put("Signature.SHA1withRSA", "sun.security.mscapi.CSignature$SHA1withRSA");
        map.put("Signature.SHA256withRSA", "sun.security.mscapi.CSignature$SHA256withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", "SHA256withRSA");
        map.put("Signature.SHA384withRSA", "sun.security.mscapi.CSignature$SHA384withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", "SHA384withRSA");
        map.put("Signature.SHA512withRSA", "sun.security.mscapi.CSignature$SHA512withRSA");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", "SHA512withRSA");
        map.put("Signature.MD5withRSA", "sun.security.mscapi.CSignature$MD5withRSA");
        map.put("Signature.MD2withRSA", "sun.security.mscapi.CSignature$MD2withRSA");
        map.put("Signature.RSASSA-PSS", "sun.security.mscapi.CSignature$PSS");
        map.put("Alg.Alias.Signature.1.2.840.113549.1.1.10", "RSASSA-PSS");
        map.put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.10", "RSASSA-PSS");
        map.put("Signature.SHA1withECDSA", "sun.security.mscapi.CSignature$SHA1withECDSA");
        map.put("Alg.Alias.Signature.1.2.840.10045.4.1", "SHA1withECDSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.10045.4.1", "SHA1withECDSA");
        map.put("Signature.SHA224withECDSA", "sun.security.mscapi.CSignature$SHA224withECDSA");
        map.put("Alg.Alias.Signature.1.2.840.10045.4.3.1", "SHA224withECDSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.1", "SHA224withECDSA");
        map.put("Signature.SHA256withECDSA", "sun.security.mscapi.CSignature$SHA256withECDSA");
        map.put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2", "SHA256withECDSA");
        map.put("Signature.SHA384withECDSA", "sun.security.mscapi.CSignature$SHA384withECDSA");
        map.put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3", "SHA384withECDSA");
        map.put("Signature.SHA512withECDSA", "sun.security.mscapi.CSignature$SHA512withECDSA");
        map.put("Alg.Alias.Signature.1.2.840.10045.4.3.4", "SHA512withECDSA");
        map.put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.4", "SHA512withECDSA");
        map.put("Signature.NONEwithRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA1withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA256withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA384withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA512withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.MD5withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.MD2withRSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.RSASSA-PSS SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA1withECDSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA224withECDSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA256withECDSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA384withECDSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("Signature.SHA512withECDSA SupportedKeyClasses", "sun.security.mscapi.CKey");
        map.put("KeyPairGenerator.RSA", "sun.security.mscapi.CKeyPairGenerator$RSA");
        map.put("KeyPairGenerator.RSA KeySize", "1024");
        map.put("Cipher.RSA", "sun.security.mscapi.CRSACipher");
        map.put("Cipher.RSA/ECB/PKCS1Padding", "sun.security.mscapi.CRSACipher");
        map.put("Cipher.RSA SupportedModes", "ECB");
        map.put("Cipher.RSA SupportedPaddings", "PKCS1PADDING");
        map.put("Cipher.RSA SupportedKeyClasses", "sun.security.mscapi.CKey");
    }
}
