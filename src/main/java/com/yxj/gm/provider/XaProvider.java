package com.yxj.gm.provider;

import com.kms.provider.FzProvider;
import sun.security.action.PutAllAction;

import java.security.AccessController;
import java.security.Provider;
import java.util.LinkedHashMap;

public class XaProvider extends Provider {
    public static final String PACKAGE_NAME = XaProvider.class.getPackage().getName();
    private static final long serialVersionUID = 6440182097568097204L;
    private static final String INFO = "XaProvider (SM2 key/cipher ; SM2 signing;  SM3 digests; SM4 cipher;)";

    public XaProvider(){
        super("XaProvider", 1.8, INFO);
        if (System.getSecurityManager() == null) {
//            this.put("SecureRandom.SM4", PACKAGE_NAME + ".secureRandom.ZyxxSecureRandom");
            this.put("MessageDigest.SM3", PACKAGE_NAME + ".messageDigest.SM3MessageDigest");
            this.put("Cipher.SM4", PACKAGE_NAME + ".cipher.SM4Cipher");
            this.put("KeyPairGenerator.SM2", PACKAGE_NAME + ".key.SM2KeyPairGenerator");
            this.put("Cipher.SM2", PACKAGE_NAME + ".cipher.SM2Cipher");
            this.put("Signature.SM2", PACKAGE_NAME + ".signature.SM2SignatureJca");
        } else {
            LinkedHashMap var1 = new LinkedHashMap();
            this.putAll(var1);
            AccessController.doPrivileged(new PutAllAction(this, var1));
        }
    }

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    protected XaProvider(String name, double version, String info) {
        super(name, version, info);
    }
}
