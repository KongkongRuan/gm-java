package com.yxj.gm.provider;


import java.security.Provider;

public class XaProvider extends Provider {
    public static final String PACKAGE_NAME = XaProvider.class.getPackage().getName();
    private static final long serialVersionUID = 6440182097568097204L;
    private static final String INFO = "XaProvider (SM2 key/cipher ; SM2 signing;  SM3 digests; SM4 cipher;)";

    public XaProvider(){
        super("XaProvider", 1.8, INFO);
//            this.put("SecureRandom.SM4", PACKAGE_NAME + ".secureRandom.ZyxxSecureRandom");
            this.put("MessageDigest.SM3", PACKAGE_NAME + ".messageDigest.XaSM3MessageDigest");
            this.put("Cipher.SM4", PACKAGE_NAME + ".cipher.XaSM4Cipher");
            this.put("KeyPairGenerator.SM2", PACKAGE_NAME + ".key.XaSM2KeyPairGenerator");
            this.put("Cipher.SM2", PACKAGE_NAME + ".cipher.XaSM2Cipher");
            this.put("Signature.SM2", PACKAGE_NAME + ".signature.XaSM2SignatureJca");

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
