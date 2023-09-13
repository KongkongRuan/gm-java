package com.yxj.gm.tls;

public class CipherSuites {
    private String symmetricAlgorithm;
    private String asymmetricAlgorithm;
    private String digestAlgorithm;

    public CipherSuites(String symmetricAlgorithm, String asymmetricAlgorithm, String digestAlgorithm) {
        this.symmetricAlgorithm = symmetricAlgorithm;
        this.asymmetricAlgorithm = asymmetricAlgorithm;
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getSymmetricAlgorithm() {
        return symmetricAlgorithm;
    }

    public void setSymmetricAlgorithm(String symmetricAlgorithm) {
        this.symmetricAlgorithm = symmetricAlgorithm;
    }

    public String getAsymmetricAlgorithm() {
        return asymmetricAlgorithm;
    }

    public void setAsymmetricAlgorithm(String asymmetricAlgorithm) {
        this.asymmetricAlgorithm = asymmetricAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }
}
