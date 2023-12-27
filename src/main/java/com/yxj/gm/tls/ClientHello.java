package com.yxj.gm.tls;

import java.io.Serializable;
import java.util.Arrays;

public class ClientHello implements Serializable {
    private String version;
    private byte[] randomC;
    private byte[] sessionId;
    private CipherSuites cipherSuites;
    private String compressionMethods;

    private String extensions;

    private boolean isCacheKey=false;


    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public byte[] getRandomC() {
        return randomC;
    }

    public void setRandomC(byte[] randomC) {
        this.randomC = randomC;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public CipherSuites getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(CipherSuites cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public String getCompressionMethods() {
        return compressionMethods;
    }

    public void setCompressionMethods(String compressionMethods) {
        this.compressionMethods = compressionMethods;
    }

    public String getExtensions() {
        return extensions;
    }

    public void setExtensions(String extensions) {
        this.extensions = extensions;
    }

    public boolean isCacheKey() {
        return isCacheKey;
    }

    public void setCacheKey(boolean cacheKey) {
        isCacheKey = cacheKey;
    }

    @Override
    public String toString() {
        return "ClientHello{" +
                "version='" + version + '\'' +
                ", randomC=" + Arrays.toString(randomC) +
                ", sessionId=" + Arrays.toString(sessionId) +
                ", cipherSuites=" + cipherSuites +
                ", compressionMethods='" + compressionMethods + '\'' +
                ", extensions='" + extensions + '\'' +
                '}';
    }
}
