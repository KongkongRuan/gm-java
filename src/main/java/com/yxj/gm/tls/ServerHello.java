package com.yxj.gm.tls;

import java.util.Arrays;

public class ServerHello {
    private String version;
    private byte[] randomS;
    private byte[] sessionId;
    private CipherSuites cipherSuites;
    private String compressionMethods;

    private String extensions;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public byte[] getRandomS() {
        return randomS;
    }

    public void setRandomS(byte[] randomS) {
        this.randomS = randomS;
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

    @Override
    public String toString() {
        return "ServerHello{" +
                "version='" + version + '\'' +
                ", randomS=" + Arrays.toString(randomS) +
                ", sessionId=" + Arrays.toString(sessionId) +
                ", cipherSuites=" + cipherSuites +
                ", compressionMethods='" + compressionMethods + '\'' +
                ", extensions='" + extensions + '\'' +
                '}';
    }
}
