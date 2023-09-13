package com.yxj.gm.tls;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class ServerKeyExchangeECDHE {
    private ServerKeyExchange serverKeyExchange;
    private byte[] signature;

    public ServerKeyExchangeECDHE(ServerKeyExchange serverKeyExchange, byte[] signature) {
        this.serverKeyExchange = serverKeyExchange;
        this.signature = signature;
    }

    public ServerKeyExchange getServerKeyExchange() {
        return serverKeyExchange;
    }

    public void setServerKeyExchange(ServerKeyExchange serverKeyExchange) {
        this.serverKeyExchange = serverKeyExchange;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        return "ServerKeyExchangeECDHE{" +
                "serverKeyExchange=" + serverKeyExchange +
                ", signature=" + Hex.toHexString(signature) +
                '}';
    }
}
