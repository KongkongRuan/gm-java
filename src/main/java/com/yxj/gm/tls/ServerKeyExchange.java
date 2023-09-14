package com.yxj.gm.tls;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class ServerKeyExchange {
    private byte[] serverPubKey;

    public ServerKeyExchange(byte[] serverPubKey) {
        this.serverPubKey = serverPubKey;
    }

    public byte[] getServerPubKey() {
        return serverPubKey;
    }

    public void setServerPubKey(byte[] serverPubKey) {
        this.serverPubKey = serverPubKey;
    }

    @Override
    public String toString() {
        return "ServerKeyExchange{" +
                "serverPubKey=" + Hex.toHexString(serverPubKey) +
                '}';
    }
}
