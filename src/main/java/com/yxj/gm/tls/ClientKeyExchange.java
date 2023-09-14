package com.yxj.gm.tls;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class ClientKeyExchange {
    private byte[] clientPubKey;

    public ClientKeyExchange(byte[] clientPubKey) {
        this.clientPubKey = clientPubKey;
    }

    public byte[] getClientPubKey() {
        return clientPubKey;
    }

    public void setClientPubKey(byte[] clientPubKey) {
        this.clientPubKey = clientPubKey;
    }

    @Override
    public String toString() {
        return "ClientKeyExchange{" +
                "clientPubKey=" + Hex.toHexString(clientPubKey) +
                '}';
    }
}
