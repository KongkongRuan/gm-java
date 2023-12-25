package com.yxj.gm.tls.netty.handler.enums;

import com.alibaba.fastjson2.JSON;

import java.nio.charset.StandardCharsets;

public enum TlsMessageType {
    CLIENT_HELLO(0),SERVER_HELLO(1),SERVER_CERT(2),SERVER_KEY_EXCHANGE_ECDHE(3),SERVER_KEY_EXCHANGE(4),SERVER_HELLO_DONE(5),CLIENT_KEY_EXCHANGE_ECDHE(6),CLIENT_KEY_EXCHANGE(7),CLIENT_CERT_VERIFY(8),CLIENT_CHANGE_CIPHER_SPEC(9),CLIENT_FINISHED(10),SERVER_CHANGE_CIPHER_SPEC(11),SERVER_FINISHED(12),APPLICATION_DATA(13);

    private int typeId;

    TlsMessageType(int i) {
        typeId=i;
    }
    public static TlsMessageType stateOf(int index) {
        for (TlsMessageType tlsMessageType : values()) {
            if (tlsMessageType.getTypeId() == index) {
                return tlsMessageType;
            }
        }
        return null;
    }
    public int getTypeId() {
        return typeId;
    }
    public byte[] getEncoded(){
        return JSON.toJSONString(this).getBytes(StandardCharsets.UTF_8);
    }
    //    public static final String CLIENT_HELLO = "clientHello";
//    public static final String SERVER_HELLO = "serverHello";
//    public static final String SERVER_CERT = "serverCert";
//    public static final String SERVER_KEY_EXCHANGE_ECDHE = "serverKeyExchangeECDHE";
//    public static final String SERVER_KEY_EXCHANGE = "serverKeyExchange";
//    public static final String SERVER_HELLO_DONE = "serverHelloDone";
//    public static final String CLIENT_KEY_EXCHANGE_ECDHE = "clientKeyExchangeECDHE";
//    public static final String CLIENT_KEY_EXCHANGE = "clientKeyExchange";
//    public static final String CLIENT_CERT_VERIFY = "clientCertVerify";
//    public static final String CLIENT_CHANGE_CIPHER_SPEC = "clientChangeCipherSpec";
//    public static final String CLIENT_FINISHED = "clientFinished";
//    public static final String SERVER_CHANGE_CIPHER_SPEC = "serverChangeCipherSpec";
//    public static final String SERVER_FINISHED = "serverFinished";
//    public static final String APPLICATION_DATA = "applicationData";
}
