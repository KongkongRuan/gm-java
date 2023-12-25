package com.yxj.gm.tls.netty;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.tls.netty.handler.enums.TlsMessageType;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class TlsMessage {
    private String version;
    private byte[] sessionId;
    private TlsMessageType tlsMessageType;
    private byte[] content;

    private Object object;

    public static byte[] getEncoded(TlsMessage tlsMessage){
        try {
            return new DEROctetString(JSON.toJSONString(tlsMessage).getBytes(StandardCharsets.UTF_8)).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public TlsMessage() {
    }
    public TlsMessage(byte[] content, TlsMessageType tlsMessageType) {
        this.version="v1";
        this.content = content;
        this.tlsMessageType=tlsMessageType;
    }
    public TlsMessage(byte[] content, TlsMessageType tlsMessageType, byte[] sessionId) {
        this.version="v1";
        this.sessionId = sessionId;
        this.tlsMessageType=tlsMessageType;
        this.content = content;
    }
    public TlsMessage(Object object, TlsMessageType tlsMessageType) {
        this.version="v1";
        this.tlsMessageType=tlsMessageType;
        this.object = object;
    }
    public TlsMessage(Object object, TlsMessageType tlsMessageType, byte[] sessionId) {
        this.version="v1";
        this.sessionId = sessionId;
        this.tlsMessageType=tlsMessageType;
        this.object = object;
    }
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public Object getObject() {
        return object;
    }

    public void setObject(Object object) {
        this.object = object;
    }

    public byte[] getSessionId() {
        return sessionId;
    }

    public void setSessionId(byte[] sessionId) {
        this.sessionId = sessionId;
    }

    public TlsMessageType getTlsMessageType() {
        return tlsMessageType;
    }

    public void setTlsMessageType(TlsMessageType tlsMessageType) {
        this.tlsMessageType = tlsMessageType;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
