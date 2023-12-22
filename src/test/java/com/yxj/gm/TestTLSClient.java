package com.yxj.gm;

import com.yxj.gm.tls.TlsClient;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class TestTLSClient {
    public static void main(String[] args) {

//            TlsClient tlsClient = new TlsClient("43.143.242.12");
            TlsClient tlsClient = new TlsClient("127.0.0.1");
            tlsClient.start();
        byte[] random = tlsClient.getRandom();
        System.out.println(Hex.toHexString(random));

    }
}
