package com.yxj.gm;

import com.yxj.gm.tls.TlsClient;
import com.yxj.gm.tls.TlsServer;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;

public class TestTLSServer {
    public static void main(String[] args) {

            TlsServer tlsServer = new TlsServer();
            tlsServer.start();
        byte[] random = tlsServer.getRandom();
        System.out.println(Hex.toHexString(random));

    }
}
