package com.yxj.gm;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.random.Random;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;

public class TestTlsJamming {
    public static void main(String[] args) {
        String serverIp = "127.0.0.1";
        int tlsPort = 4433;
        Socket socket = null;
        try {
            socket = new Socket(serverIp, tlsPort);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        OutputStream outputStream = null;
        try {
            outputStream = socket.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            Thread.sleep(50000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        byte[] bytes = Random.RandomBySM3(5);
        try {
            outputStream.write(bytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            outputStream.write("gmjava".getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
