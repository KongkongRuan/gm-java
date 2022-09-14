package com.yxj.gm.provider.messageDigest;

import com.yxj.gm.SM3.SM3;

import java.io.Serializable;
import java.security.MessageDigestSpi;

public class SM3MessageDigest extends MessageDigestSpi implements Serializable {
    SM3 sm3 = new SM3();


    @Override
    protected void engineUpdate(byte input) {

    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        sm3.update(input);
    }

    @Override
    protected byte[] engineDigest() {
        return sm3.doFinal();
    }

    @Override
    protected void engineReset() {
        sm3.msgAllReset();
    }
}
