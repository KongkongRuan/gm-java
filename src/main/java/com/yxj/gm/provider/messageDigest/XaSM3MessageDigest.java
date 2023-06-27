package com.yxj.gm.provider.messageDigest;

import com.yxj.gm.SM3.SM3Digest;

import java.io.Serializable;
import java.security.MessageDigestSpi;

public class XaSM3MessageDigest extends MessageDigestSpi implements Serializable {
    SM3Digest sm3 = new SM3Digest();


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

    @Override
    protected int engineGetDigestLength() {
        return 32;
    }
}
