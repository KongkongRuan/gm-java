package com.yxj.gm.provider.mac;

import com.yxj.gm.SM3.SM3HMac;

import javax.crypto.MacSpi;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * HMAC-SM3 的 JCA MacSpi 实现。
 */
public class XaHMacSM3 extends MacSpi {

    private static final int MAC_LENGTH = 32;

    private byte[] key;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected int engineGetMacLength() {
        return MAC_LENGTH;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("HmacSM3 does not support AlgorithmParameterSpec");
        }
        if (key == null) {
            throw new InvalidKeyException("key is null");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("key encoding is null");
        }
        this.key = Arrays.copyOf(encoded, encoded.length);
        engineReset();
    }

    @Override
    protected void engineUpdate(byte input) {
        buffer.write(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (input == null) {
            throw new IllegalArgumentException("input is null");
        }
        if (offset < 0 || len < 0 || offset + len > input.length) {
            throw new IllegalArgumentException("invalid input range");
        }
        if (len == 0) {
            return;
        }
        buffer.write(input, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        if (key == null) {
            throw new IllegalStateException("HmacSM3 not initialized");
        }
        byte[] result = new SM3HMac(key).doFinal(buffer.toByteArray());
        engineReset();
        return result;
    }

    @Override
    protected void engineReset() {
        buffer.reset();
    }
}
