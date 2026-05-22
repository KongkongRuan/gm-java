package com.yxj.gm.SM3;

import java.util.Arrays;

/**
 * HMAC-SM3 直接调用实现，不依赖 JCA Mac。
 */
public class SM3HMac {

    private static final int BLOCK_LEN = 64;

    private final byte[] key;
    private final byte[] ipadKey;
    private final byte[] opadKey;
    private final SM3Digest innerDigest = new SM3Digest();

    public SM3HMac(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }
        this.key = normalizeKey(key);
        this.ipadKey = xorPad(this.key, 0x36);
        this.opadKey = xorPad(this.key, 0x5c);
        reset();
    }

    public void update(byte[] msg) {
        innerDigest.update(msg);
    }

    public void update(byte[] msg, int offset, int len) {
        innerDigest.update(msg, offset, len);
    }

    public byte[] doFinal() {
        byte[] innerHash = innerDigest.doFinal();
        SM3Digest outerDigest = new SM3Digest();
        outerDigest.update(opadKey);
        outerDigest.update(innerHash);
        byte[] result = outerDigest.doFinal();
        reset();
        return result;
    }

    public byte[] doFinal(byte[] msg) {
        reset();
        innerDigest.update(msg);
        return doFinal();
    }

    public void reset() {
        innerDigest.msgAllReset();
        innerDigest.update(ipadKey);
    }

    public byte[] getEncodedKey() {
        return Arrays.copyOf(key, key.length);
    }

    private static byte[] normalizeKey(byte[] key) {
        byte[] normalized = new byte[BLOCK_LEN];
        if (key.length > BLOCK_LEN) {
            SM3Digest digest = new SM3Digest();
            byte[] hashed = digest.doFinal(key);
            System.arraycopy(hashed, 0, normalized, 0, hashed.length);
            return normalized;
        }
        System.arraycopy(key, 0, normalized, 0, key.length);
        return normalized;
    }

    private static byte[] xorPad(byte[] key, int pad) {
        byte[] result = new byte[BLOCK_LEN];
        for (int i = 0; i < BLOCK_LEN; i++) {
            result[i] = (byte) (key[i] ^ pad);
        }
        return result;
    }
}
