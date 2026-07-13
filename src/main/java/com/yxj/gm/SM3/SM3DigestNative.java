package com.yxj.gm.SM3;

/**
 * SM3 implementation that delegates the compression function to a native
 * AVX2-optimized library. Public API identical to {@link SM3Digest}.
 */
public class SM3DigestNative {

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private final byte[] state = new byte[32];
    private final byte[] buffer = new byte[64];
    private int bufferLen = 0;
    private long totalBytes = 0;

    public SM3DigestNative() {
        if (!SM3Native.isAvailable()) {
            throw new UnsatisfiedLinkError("SM3 native library not available: " + SM3Native.getLoadError());
        }
        resetState();
    }

    private void resetState() {
        for (int i = 0; i < 8; i++) {
            int v = IV[i];
            state[i * 4] = (byte) (v >>> 24);
            state[i * 4 + 1] = (byte) (v >>> 16);
            state[i * 4 + 2] = (byte) (v >>> 8);
            state[i * 4 + 3] = (byte) v;
        }
        bufferLen = 0;
        totalBytes = 0;
    }

    private static void intToBytesBE(int val, byte[] b, int off) {
        b[off] = (byte) (val >>> 24);
        b[off + 1] = (byte) (val >>> 16);
        b[off + 2] = (byte) (val >>> 8);
        b[off + 3] = (byte) val;
    }

    public void update(byte[] msg) {
        update(msg, 0, msg.length);
    }

    public void update(byte[] msg, int offset, int len) {
        totalBytes += len;
        int pos = offset;
        int remaining = len;

        if (bufferLen > 0) {
            int need = 64 - bufferLen;
            int copy = Math.min(need, remaining);
            System.arraycopy(msg, pos, buffer, bufferLen, copy);
            bufferLen += copy;
            pos += copy;
            remaining -= copy;
            if (bufferLen == 64) {
                SM3Native.sm3Compress(state, buffer, 1);
                bufferLen = 0;
            }
        }

        int blocks = remaining >>> 6;
        if (blocks > 0) {
            SM3Native.sm3CompressOffset(state, msg, pos, blocks);
            pos += blocks << 6;
            remaining -= blocks << 6;
        }

        if (remaining > 0) {
            System.arraycopy(msg, pos, buffer, 0, remaining);
            bufferLen = remaining;
        }
    }

    public byte[] doFinal() {
        long bitLen = totalBytes * 8L;
        int remainder = bufferLen;

        byte[] finalBlock = new byte[remainder <= 55 ? 64 : 128];
        System.arraycopy(buffer, 0, finalBlock, 0, remainder);
        finalBlock[remainder] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            finalBlock[finalBlock.length - 1 - i] = (byte) (bitLen >>> (i * 8));
        }

        SM3Native.sm3Compress(state, finalBlock, finalBlock.length >>> 6);

        byte[] result = new byte[32];
        System.arraycopy(state, 0, result, 0, 32);
        resetState();
        return result;
    }

    public byte[] doFinal(byte[] msg) {
        resetState();
        update(msg);
        return doFinal();
    }

    public void msgAllReset() {
        resetState();
    }
}
