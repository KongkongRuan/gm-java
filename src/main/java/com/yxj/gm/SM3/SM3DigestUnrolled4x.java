package com.yxj.gm.SM3;

/**
 * SM3 with the compression-function 64-round loop unrolled 4x.
 * Public API identical to {@link SM3Digest}.
 */
public class SM3DigestUnrolled4x {

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private static final int T_0_15 = 0x79cc4519;
    private static final int T_16_63 = 0x7a879d8a;

    private static final int[] T_ROTATED = new int[64];
    static {
        for (int j = 0; j < 64; j++) {
            int T = (j < 16) ? T_0_15 : T_16_63;
            T_ROTATED[j] = Integer.rotateLeft(T, j % 32);
        }
    }

    private final byte[] buffer = new byte[64];
    private int bufferLen = 0;
    private long totalBytes = 0;

    private final int[] W = new int[68];
    private final int[] W1 = new int[64];
    private final int[] stateA = new int[8];
    private final int[] stateB = new int[8];
    private int[] inState;
    private int[] outState;

    public SM3DigestUnrolled4x() {
        resetState();
    }

    private void resetState() {
        System.arraycopy(IV, 0, stateA, 0, 8);
        inState = stateA;
        outState = stateB;
        bufferLen = 0;
        totalBytes = 0;
    }

    private static int bytesToIntBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) |
                ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static void intToBytesBE(int val, byte[] b, int off) {
        b[off] = (byte) (val >>> 24);
        b[off + 1] = (byte) (val >>> 16);
        b[off + 2] = (byte) (val >>> 8);
        b[off + 3] = (byte) val;
    }

    private static int P1(int X) {
        return X ^ Integer.rotateLeft(X, 15) ^ Integer.rotateLeft(X, 23);
    }

    private static int P0(int X) {
        return X ^ Integer.rotateLeft(X, 9) ^ Integer.rotateLeft(X, 17);
    }

    private void processBlock(byte[] data, int offset) {
        CF(inState, data, offset, outState, W, W1);
        int[] tmp = inState;
        inState = outState;
        outState = tmp;
    }

    private static void CF(int[] V, byte[] padded, int offset, int[] out, int[] W, int[] W1) {
        for (int i = 0; i < 16; i++) {
            W[i] = bytesToIntBE(padded, offset + i * 4);
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ Integer.rotateLeft(W[j - 3], 15))
                    ^ Integer.rotateLeft(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        int A = V[0], B = V[1], C = V[2], D = V[3];
        int E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 16; j += 4) {
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j], 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
            int TT2 = (E ^ F ^ G) + H + SS1 + W[j];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 1], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = (A ^ B ^ C) + D + SS2 + W1[j + 1];
            TT2 = (E ^ F ^ G) + H + SS1 + W[j + 1];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 2], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = (A ^ B ^ C) + D + SS2 + W1[j + 2];
            TT2 = (E ^ F ^ G) + H + SS1 + W[j + 2];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 3], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = (A ^ B ^ C) + D + SS2 + W1[j + 3];
            TT2 = (E ^ F ^ G) + H + SS1 + W[j + 3];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);
        }
        for (int j = 16; j < 64; j += 4) {
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j], 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
            int TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 1], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j + 1];
            TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j + 1];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 2], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j + 2];
            TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j + 2];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);

            SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j + 3], 7);
            SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j + 3];
            TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j + 3];
            D = C; C = Integer.rotateLeft(B, 9); B = A; A = TT1;
            H = G; G = Integer.rotateLeft(F, 19); F = E; E = P0(TT2);
        }

        out[0] = A ^ V[0];
        out[1] = B ^ V[1];
        out[2] = C ^ V[2];
        out[3] = D ^ V[3];
        out[4] = E ^ V[4];
        out[5] = F ^ V[5];
        out[6] = G ^ V[6];
        out[7] = H ^ V[7];
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
                processBlock(buffer, 0);
                bufferLen = 0;
            }
        }

        while (remaining >= 64) {
            processBlock(msg, pos);
            pos += 64;
            remaining -= 64;
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

        int finalBlocks = finalBlock.length >>> 6;
        for (int i = 0; i < finalBlocks; i++) {
            CF(inState, finalBlock, i << 6, outState, W, W1);
            int[] tmp = inState;
            inState = outState;
            outState = tmp;
        }

        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++) {
            intToBytesBE(inState[i], result, i * 4);
        }

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
