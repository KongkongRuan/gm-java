package com.yxj.gm.SM3;

/**
 * Batch SM3 hashing API. When the native SIMD implementation is available,
 * multiple independent messages are hashed in parallel; otherwise falls back
 * to sequential Java hashing.
 */
public final class SM3Batch {

    private SM3Batch() {}

    /**
     * Returns true if the native SIMD batch implementation is loaded.
     */
    public static boolean isAvailable() {
        return SM3Native.isAvailable();
    }

    /**
     * Hash an array of independent messages.
     *
     * @param inputs one message per element
     * @return 32-byte digest per input, in the same order
     */
    public static byte[][] sm3HashBatch(byte[][] inputs) {
        if (inputs == null) throw new IllegalArgumentException("inputs is null");
        byte[][] outputs = new byte[inputs.length][];
        if (inputs.length == 0) return outputs;

        if (SM3Native.isAvailable()) {
            byte[] flat = new byte[inputs.length * 32];
            SM3Native.sm3HashBatch(inputs, flat);
            for (int i = 0; i < inputs.length; i++) {
                outputs[i] = new byte[32];
                System.arraycopy(flat, i * 32, outputs[i], 0, 32);
            }
        } else {
            com.yxj.gm.SM3.SM3Digest d = new com.yxj.gm.SM3.SM3Digest();
            for (int i = 0; i < inputs.length; i++) {
                outputs[i] = d.doFinal(inputs[i]);
            }
        }
        return outputs;
    }
}
