package com.yxj.gm.util.JNI;

/**
 * SM4-GCM native acceleration (x86_64 CLMUL).
 *
 * Currently exposes one-shot GHASH via PCLMULQDQ. The whole GHASH input
 * (already padded to 16-byte alignment) is passed down in a single JNI call
 * to avoid per-block JNI overhead.
 *
 * Loading fails gracefully; callers should fall back to the Java GHASH path.
 */
public class SM4GCMNative {

    private static volatile boolean loaded = false;
    private static volatile boolean available = false;

    static {
        try {
            NativeLoader.loadLibrary("sm4gcm");
            loaded = true;
            available = true;
        } catch (Throwable t) {
            loaded = true;
            available = false;
        }
    }

    /**
     * Compute GHASH over a pre-padded byte array.
     *
     * @param in  input aligned to 16 bytes (caller must pad with zeros)
     * @param H   16-byte hash subkey
     * @param out 16-byte result
     */
    public static native void ghash(byte[] in, byte[] H, byte[] out);

    /**
     * Full SM4-GCM encryption in one JNI call (12-byte IV, arbitrary AAD/PT).
     * Output ciphertext is written to ct, 16-byte tag to tag.
     */
    public static native void gcmEncrypt(byte[] key, byte[] iv,
                                         byte[] aad, int aadLen,
                                         byte[] pt, int ptLen,
                                         byte[] ct, byte[] tag);

    public static boolean isAvailable() {
        return available;
    }

    public static void markUnavailable() {
        available = false;
    }

    public static void main(String[] args) {
        System.out.println("SM4GCMNative available: " + isAvailable());
    }
}
