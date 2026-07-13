package com.yxj.gm.SM3;

import java.io.*;
import java.nio.file.*;

/**
 * Loads the SM3 native library and exposes raw JNI entry points.
 */
final class SM3Native {

    private static final boolean AVAILABLE;
    private static Throwable loadError;

    static {
        boolean ok = false;
        try {
            loadNative();
            ok = true;
        } catch (Throwable t) {
            loadError = t;
        }
        AVAILABLE = ok;
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    static Throwable getLoadError() {
        return loadError;
    }

    private static void loadNative() throws IOException {
        String libName = System.mapLibraryName("sm3native");
        String resourcePath = "/native/" + osArchDir() + "/" + libName;
        InputStream in = SM3Native.class.getResourceAsStream(resourcePath);
        if (in == null) {
            // Fallback: try loading from java.library.path
            System.loadLibrary("sm3native");
            return;
        }
        Path tmp = Files.createTempFile("sm3native-", libName.contains(".") ? libName.substring(libName.lastIndexOf('.')) : "");
        tmp.toFile().deleteOnExit();
        try (OutputStream out = Files.newOutputStream(tmp)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        } finally {
            in.close();
        }
        System.load(tmp.toAbsolutePath().toString());
    }

    private static String osArchDir() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();
        if (os.contains("win")) {
            return "win-x86_64";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return arch.contains("aarch64") ? "macos-aarch64" : "macos-x64";
        }
        return arch.contains("aarch64") ? "linux-aarch64" : "linux-x64";
    }

    /**
     * Computes one or more SM3 compression iterations in native code.
     *
     * @param state 8 int initial value (IV or previous state), updated in place
     * @param data  one or more 64-byte blocks
     * @param blocks number of blocks
     */
    static native void sm3Compress(byte[] state, byte[] data, int blocks);

    /**
     * Computes compression iterations starting at an offset in data.
     */
    static native void sm3CompressOffset(byte[] state, byte[] data, int offset, int blocks);

    /**
     * Hash multiple independent messages in parallel using SIMD.
     *
     * @param inputs  input messages (each may be any length)
     * @param outputs output buffers, must be inputs.length * 32 bytes
     * @return number of messages hashed
     */
    static native int sm3HashBatch(byte[][] inputs, byte[] outputs);
}
