package com.yxj.gm.util.JNI;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 加载 nat256mul 原生库。若库不存在则抛出异常，由 Nat256Native 捕获并设置 available=false。
 */
public class NativeLoader {

    static void load() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        String platform;
        if (os.contains("win"))
            platform = "win";
        else if (os.contains("mac"))
            platform = "macos";
        else
            platform = "linux";

        if (arch.contains("aarch64") || arch.equals("arm64"))
            arch = "aarch64";
        else if (arch.contains("loongarch"))
            arch = "loongarch64";
        else if (arch.contains("mips"))
            arch = "mips64";
        else if (arch.contains("amd64") || arch.equals("x86_64") || arch.contains("64"))
            arch = "x86_64";

        String libName;
        if (platform.equals("win"))
            libName = "nat256mul.dll";
        else if (platform.equals("macos"))
            libName = "libnat256mul.dylib";
        else
            libName = "libnat256mul.so";

        String path = "/native/" + platform + "-" + arch + "/" + libName;
        InputStream in = NativeLoader.class.getResourceAsStream(path);

        if (in == null)
            throw new RuntimeException("native lib not found: " + path);

        try {
            Path temp = Files.createTempFile("nat256", libName);
            Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
            System.load(temp.toAbsolutePath().toString());
        } catch (Exception e) {
            throw new RuntimeException("failed to load native lib: " + e.getMessage(), e);
        }
    }
}
