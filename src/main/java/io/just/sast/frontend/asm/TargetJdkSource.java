package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.JdkClassSource;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 目标 JDK 类来源（--jdk-home 指定）：
 * - Java 8 及以下（有 rt.jar）：从 $jdkHome/jre/lib/ 或 $jdkHome/lib/ 读 rt.jar + 辅助 jar
 * - Java 9+（有 jmods/release）：走 JrtClassSource 挂载外部 jrt-fs
 */
public final class TargetJdkSource implements JdkClassSource {

    private final ClassFileReader reader = new ClassFileReader();
    /** 内部名 → 所在 jar 路径（Java 8 模式） */
    private final Map<String, Path> classToJar = new HashMap<>();
    private final List<Path> coreJars = new ArrayList<>();
    /** Java 9+ 模式的 jrt 代理 */
    private final JrtClassSource jrtDelegate;
    private final String jdkDescription;

    public TargetJdkSource(Path jdkHome) throws IOException {
        Path home = jdkHome.toAbsolutePath().normalize();
        if (!Files.isDirectory(home)) {
            throw new IOException("--jdk-home 不是目录: " + home);
        }
        // Java 8 及以下：找 rt.jar（JDK 在 $home/jre/lib/rt.jar，JRE 在 $home/lib/rt.jar）
        Path rtJar = home.resolve("jre").resolve("lib").resolve("rt.jar");
        if (!Files.exists(rtJar)) {
            rtJar = home.resolve("lib").resolve("rt.jar");
        }
        if (Files.exists(rtJar)) {
            jdkDescription = detectLegacyVersion(home) + "（rt.jar 模式）";
            coreJars.add(rtJar);
            // 辅助 jar：jce / jsse / charsets / resources（反序列化相关类可能分布在多个 jar）
            Path libDir = rtJar.getParent();
            for (String aux : List.of("jce.jar", "jsse.jar", "charsets.jar", "resources.jar")) {
                Path auxPath = libDir.resolve(aux);
                if (Files.exists(auxPath)) {
                    coreJars.add(auxPath);
                }
            }
            jrtDelegate = null;
            JustLogger.info("目标 JDK 来源：{}（{} 个核心 jar：{}）",
                    jdkDescription, coreJars.size(),
                    coreJars.stream().map(p -> p.getFileName().toString())
                            .collect(java.util.stream.Collectors.joining(", ")));
            return;
        }
        // Java 9+：检查 release 文件确认模块化 JDK
        Path release = home.resolve("release");
        if (Files.exists(release)) {
            jdkDescription = readReleaseVersion(home) + "（jrt-fs 模式）";
            // Java 9+ 的 jrt-fs 挂载：暂不实现（用运行时 jrt 作为回退），只读 release 版本信息
            jrtDelegate = new JrtClassSource();
            JustLogger.info("目标 JDK 来源：{}（暂用运行时 jrt-fs，模块化 JDK 精确匹配待实现）", jdkDescription);
            return;
        }
        throw new IOException("--jdk-home 无法识别 JDK 结构（既无 rt.jar 也无 release 文件）: " + home);
    }

    @Override
    public ClassInfo load(String internalName) {
        if (jrtDelegate != null) {
            return jrtDelegate.load(internalName);
        }
        // Java 8 模式：从 classToJar 索引（懒构建）或遍历 jar 查找
        Path jarPath = classToJar.get(internalName);
        if (jarPath == null) {
            jarPath = findInJars(internalName);
            if (jarPath == null) {
                return null;
            }
            classToJar.put(internalName, jarPath);
        }
        try (ZipFile zip = new ZipFile(jarPath.toFile())) {
            ZipEntry entry = zip.getEntry(internalName + ".class");
            if (entry == null) {
                return null;
            }
            return reader.read(zip.getInputStream(entry).readAllBytes());
        } catch (Exception e) {
            JustLogger.debug("目标 JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    /** 枚举全部核心 jar 的类（替代 jrt 的 listAll，全量分析用）。 */
    public List<ClassBytes> listAll() throws IOException {
        List<ClassBytes> result = new ArrayList<>();
        if (jrtDelegate != null) {
            return jrtDelegate.listAll(JrtClassSource.DESER_MODULES);
        }
        for (Path jar : coreJars) {
            try (ZipFile zip = new ZipFile(jar.toFile())) {
                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();
                    if (entry.isDirectory() || !name.endsWith(".class")
                            || name.startsWith("META-INF/versions/")) {
                        continue;
                    }
                    String className = name.substring(0, name.length() - 6);
                    classToJar.putIfAbsent(className, jar);
                    result.add(new ClassBytes(className,
                            zip.getInputStream(entry).readAllBytes(), "jdk:" + jar.getFileName()));
                }
            }
        }
        return result;
    }

    public String description() {
        return jdkDescription;
    }

    private Path findInJars(String internalName) {
        for (Path jar : coreJars) {
            try (ZipFile zip = new ZipFile(jar.toFile())) {
                if (zip.getEntry(internalName + ".class") != null) {
                    return jar;
                }
            } catch (IOException e) {
                continue;
            }
        }
        return null;
    }

    /** 从 $jdkHome/release 或目录名推断版本描述。 */
    private static String detectLegacyVersion(Path home) {
        // 尝试读 jre/release（部分发行版有）
        for (Path release : List.of(home.resolve("release"), home.resolve("jre").resolve("release"))) {
            String version = readVersionFromRelease(release);
            if (version != null) {
                return "JDK " + version;
            }
        }
        // 回退：目录名推断（如 jdk8u202 → JDK 8u202）
        String name = home.getFileName().toString().toLowerCase();
        if (name.contains("jdk7") || name.contains("jre7")) {
            return "JDK 7";
        }
        if (name.contains("jdk8") || name.contains("jre8")) {
            return "JDK 8";
        }
        return "JDK (legacy, " + name + ")";
    }

    private static String readReleaseVersion(Path home) {
        String version = readVersionFromRelease(home.resolve("release"));
        return version != null ? "JDK " + version : "JDK 9+";
    }

    private static String readVersionFromRelease(Path releaseFile) {
        try {
            for (String line : Files.readAllLines(releaseFile)) {
                if (line.startsWith("JAVA_VERSION=")) {
                    return line.substring("JAVA_VERSION=".length()).replace("\"", "").trim();
                }
            }
        } catch (IOException ignored) {
        }
        return null;
    }
}
