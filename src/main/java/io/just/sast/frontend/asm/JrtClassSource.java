package io.just.sast.frontend.asm;

import io.just.sast.analysis.hierarchy.JdkClassSource;
import io.just.sast.model.ClassInfo;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.net.URI;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/** 通过 jrtfs 读取 JDK 运行库类：按需懒加载 + 全量模块枚举。 */
public final class JrtClassSource implements JdkClassSource {

    /** 与反序列化链相关的 JDK 模块（--jdk 全量加载集）。 */
    public static final List<String> DESER_MODULES = List.of(
            "java.base", "java.naming", "java.rmi", "java.management", "java.scripting", "java.sql");

    private final ClassFileReader reader = new ClassFileReader();
    private final Map<String, String> moduleIndex = new HashMap<>();
    private volatile FileSystem jrt;
    private volatile boolean fullIndexBuilt = false;

    @Override
    public ClassInfo load(String internalName) {
        try {
            String module = moduleOf(internalName);
            if (module == null) {
                return null;
            }
            Path classFile = jrt().getPath("modules", module, internalName + ".class");
            if (!Files.exists(classFile)) {
                return null;
            }
            return reader.read(Files.readAllBytes(classFile));
        } catch (Exception e) {
            JustLogger.debug("JDK 类加载失败 {}: {}", internalName, e.getMessage());
            return null;
        }
    }

    private String moduleOf(String internalName) throws IOException {
        if (moduleIndex.containsKey(internalName)) {
            return moduleIndex.get(internalName);
        }
        Path inJavaBase = jrt().getPath("modules", "java.base", internalName + ".class");
        if (Files.exists(inJavaBase)) {
            moduleIndex.put(internalName, "java.base");
            return "java.base";
        }
        if (!fullIndexBuilt) {
            buildFullIndex();
            fullIndexBuilt = true;
        }
        return moduleIndex.get(internalName); // 不存在则 null
    }

    private void buildFullIndex() throws IOException {
        Path modules = jrt().getPath("modules");
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(modules)) {
            for (Path module : ds) {
                if (!Files.isDirectory(module)) {
                    continue;
                }
                String moduleName = module.getFileName().toString();
                try (Stream<Path> walk = Files.walk(module)) {
                    walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                        String rel = module.relativize(p).toString().replace('\\', '/');
                        String className = rel.substring(0, rel.length() - 6);
                        moduleIndex.putIfAbsent(className, moduleName);
                    });
                }
            }
        }
    }

    /** 枚举指定模块的全部类字节（--jdk 全量分析用）。 */
    public List<ClassBytes> listAll(List<String> modules) throws IOException {
        List<ClassBytes> result = new ArrayList<>();
        Path modulesRoot = jrt().getPath("modules");
        for (String module : modules) {
            Path modulePath = modulesRoot.resolve(module);
            if (!Files.isDirectory(modulePath)) {
                continue;
            }
            try (Stream<Path> walk = Files.walk(modulePath)) {
                walk.filter(p -> p.toString().endsWith(".class")).forEach(p -> {
                    String rel = modulePath.relativize(p).toString().replace('\\', '/');
                    String className = rel.substring(0, rel.length() - 6);
                    try {
                        result.add(new ClassBytes(className, Files.readAllBytes(p), "jdk:/" + module));
                    } catch (IOException e) {
                        JustLogger.debug("JDK 类读取失败 {}: {}", className, e.getMessage());
                    }
                });
            }
        }
        return result;
    }

    private FileSystem jrt() throws IOException {
        FileSystem fs = jrt;
        if (fs == null) {
            synchronized (this) {
                fs = jrt;
                if (fs == null) {
                    jrt = fs = FileSystems.getFileSystem(URI.create("jrt:/"));
                }
            }
        }
        return fs;
    }
}
