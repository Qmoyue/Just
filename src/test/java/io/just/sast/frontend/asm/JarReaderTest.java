package io.just.sast.frontend.asm;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** fat jar 解析契约：BOOT-INF/classes 应用类 + BOOT-INF/lib 嵌套 jar 均被解析。 */
class JarReaderTest {

    @Test
    void readsFatJarIncludingNestedLibs() throws Exception {
        Path demoJar = Path.of("benchmark", "demo", "demo.jar");
        assertTrue(Files.exists(demoJar), "benchmark/demo/demo.jar 必须存在");

        List<ClassBytes> bytes = new JarReader().read(demoJar);
        Set<String> names = bytes.stream().map(ClassBytes::className).collect(Collectors.toSet());

        assertTrue(bytes.size() > 5000, "嵌套依赖应被递归解析，实际 " + bytes.size());
        assertTrue(names.contains("com/example/demo/Dog/Dog"), "BOOT-INF/classes 前缀应被剥离");
        assertTrue(names.contains("org/springframework/boot/SpringApplication"),
                "BOOT-INF/lib 嵌套 jar 应被递归解析");
    }
}
