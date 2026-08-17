package io.just.sast.integration;

import io.just.sast.blackboard.Chain;
import io.just.sast.cli.ScanPipeline;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * benchmark/demo/ 三个 jar 的真实回归（预期链均来自 javap 反汇编确认的真实代码，非工具推断）：
 * - demo.jar：Dog.hashCode → wagTail → Method.invoke（Dog.equals 为负例）
 * - demo2.jar：与 demo 同链（DogService 去掉 Serializable，不影响 Dog 链）
 * - Unictf.jar：ConfigDataWrapper.toString → XOR 解密 ClassByte → Method.invoke(ClassLoader.defineClass)
 */
class BenchmarkJarsRegressionTest {

    private static final Path DEMO = Path.of("benchmark", "demo", "demo.jar");
    private static final Path DEMO2 = Path.of("benchmark", "demo", "demo2.jar");
    private static final Path UNICTF = Path.of("benchmark", "demo", "Unictf.jar");

    @Test
    void demoJarFindsDogChainAndNotEquals(@TempDir Path outDir) throws Exception {
        List<Chain> chains = scan(DEMO, outDir.resolve("demo"));

        assertTrue(hasChain(chains, "com/example/demo/Dog/Dog", "hashCode",
                "java/lang/reflect/Method", "invoke"), "demo.jar 应检出 Dog.hashCode 链");
        assertFalse(chains.stream().anyMatch(c ->
                        c.entryClass().equals("com/example/demo/Dog/Dog") && c.entryMethod().equals("equals")),
                "Dog.equals 不应出链");
    }

    @Test
    void demo2JarFindsSameDogChain(@TempDir Path outDir) throws Exception {
        List<Chain> chains = scan(DEMO2, outDir.resolve("demo2"));

        assertTrue(hasChain(chains, "com/example/demo/Dog/Dog", "hashCode",
                "java/lang/reflect/Method", "invoke"), "demo2.jar 应检出 Dog.hashCode 链");
    }

    @Test
    void unictfJarFindsToStringDefineClassChain(@TempDir Path outDir) throws Exception {
        List<Chain> chains = scan(UNICTF, outDir.resolve("unictf"));

        assertTrue(hasChain(chains, "com/unictf/ctf/tools/ConfigDataWrapper", "toString",
                        "java/lang/reflect/Method", "invoke"),
                "Unictf.jar 应检出 ConfigDataWrapper.toString → Method.invoke 链");
    }

    @Test
    void csvOutputsHaveBomAndHeaders(@TempDir Path outDir) throws Exception {
        scan(DEMO, outDir.resolve("csv"));

        for (String file : List.of("findings.csv", "edges.csv", "sinks.csv")) {
            String content = Files.readString(outDir.resolve("csv").resolve(file), StandardCharsets.UTF_8);
            assertTrue(content.startsWith("\uFEFF"), file + " 应以 BOM 开头");
            assertTrue(content.contains("\r\n"), file + " 应使用 CRLF");
        }
        String findings = Files.readString(outDir.resolve("csv").resolve("findings.csv"), StandardCharsets.UTF_8);
        assertTrue(findings.contains("variant_count"), "findings 表头应包含 variant_count");
    }

    @Test
    void jdkFullAnalysisSurfacesJdkGadgetPrimitives(@TempDir Path outDir) throws Exception {
        // --jdk：JDK 运行库全量参与分析；JDK 内部真实 gadget 原语应被检出
        ScanPipeline.ScanResult result =
                ScanPipeline.run(UNICTF, null, outDir.resolve("jdk"), null, 20, false, false, true);
        List<Chain> chains = result.chains();

        // 目标链不丢
        assertTrue(hasChain(chains, "com/unictf/ctf/tools/ConfigDataWrapper", "toString",
                        "java/lang/reflect/Method", "invoke"),
                "--jdk 下 Unictf 目标链应保持检出");
        // JDK7u21 链的处理器原语（javadoc 已知真实 gadget）
        assertTrue(hasChain(chains, "sun/reflect/annotation/AnnotationInvocationHandler", "invoke",
                        "java/lang/reflect/Method", "invoke"),
                "--jdk 下应检出 AnnotationInvocationHandler 原语");
    }

    private static boolean hasChain(List<Chain> chains, String entryClass, String entryMethod,
                                    String sinkClass, String sinkMethod) {
        return chains.stream().anyMatch(c ->
                c.entryClass().equals(entryClass) && c.entryMethod().equals(entryMethod)
                        && c.sinkClass().equals(sinkClass) && c.sinkMethod().equals(sinkMethod));
    }

    private List<Chain> scan(Path jar, Path outDir) throws Exception {
        assertTrue(Files.exists(jar), jar + " 必须存在");
        ScanPipeline.ScanResult result =
                ScanPipeline.run(jar, null, outDir, null, 20, false, false);
        assertTrue(result.exitCode() == 0, "扫描应成功");
        return result.chains();
    }
}
