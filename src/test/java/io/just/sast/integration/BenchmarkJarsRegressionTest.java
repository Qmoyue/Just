package io.just.sast.integration;

import io.just.sast.blackboard.Chain;
import io.just.sast.cli.ScanPipeline;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * benchmark 五个 jar 的真实回归（预期链均来自 javap 反汇编/wp 确认的真实代码，非工具推断）：
 * - demo.jar / demo2.jar：Dog.hashCode → wagTail → Method.invoke（Dog.equals 负例）
 * - Unictf.jar：ConfigDataWrapper.toString → Method.invoke(defineClass)
 * - java-quote-1.0.jar：DebugController.importConfig（OIS 源）→ Transformer → Method.invoke
 * - javamix-1.0.0.jar：TreeMultimap.readObject → Method.invoke（WP 双层链入口）
 */
class BenchmarkJarsRegressionTest {

    private static final Path DEMO = Path.of("benchmark", "demo", "demo.jar");
    private static final Path DEMO2 = Path.of("benchmark", "demo", "demo2.jar");
    private static final Path UNICTF = Path.of("benchmark", "demo", "Unictf.jar");
    private static final Path JAVA_QUOTE = Path.of("benchmark", "demo", "java-quote-1.0.jar");
    private static final Path JAVAMIX = Path.of("benchmark", "javamix", "javamix-1.0.0.jar");

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
    void javaQuoteJarFindsImportConfigTransformerChain(@TempDir Path outDir) throws Exception {
        List<Chain> chains = scan(JAVA_QUOTE, outDir.resolve("quote"));

        assertTrue(hasChain(chains, "com/quote/controller/DebugController", "importConfig",
                        "java/lang/reflect/Method", "invoke"),
                "java-quote 应检出 importConfig（反序列化源）→ Transformer → Method.invoke 链");
    }

    @Test
    @Timeout(value = 900, unit = TimeUnit.SECONDS)
    void javamixJarFindsWpChainComponents(@TempDir Path outDir) throws Exception {
        List<Chain> chains = scan(JAVAMIX, outDir.resolve("javamix"));

        // WP 双层链的真实构件（javap/WP 确认）：TreeMultimap 入口链 + MapProxy 代理构件 + vaadin 反射构件
        assertTrue(hasChain(chains, "com/google/common/collect/TreeMultimap", "readObject",
                        "java/lang/Class", "forName"),
                "javamix 应检出 TreeMultimap.readObject 入口链（WP 外层链入口）");
        assertTrue(hasChain(chains, "cn/hutool/core/map/MapProxy", "invoke",
                        "java/lang/Class", "forName"),
                "javamix 应检出 MapProxy 代理构件链（WP 外层链构件）");
        assertTrue(hasChain(chains, "com/vaadin/data/util/MethodProperty", "readObject",
                        "java/lang/reflect/Method", "invoke"),
                "javamix 应检出 vaadin MethodProperty 反射链（WP 内层链构件）");
    }

    @Test
    void deepAnalysisSurfacesJdkGadgetPrimitives(@TempDir Path outDir) throws Exception {
        // 深度分析默认开启：JDK 内部真实 gadget 原语应被检出
        List<Chain> chains = scan(UNICTF, outDir.resolve("deep"));

        assertTrue(hasChain(chains, "sun/reflect/annotation/AnnotationInvocationHandler", "invoke",
                        "java/lang/reflect/Method", "invoke"),
                "深度分析应检出 AnnotationInvocationHandler 原语（JDK7u21 链处理器）");
    }

    @Test
    void csvOutputsSortedByConfidenceWithBomAndHeaders(@TempDir Path outDir) throws Exception {
        scan(DEMO, outDir.resolve("csv"));

        for (String file : List.of("findings.csv", "edges.csv", "sinks.csv")) {
            String content = Files.readString(outDir.resolve("csv").resolve(file), StandardCharsets.UTF_8);
            assertTrue(content.startsWith("\uFEFF"), file + " 应以 BOM 开头");
            assertTrue(content.contains("\r\n"), file + " 应使用 CRLF");
        }
        // 置信度排序契约：HIGH 在前、LOW 在后（高可用链置顶）
        List<String> lines = Files.readAllLines(outDir.resolve("csv").resolve("findings.csv"),
                StandardCharsets.UTF_8);
        int previousRank = 0;
        for (int i = 1; i < lines.size(); i++) {
            String confidence = lines.get(i).split(",", -1)[4];
            int rank = switch (confidence) {
                case "HIGH" -> 0;
                case "MEDIUM" -> 1;
                default -> 2;
            };
            assertTrue(rank >= previousRank,
                    "findings.csv 应按置信度降序：第 " + i + " 行 " + confidence + " 违序");
            previousRank = rank;
        }
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
                ScanPipeline.run(jar, null, outDir, null, false, false);
        assertTrue(result.exitCode() == 0, "扫描应成功");
        return result.chains();
    }
}
