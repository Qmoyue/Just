package io.just.sast.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/** scan 子命令：扫描 JAR/目录，输出 gadget 链 CSV。 */
@Command(name = "scan", description = "扫描 JAR/class 目录，挖掘反序列化 gadget 链并导出 CSV")
public final class ScanCommand implements Callable<Integer> {

    @Option(names = "--jar", required = true, paramLabel = "<jar|dir>",
            description = "目标 JAR 或 class 目录（支持 Spring Boot fat jar）")
    Path target;

    @Option(names = "--deps", split = ",", paramLabel = "<jar|dir,...>",
            description = "附加依赖（逗号分隔）")
    List<Path> deps;

    @Option(names = "--output", paramLabel = "<dir>", defaultValue = "just-out",
            description = "CSV 输出目录（默认 just-out）")
    Path output;

    @Option(names = "--rules", paramLabel = "<file>",
            description = "自定义规则 YAML（默认内置规则）")
    Path rules;

    @Option(names = "--max-depth", paramLabel = "<n>", defaultValue = "20",
            description = "反向回溯深度上限（默认 20）")
    int maxDepth;

    @Option(names = "--jdk", description = "将 JDK 运行库（java.base/naming/rmi/management/scripting/sql）全量纳入分析，挖掘穿过 JDK 类的完整链")
    boolean jdk;

    @Option(names = "--stats", description = "输出扫描统计")
    boolean stats;

    @Option(names = {"-v", "--verbose"}, description = "调试日志")
    boolean verbose;

    @Override
    public Integer call() {
        try {
            return ScanPipeline.run(target, deps, output, rules, maxDepth, stats, verbose, jdk).exitCode();
        } catch (ScanPipeline.UsageException e) {
            System.err.println("[just:error] " + e.getMessage());
            return ExitCode.USAGE.code();
        } catch (Exception e) {
            System.err.println("[just:error] 扫描失败: " + e.getMessage());
            if (verbose) {
                e.printStackTrace();
            }
            return ExitCode.INTERNAL.code();
        }
    }
}
