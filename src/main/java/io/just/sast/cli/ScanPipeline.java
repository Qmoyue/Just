package io.just.sast.cli;

import io.just.sast.analysis.callgraph.CallGraphBuilder;
import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Controller;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.config.RuleSet;
import io.just.sast.config.YamlRuleLoader;
import io.just.sast.cpg.build.BuiltCpg;
import io.just.sast.cpg.build.CpgBuilder;
import io.just.sast.frontend.asm.BytecodeFrontend;
import io.just.sast.frontend.asm.JrtClassSource;
import io.just.sast.frontend.asm.LoadResult;
import io.just.sast.report.ConsoleSummary;
import io.just.sast.report.CsvReporter;
import io.just.sast.report.ScanStatistics;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** 扫描管线编排：frontend → 层次 → CPG → 调用图 → 黑板（KS1+KS2 交叉并行）→ CSV。 */
public final class ScanPipeline {

    /** 反向回溯深度上限（内部固定，不暴露参数）。 */
    private static final int MAX_DEPTH = 20;

    private ScanPipeline() {}

    public static final class UsageException extends Exception {
        public UsageException(String message) {
            super(message);
        }
    }

    /** 扫描结果。 */
    public record ScanResult(int exitCode, List<Chain> chains, ScanStatistics stats) {}

    public static ScanResult run(Path target, List<Path> deps, Path output, Path rules,
                                 boolean stats, boolean fast) throws Exception {
        long start = System.currentTimeMillis();

        // 规则
        RuleSet ruleSet;
        try {
            ruleSet = loadRules(rules);
        } catch (IOException e) {
            throw new UsageException("规则加载失败: " + e.getMessage());
        }

        // 输入目标
        List<Path> targets = new ArrayList<>();
        targets.add(target);
        if (deps != null) {
            targets.addAll(deps);
        }

        // 构建期（深度分析默认：JDK 运行库全量纳入）
        BytecodeFrontend frontend = new BytecodeFrontend();
        LoadResult load = fast
                ? frontend.load(targets)
                : frontend.load(targets, new JrtClassSource().listAll(JrtClassSource.DESER_MODULES));
        JustLogger.info("解析完成：{} 个类（{} 个文件），诊断 {} 条",
                load.classCount(), load.filesScanned(), load.diagnosticCount());

        ClassHierarchy hierarchy = new ClassHierarchy(load.classes(), new JrtClassSource());
        BuiltCpg cpg = new CpgBuilder().build(load);
        int callEdges = new CallGraphBuilder(hierarchy).build(cpg.graph());
        JustLogger.info("CPG 构建完成：节点 {}，边 {}，调用边 {}，字段写入 {} 组",
                cpg.graph().nodeCount(), cpg.graph().edgeCount(), callEdges,
                cpg.fieldWriters().fieldCount());

        // 分析期（黑板循环：KS1 标记与 KS2 反向污点交叉并行，各自独立写黑板）
        Blackboard blackboard = new Blackboard(cpg.graph(), hierarchy, cpg.fieldWriters(), ruleSet, MAX_DEPTH);
        new Controller(blackboard, KnowledgeSources.discover()).run();

        // 报告期
        CsvReporter reporter = new CsvReporter();
        reporter.write(output, blackboard.chains(), blackboard.sinkOutcomes());
        JustLogger.info("CSV 已输出到 {}", output.toAbsolutePath());

        ScanStatistics scanStats = new ScanStatistics(
                load.filesScanned(), load.classCount(), load.diagnosticCount(),
                blackboard.sinkCount(), blackboard.entryCount(), blackboard.chains().size(),
                System.currentTimeMillis() - start,
                (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()) / 1024 / 1024);
        if (stats) {
            ConsoleSummary.print(scanStats, blackboard.sinkOutcomes());
        }
        return new ScanResult(ExitCode.OK.code(), blackboard.chains(), scanStats);
    }

    private static RuleSet loadRules(Path rulesFile) throws IOException {
        YamlRuleLoader loader = new YamlRuleLoader();
        if (rulesFile != null) {
            try (InputStream in = Files.newInputStream(rulesFile)) {
                return loader.load(in);
            }
        }
        try (InputStream in = ScanPipeline.class.getResourceAsStream("/rules/default-rules.yaml")) {
            return loader.load(in);
        }
    }
}
