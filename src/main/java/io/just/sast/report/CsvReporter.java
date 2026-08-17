package io.just.sast.report;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.chain.ChainIds;
import io.just.sast.chain.ConfidenceScorer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CSV 报告：findings.csv（一条链一行，entry → sink 顺序）+ edges.csv（每跳明细）
 * + sinks.csv（每个 sink 的 KS2 裁决，KS1 误报被纠正的记录）。
 * RFC 4180，UTF-8 with BOM（Excel 中文兼容）。
 */
public final class CsvReporter {

    public void write(Path outDir, List<Chain> chains, Map<Long, SinkOutcome> outcomes) throws IOException {
        Files.createDirectories(outDir);
        List<Row> findings = new ArrayList<>();
        List<Row> edges = new ArrayList<>();
        // 按 (entry, sink, category) 折叠：代表链取最短路径，其余计入 variant_count
        Map<String, List<Chain>> groups = new java.util.LinkedHashMap<>();
        for (Chain chain : chains) {
            groups.computeIfAbsent(pairKey(chain), k -> new ArrayList<>()).add(chain);
        }
        // 高可用链置顶：置信度 → 质量（无未解析） → 链长 → 变体数
        List<List<Chain>> sortedGroups = new ArrayList<>(groups.values());
        sortedGroups.sort((g1, g2) -> compareGroups(g1, g2));
        int seq = 0;
        for (List<Chain> group : sortedGroups) {
            Chain representative = group.stream()
                    .min(java.util.Comparator.comparingInt(c -> c.hops().size()))
                    .orElseThrow();
            String chainId = ChainIds.id(representative.key()) + "-" + String.format("%04d", ++seq);
            findings.add(findingRow(chainId, representative, group.size()));
            edges.addAll(edgeRows(chainId, representative));
        }
        List<Row> sinks = new ArrayList<>();
        for (SinkOutcome outcome : outcomes.values()) {
            sinks.add(sinkRow(outcome));
        }
        Files.write(outDir.resolve("findings.csv"),
                toCsv(FINDINGS_HEADER, findings).getBytes(StandardCharsets.UTF_8));
        Files.write(outDir.resolve("edges.csv"),
                toCsv(EDGES_HEADER, edges).getBytes(StandardCharsets.UTF_8));
        Files.write(outDir.resolve("sinks.csv"),
                toCsv(SINKS_HEADER, sinks).getBytes(StandardCharsets.UTF_8));
    }

    private static String pairKey(Chain chain) {
        return chain.entryClass() + "#" + chain.entryMethod() + "|"
                + chain.sinkClass() + "#" + chain.sinkMethod() + "|" + chain.category();
    }

    /** 组排序：置信度（HIGH 置顶）→ 质量（无未解析优先） → 链长（短优先） → 变体数（多优先）。 */
    private static int compareGroups(List<Chain> g1, List<Chain> g2) {
        Chain c1 = g1.stream().min(java.util.Comparator.comparingInt(c -> c.hops().size())).orElseThrow();
        Chain c2 = g2.stream().min(java.util.Comparator.comparingInt(c -> c.hops().size())).orElseThrow();
        int cmp = Integer.compare(ConfidenceScorer.rank(c1), ConfidenceScorer.rank(c2));
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(c1.unresolvedHops(), c2.unresolvedHops());
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(c1.hops().size(), c2.hops().size());
        if (cmp != 0) {
            return cmp;
        }
        cmp = Integer.compare(g2.size(), g1.size());
        if (cmp != 0) {
            return cmp;
        }
        return pairKey(c1).compareTo(pairKey(c2));
    }

    private static final String FINDINGS_HEADER = "chain_id,rule_id,category,severity,confidence,quality,"
            + "entry_class,entry_method,entry_kind,sink_class,sink_method,sink_kind,"
            + "chain_length,unresolved_hops,variant_count,path,evidence";

    private static final String EDGES_HEADER = "chain_id,step,from_class,from_method,to_class,to_method,"
            + "edge_kind,field,reason";

    private static final String SINKS_HEADER = "rule_id,category,sink_class,sink_method,"
            + "enclosing_class,enclosing_method,"
            + "verdict,chains_found,steps,unresolved,too_long";

    private Row sinkRow(SinkOutcome outcome) {
        return new Row(outcome.ruleId(), outcome.category(),
                outcome.sinkOwner(), outcome.sinkMethod(),
                outcome.enclosingClass(), outcome.enclosingMethod(),
                outcome.verdict(), String.valueOf(outcome.chainsFound()),
                String.valueOf(outcome.steps()), String.valueOf(outcome.unresolved()),
                String.valueOf(outcome.tooLong()));
    }

    private Row findingRow(String chainId, Chain chain, int variantCount) {
        String confidence = ConfidenceScorer.score(chain);
        String quality = chain.unresolvedHops() > 0 ? "PARTIAL(unresolved=" + chain.unresolvedHops() + ")" : "COMPLETE";
        String path = pathSummary(chain);
        String evidence = evidence(chain);
        return new Row(chainId, chain.ruleId(), chain.category(), chain.severity(), confidence, quality,
                chain.entryClass(), chain.entryMethod(), chain.entryKind(),
                chain.sinkClass(), chain.sinkMethod(), chain.category(),
                String.valueOf(chain.hops().size()), String.valueOf(chain.unresolvedHops()),
                String.valueOf(variantCount), path, evidence);
    }

    /** entry → sink 的人读顺序：反转 hops，每跳 from → to。 */
    private String pathSummary(Chain chain) {
        StringBuilder sb = new StringBuilder();
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        for (int i = 0; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (i == 0) {
                sb.append(hop.fromOwner()).append('.').append(hop.fromName());
            }
            if (hop.kind() != HopKind.ENTRY && hop.kind() != HopKind.FIELD_FLOW) {
                sb.append(" -> ").append(hop.toOwner()).append('.').append(hop.toName());
            } else if (hop.kind() == HopKind.FIELD_FLOW) {
                sb.append(" --[").append(hop.field()).append("]--> ")
                        .append(hop.toOwner()).append('.').append(hop.toName());
            }
        }
        return sb.toString();
    }

    private String evidence(Chain chain) {
        List<String> parts = new ArrayList<>();
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.FIELD_FLOW) {
                parts.add("field:" + hop.field());
            } else if (hop.kind() == HopKind.ENTRY) {
                parts.add("entry:" + hop.reason());
            }
        }
        return String.join("; ", parts);
    }

    private List<Row> edgeRows(String chainId, Chain chain) {
        List<Row> rows = new ArrayList<>();
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        java.util.Collections.reverse(hops);
        int step = 1;
        for (ChainHop hop : hops) {
            if (hop.kind() == HopKind.ENTRY) {
                continue;
            }
            rows.add(new Row(chainId, String.valueOf(step++),
                    hop.fromOwner(), hop.fromName(), hop.toOwner(), hop.toName(),
                    edgeKind(hop.kind()), hop.field() == null ? "" : hop.field(),
                    hop.reason() == null ? "" : hop.reason()));
        }
        return rows;
    }

    private static String edgeKind(HopKind kind) {
        return switch (kind) {
            case DIRECT_CALL -> "DIRECT_CALL";
            case VIRTUAL_DISPATCH -> "VIRTUAL_DISPATCH";
            case LAMBDA -> "LAMBDA";
            case FIELD_FLOW -> "FIELD_FLOW";
            case ENTRY -> "ENTRY";
        };
    }

    private record Row(List<String> cells) {
        Row(String... values) {
            this(List.of(values));
        }
    }

    private static String toCsv(String header, List<Row> rows) {
        StringBuilder sb = new StringBuilder();
        sb.append('\uFEFF');
        sb.append(header).append("\r\n");
        for (Row row : rows) {
            for (int i = 0; i < row.cells().size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(escape(row.cells().get(i)));
            }
            sb.append("\r\n");
        }
        return sb.toString();
    }

    private static String escape(String value) {
        String v = value == null ? "" : value;
        boolean needQuote = v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r");
        if (!needQuote) {
            return v;
        }
        return '"' + v.replace("\"", "\"\"") + '"';
    }
}
