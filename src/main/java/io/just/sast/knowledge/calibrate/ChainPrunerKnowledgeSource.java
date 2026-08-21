package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.MethodInfo;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 链剪枝知识源（CALIBRATION 阶段，合并原 KS10 触发上下文 + KS11 机制去重）。
 * 两层剪枝：
 * 1. 触发上下文：hashCode/equals/compareTo/compare/toString 入口须有反序列化可达触发者（原 KS10）
 * 2. 机制去重：同机制尾按入口家族留 ≤5 条代表（原 KS11）
 * 顺序：先精化（validator）后去重（本源须在 ChainValidator 之后执行）。
 */
public final class ChainPrunerKnowledgeSource implements KnowledgeSource {

    private static final Set<String> TRIGGER_REQUIRED = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");
    private static final int MAX_FAMILIES = 5;

    private Blackboard bb;

    @Override
    public String id() {
        return "chain-pruner";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        // 1. 触发上下文
        Set<String> downstream = entryDownstream();
        int noTrigger = 0;
        for (Chain chain : bb.chains()) {
            if (!TRIGGER_REQUIRED.contains(chain.entryKind())
                    || bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            if (!hasReachableTrigger(chain, downstream)) {
                bb.calibrateChain(chain.key(), "no-trigger");
                noTrigger++;
            }
        }
        // 2. 机制去重（按家族）
        Map<String, List<Chain>> groups = new LinkedHashMap<>();
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue; // 已被前面校验拒绝的不再处理
            }
            groups.computeIfAbsent(mechanismKey(chain), k -> new ArrayList<>()).add(chain);
        }
        int dedup = 0;
        for (List<Chain> group : groups.values()) {
            group.sort(Comparator.<Chain>comparingInt(Chain::unresolvedHops)
                    .thenComparingInt(c -> c.hops().size())
                    .thenComparingInt(c -> -ConfidenceScorer.evidenceScore(c))
                    .thenComparing(Chain::key));
            Set<String> keptFamilies = new LinkedHashSet<>();
            boolean cap = false;
            for (Chain chain : group) {
                String family = entryFamily(chain.entryClass());
                if (keptFamilies.contains(family) || cap) {
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    dedup++;
                } else if (keptFamilies.size() >= MAX_FAMILIES) {
                    cap = true;
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    dedup++;
                } else {
                    keptFamilies.add(family);
                }
            }
        }
        JustLogger.info("链剪枝：无触发拒绝 {}，机制去重 {}（共 {} 条）", noTrigger, dedup, bb.chains().size());
    }

    // ---- 触发上下文（原 KS10） ----

    private boolean hasReachableTrigger(Chain chain, Set<String> downstream) {
        var support = bb.originSupport();
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (!m.strProp("owner").equals(chain.entryClass())
                    || !m.strProp("name").equals(chain.entryMethod())) {
                continue;
            }
            Set<Node> callSites = new HashSet<>();
            collectCallSites(m, callSites);
            if (callSites.isEmpty()) {
                for (String ancestor : ancestors(chain.entryClass())) {
                    Node anc = bb.graph().findMethodNode(ancestor, chain.entryMethod(), m.strProp("desc"));
                    if (anc != null) {
                        collectCallSites(anc, callSites);
                    }
                }
            }
            for (Node call : callSites) {
                String caller = call.strProp("methodOwner") + "#"
                        + call.strProp("methodName") + call.strProp("methodDesc");
                if (downstream.contains(caller)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void collectCallSites(Node methodNode, Set<Node> out) {
        for (Edge edge : methodNode.in()) {
            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                    || edge.type() == EdgeType.LAMBDA) {
                out.add(edge.from());
            }
        }
    }

    private Set<String> ancestors(String owner) {
        Set<String> result = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        var ci = bb.hierarchy().classInfo(owner);
        if (ci != null) {
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(owner));
        }
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur) || cur.equals(owner)) {
                continue;
            }
            result.add(cur);
            var c = bb.hierarchy().classInfo(cur);
            if (c == null) {
                continue;
            }
            if (c.superName() != null) {
                queue.add(c.superName());
            }
            queue.addAll(bb.hierarchy().transitiveInterfaces(cur));
        }
        return result;
    }

    private Set<String> entryDownstream() {
        var support = bb.originSupport();
        Map<String, List<Node>> callsByMethod = new HashMap<>();
        Map<String, List<String>> fieldsWrittenBy = new HashMap<>();
        Map<String, List<String>> fieldReaders = new HashMap<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            callsByMethod.computeIfAbsent(
                    io.just.sast.analysis.taint.OriginSupport.methodKey(call),
                    k -> new ArrayList<>(1)).add(call);
        }
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                    m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            for (var insn : info.instructions()) {
                if (insn.op().isFieldRead() || insn.op().isFieldWrite()) {
                    String fieldKey = insn.fieldRef().owner() + "#" + insn.fieldRef().name();
                    if (insn.op().isFieldRead()) {
                        fieldReaders.computeIfAbsent(fieldKey, k -> new ArrayList<>(1)).add(key);
                    } else {
                        fieldsWrittenBy.computeIfAbsent(key, k -> new ArrayList<>(1)).add(fieldKey);
                    }
                }
            }
        }
        Set<String> downstream = new HashSet<>();
        Deque<Node> work = new ArrayDeque<>();
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (io.just.sast.config.RuleEngine.matchingEntry(bb.rules(), bb.hierarchy(),
                    m.strProp("owner"), m.strProp("name"), m.strProp("desc")).isPresent()
                    && downstream.add(io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                            m.strProp("owner"), m.strProp("name"), m.strProp("desc")))) {
                work.add(m);
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (io.just.sast.analysis.taint.OriginSupport.isOisRead(call)) {
                Node host = bb.graph().findMethodNode(call.strProp("methodOwner"),
                        call.strProp("methodName"), call.strProp("methodDesc"));
                if (host != null && downstream.add(io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                        host.strProp("owner"), host.strProp("name"), host.strProp("desc")))) {
                    work.add(host);
                }
            }
        }
        while (!work.isEmpty()) {
            Node m = work.poll();
            String key = io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                    m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            List<Node> calls = callsByMethod.get(key);
            if (calls != null) {
                for (Node call : calls) {
                    for (Edge edge : call.out()) {
                        if (downstream.add(io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                                edge.to().strProp("owner"), edge.to().strProp("name"),
                                edge.to().strProp("desc")))) {
                            work.add(edge.to());
                        }
                    }
                }
            }
            List<String> written = fieldsWrittenBy.get(key);
            if (written != null) {
                for (String fieldKey : written) {
                    for (String reader : fieldReaders.getOrDefault(fieldKey, List.of())) {
                        if (downstream.add(reader)) {
                            Node rn = methodNodeOf(reader);
                            if (rn != null) {
                                work.add(rn);
                            }
                        }
                    }
                }
            }
        }
        return downstream;
    }

    private Node methodNodeOf(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        if (sep < 0 || paren < 0) {
            return null;
        }
        return bb.graph().findMethodNode(key.substring(0, sep),
                key.substring(sep + 1, paren), key.substring(paren));
    }

    // ---- 机制去重（原 KS11） ----

    private static String mechanismKey(Chain chain) {
        StringBuilder sb = new StringBuilder();
        sb.append(chain.sinkClass()).append('.').append(chain.sinkMethod())
                .append('|').append(chain.category()).append('|');
        List<ChainHop> hops = chain.hops();
        for (int i = 1; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.kind() == HopKind.ENTRY) {
                continue;
            }
            sb.append(hop.toOwner()).append('.').append(hop.toName()).append('.')
                    .append(hop.field() != null ? hop.field() : "").append(';');
        }
        return sb.toString();
    }

    private static String entryFamily(String entryClass) {
        String[] parts = entryClass.split("/");
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1];
        }
        return entryClass;
    }
}
