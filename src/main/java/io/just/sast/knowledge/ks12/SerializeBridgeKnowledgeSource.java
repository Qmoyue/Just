package io.just.sast.knowledge.ks12;

import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * KS12 序列化框架桥接（ANALYSIS 阶段，自足）。
 * 领域建模：当 magic-entry 方法（toString/readObject/hashCode/equals/proxyInvoke 等）
 * 调用序列化框架的"对象→字符串"入口（jackson/gson/fastjson/XStream 等），
 * 序列化管线以反射调用 getter/setter（Method.invoke）来获取字段——被序列化对象上的
 * 任何 getter 都成为攻击面。KS2/KS4/KS5 在框架管线深处（接口多态跳、数十候选）
 * 预算耗尽无法串通——本源以调用图 BFS 直接桥接管线，补足缺失段。
 */
public final class SerializeBridgeKnowledgeSource implements KnowledgeSource {

    /** 框架入口（owner 前缀 → 方法名集合），内置声明式清单。 */
    private record FrameworkEntry(String ownerPrefix, Set<String> methodNames) {}

    private static final List<FrameworkEntry> FRAMEWORKS = List.of(
            new FrameworkEntry("com/fasterxml/jackson/databind/ObjectMapper",
                    Set.of("writeValueAsString", "writeValueAsBytes", "writeValue")),
            new FrameworkEntry("com/fasterxml/jackson/databind/ObjectWriter",
                    Set.of("writeValueAsString", "writeValueAsBytes", "writeValue")),
            new FrameworkEntry("com/fasterxml/jackson/databind/node/InternalNodeMapper",
                    Set.of("nodeToString")),
            new FrameworkEntry("com/alibaba/fastjson2/JSON",
                    Set.of("toJSONString", "toJSONBytes", "writeTo")),
            new FrameworkEntry("com/alibaba/fastjson2/JSONObject",
                    Set.of("toString", "toJSONString")),
            new FrameworkEntry("com/alibaba/fastjson2/JSONArray",
                    Set.of("toString", "toJSONString")),
            new FrameworkEntry("com/alibaba/fastjson/JSON",
                    Set.of("toJSONString", "toJSONBytes", "writeJSONString")),
            new FrameworkEntry("com/alibaba/fastjson/JSONObject",
                    Set.of("toJSONString")),
            new FrameworkEntry("com/alibaba/fastjson/JSONArray",
                    Set.of("toJSONString")),
            new FrameworkEntry("com/google/gson/Gson",
                    Set.of("toJson")),
            new FrameworkEntry("com/thoughtworks/xstream/XStream",
                    Set.of("toXML")),
            new FrameworkEntry("org/yaml/snakeyaml/Yaml",
                    Set.of("dump", "dumpAs")),
            new FrameworkEntry("cn/hutool/json/JSONUtil",
                    Set.of("toJsonStr")));

    /** 管线 BFS 深度上限。 */
    private static final int MAX_PIPELINE_DEPTH = 12;
    /** 产出链总数上限。 */
    private static final int MAX_CHAINS = 200;

    private Blackboard bb;
    private OriginSupport support;

    @Override
    public String id() {
        return "serialize-bridge";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
        this.support = blackboard.originSupport();
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        Map<String, List<FrameworkCall>> entryCalls = discoverEntryCalls();
        if (entryCalls.isEmpty()) {
            JustLogger.info("KS12 序列化桥接：无框架入口调用");
            return;
        }
        int chains = 0;
        for (Map.Entry<String, List<FrameworkCall>> entry : entryCalls.entrySet()) {
            if (chains >= MAX_CHAINS) {
                break;
            }
            MethodInfo entryMethod = support.methodOf(splitOwner(entry.getKey()),
                    splitName(entry.getKey()), splitDesc(entry.getKey()));
            if (entryMethod == null) {
                continue;
            }
            var entryRule = RuleEngine.matchingEntry(bb.rules(), bb.hierarchy(),
                    entryMethod.owner(), entryMethod.name(), entryMethod.descriptor());
            String entryKind = entryRule.map(r -> r.entryKind()).orElse("deserialization");
            for (FrameworkCall fwCall : entry.getValue()) {
                Node sinkCall = fwCall.sinkCall();
                var sinkRule = RuleEngine.matchingSink(bb.rules(), bb.hierarchy(), sinkCall);
                if (sinkRule.isEmpty()) {
                    continue;
                }
                Chain chain = assemble(entryMethod, entryKind, fwCall, sinkCall, sinkRule.get());
                if (chain != null && bb.addChain(chain)) {
                    chains++;
                }
            }
        }
        JustLogger.info("KS12 序列化桥接：产链 {} 条", chains);
    }

    /** 发现 magic-entry 方法内的框架入口调用。key = entryMethodKey。 */
    private Map<String, List<FrameworkCall>> discoverEntryCalls() {
        Map<String, List<FrameworkCall>> result = new HashMap<>();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.strProp("owner"),
                    method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            String methodKey = OriginSupport.methodKey(info);
            for (InsnFact insn : info.instructions()) {
                if (!insn.op().isInvoke() || insn.operands().isEmpty()) {
                    continue;
                }
                if (!(insn.operands().get(0) instanceof io.just.sast.model.MethodRef ref)) {
                    continue; // invokedynamic 等非方法引用指令
                }
                if (!isFrameworkEntry(ref.owner(), ref.name())) {
                    continue;
                }
                Long callId = support.callId(methodKey, insn.offset());
                if (callId == null) {
                    continue;
                }
                Node callNode = bb.graph().node(callId);
                // 找管线终点：从框架入口方法 BFS 到 Method.invoke
                String pipelineKey = ref.owner() + "#" + ref.name();
                Node sinkCall = findPipelineSink(callNode);
                if (sinkCall != null) {
                    result.computeIfAbsent(methodKey, k -> new ArrayList<>(1))
                            .add(new FrameworkCall(callNode, sinkCall, pipelineKey));
                }
            }
        }
        return result;
    }

    private boolean isFrameworkEntry(String owner, String name) {
        for (FrameworkEntry fw : FRAMEWORKS) {
            if (owner.startsWith(fw.ownerPrefix()) && fw.methodNames().contains(name)) {
                return true;
            }
        }
        return false;
    }

    /** 从框架入口调用点沿调用边 BFS 找 Method.invoke sink（管线终点）。 */
    private Node findPipelineSink(Node frameworkCall) {
        Deque<Node> work = new ArrayDeque<>();
        Set<Long> visited = new HashSet<>();
        work.add(frameworkCall);
        visited.add(frameworkCall.id());
        int depth = 0;
        while (!work.isEmpty() && depth < MAX_PIPELINE_DEPTH) {
            int size = work.size();
            for (int i = 0; i < size; i++) {
                Node call = work.poll();
                for (Edge edge : call.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                        continue;
                    }
                    Node calleeMethod = edge.to();
                    // 是 Method.invoke？
                    if ("java/lang/reflect/Method".equals(calleeMethod.strProp("owner"))
                            && "invoke".equals(calleeMethod.strProp("name"))) {
                        // 找到管线终点：回溯这个 invoke 的 CALL 节点
                        for (Edge in : calleeMethod.in()) {
                            if (in.type() != EdgeType.INVOKES && in.type() != EdgeType.DISPATCHES) {
                                continue;
                            }
                            // in.from() 是 invoke 的调用点；但可能不是从当前 BFS 路径来的——
                            // 简化：返回第一个 Method.invoke 调用点（管线唯一终点假设）
                            // 更精确的做法是记录 BFS parent
                            return in.from();
                        }
                    }
                    // 展开此方法体内的调用
                    String key = OriginSupport.methodKeyOf(calleeMethod.strProp("owner"),
                            calleeMethod.strProp("name"), calleeMethod.strProp("desc"));
                    MethodInfo info = support.methodOf(calleeMethod.strProp("owner"),
                            calleeMethod.strProp("name"), calleeMethod.strProp("desc"));
                    if (info == null) {
                        continue;
                    }
                    for (InsnFact insn : info.instructions()) {
                        if (!insn.op().isInvoke()) {
                            continue;
                        }
                        Long callId = support.callId(key, insn.offset());
                        if (callId != null) {
                            Node nextCall = bb.graph().node(callId);
                            if (visited.add(nextCall.id())) {
                                work.add(nextCall);
                            }
                        }
                    }
                }
            }
            depth++;
        }
        return null;
    }

    /** 组装链：entry → 框架入口调用跳 → Method.invoke sink（简化三跳桥接，管线内部以 reason 标记）。 */
    private Chain assemble(MethodInfo entryMethod, String entryKind, FrameworkCall fwCall,
                           Node sinkCall, Rule.SinkRule rule) {
        MethodInfo sinkEnclosing = support.enclosingMethod(sinkCall);
        if (sinkEnclosing == null) {
            return null;
        }
        List<ChainHop> hops = new ArrayList<>();
        // sink 侧：invoke 所在方法（如 BeanPropertyWriter.serializeAsField）
        hops.add(new ChainHop(sinkEnclosing.owner(), sinkEnclosing.name(),
                sinkEnclosing.owner(), sinkEnclosing.name(),
                HopKind.DIRECT_CALL, null, "serialize-bridge", sinkEnclosing.descriptor(), null));
        // 框架入口调用跳
        Node fwNode = fwCall.frameworkCall();
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                fwNode.strProp("owner"), fwNode.strProp("name"),
                HopKind.DIRECT_CALL, null, "serialize-bridge", fwNode.strProp("desc"), null));
        // 入口跳（entry-last 格式）
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                entryMethod.owner(), entryMethod.name(),
                HopKind.ENTRY, null, entryKind, "", null));
        return new Chain(rule.id(), rule.category(), rule.severity(),
                entryMethod.owner(), entryMethod.name(), entryKind,
                sinkCall.strProp("owner"), sinkCall.strProp("name"), hops, 0);
    }

    // ---- 工具 ----

    private static String splitOwner(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        return key.substring(0, sep);
    }

    private static String splitName(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        return key.substring(sep + 1, paren);
    }

    private static String splitDesc(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        return key.substring(paren);
    }

    /** 框架入口调用点 + 管线终点。 */
    private record FrameworkCall(Node frameworkCall, Node sinkCall, String pipelineKey) {}
}
