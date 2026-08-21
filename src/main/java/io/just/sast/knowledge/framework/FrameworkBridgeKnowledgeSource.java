package io.just.sast.knowledge.framework;

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
import io.just.sast.model.MethodRef;
import io.just.sast.util.JustLogger;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 统一框架桥接引擎（ANALYSIS 阶段，自足，合并原 KS12/KS13/KS14）。
 * 从 YAML source 规则读取框架清单（bridge=deserialize 的反序列化入口 + bridge=serialize 的序列化入口），
 * 以包前缀剪枝 BFS 桥接到反射 sink（Method.invoke / Constructor.newInstance / Class.forName）。
 *
 * 引擎只做一件事：框架入口 → 框架包内 BFS → 反射 sink 的管线桥接。
 * 哪些框架、哪些方法、哪个方向——全部由规则声明，引擎零硬编码。
 */
public final class FrameworkBridgeKnowledgeSource implements KnowledgeSource {

    private static final int MAX_DEPTH = 12;
    private static final int MAX_CHAINS = 200;

    private Blackboard bb;
    private OriginSupport support;

    @Override
    public String id() {
        return "framework-bridge";
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
        List<Rule.SourceRule> sources = bb.rules().sources();
        if (sources.isEmpty()) {
            return;
        }
        int chains = 0;
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (chains >= MAX_CHAINS) {
                break;
            }
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
                if (!(insn.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                // 匹配 source 规则（规则驱动，非硬编码）
                Rule.SourceRule matched = null;
                for (Rule.SourceRule src : sources) {
                    if (src.call().matches(ref.owner(), ref.name(), ref.descriptor())) {
                        matched = src;
                        break;
                    }
                }
                if (matched == null) {
                    continue;
                }
                Long callId = support.callId(methodKey, insn.offset());
                if (callId == null) {
                    continue;
                }
                Node fwCall = bb.graph().node(callId);
                // 管线 BFS（包前缀剪枝）到反射 sink
                Node sinkCall = findReflectiveSink(fwCall, ref.owner());
                if (sinkCall == null) {
                    continue;
                }
                var sinkRule = RuleEngine.matchingSink(bb.rules(), bb.hierarchy(), sinkCall);
                if (sinkRule.isEmpty()) {
                    continue;
                }
                Chain chain = assemble(info, fwCall, sinkCall, sinkRule.get(), matched);
                if (chain != null && bb.addChain(chain)) {
                    chains++;
                }
            }
        }
        JustLogger.info("框架桥接[规则驱动]：产链 {} 条", chains);
    }

    /** 包前缀剪枝 BFS：从框架入口沿同包方法到反射 sink。 */
    private Node findReflectiveSink(Node fwCall, String fwOwner) {
        String fwPrefix = packagePrefix(fwOwner, 3);
        Deque<Node> work = new ArrayDeque<>();
        Set<Long> visited = new HashSet<>();
        work.add(fwCall);
        visited.add(fwCall.id());
        int depth = 0;
        while (!work.isEmpty() && depth < MAX_DEPTH) {
            int size = work.size();
            for (int i = 0; i < size; i++) {
                Node call = work.poll();
                for (Edge edge : call.out()) {
                    if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                        continue;
                    }
                    Node callee = edge.to();
                    String owner = callee.strProp("owner");
                    String name = callee.strProp("name");
                    if (isReflectiveSink(owner, name)) {
                        return call;
                    }
                    boolean inFramework = owner.startsWith(fwPrefix);
                    if (!inFramework) {
                        continue;
                    }
                    String key = OriginSupport.methodKeyOf(owner, name, callee.strProp("desc"));
                    MethodInfo info = support.methodOf(owner, name, callee.strProp("desc"));
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

    private static boolean isReflectiveSink(String owner, String name) {
        return ("java/lang/reflect/Method".equals(owner) && "invoke".equals(name))
                || ("java/lang/reflect/Constructor".equals(owner) && "newInstance".equals(name))
                || ("java/lang/Class".equals(owner) && ("forName".equals(name) || "newInstance".equals(name)));
    }

    private Chain assemble(MethodInfo entryMethod, Node fwCall, Node sinkCall,
                           Rule.SinkRule rule, Rule.SourceRule source) {
        MethodInfo sinkEnclosing = support.enclosingMethod(sinkCall);
        if (sinkEnclosing == null) {
            return null;
        }
        List<ChainHop> hops = new ArrayList<>();
        hops.add(new ChainHop(sinkEnclosing.owner(), sinkEnclosing.name(),
                sinkEnclosing.owner(), sinkEnclosing.name(),
                HopKind.DIRECT_CALL, null, source.bridge(), sinkEnclosing.descriptor(), null));
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                fwCall.strProp("owner"), fwCall.strProp("name"),
                HopKind.DIRECT_CALL, null, source.bridge(), fwCall.strProp("desc"), null));
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                entryMethod.owner(), entryMethod.name(),
                HopKind.ENTRY, null, "deserialization", "", null));
        return new Chain(rule.id(), rule.category(), rule.severity(),
                entryMethod.owner(), entryMethod.name(), "deserialization",
                sinkCall.strProp("owner"), sinkCall.strProp("name"), hops, 0);
    }

    private static String packagePrefix(String internalName, int segments) {
        String[] parts = internalName.split("/");
        int n = Math.min(segments, parts.length - 1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append('/');
            }
            sb.append(parts[i]);
        }
        return sb.toString();
    }
}
