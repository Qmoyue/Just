package io.just.sast.knowledge.ks10;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
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
 * KS10 触发上下文校准（CALIBRATION 阶段）。
 * hashCode/equals/compareTo/compare/toString 类入口不被 OIS 机制自动调用——链要成立，
 * 必须有反序列化可达的调用者触发入口方法（HashMap.readObject→hash(key)→hashCode、
 * TreeMap→compareTo、BadAttributeValueExpException.readObject→val.toString 等）。
 * 入口方法在"入口/OIS 宿主下游集"（含字段中介边，与 KS2 剪枝集同构）内无任何调用者
 * → 链不可能在反序列化过程中触发，拒绝。机制调用的入口类别（readObject 族/proxyInvoke/
 * deserialization）不校验。
 */
public final class TriggerContextKnowledgeSource implements KnowledgeSource {

    /** 须触发者的入口类别（OIS 机制不自动调用）。 */
    private static final Set<String> TRIGGER_REQUIRED = Set.of(
            "hashCode", "equals", "compareTo", "compare", "toString");

    private Blackboard bb;

    @Override
    public String id() {
        return "trigger-context";
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
        Set<String> downstream = entryDownstream();
        int rejected = 0;
        int checked = 0;
        for (Chain chain : bb.chains()) {
            if (!TRIGGER_REQUIRED.contains(chain.entryKind())
                    || bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            checked++;
            if (!hasReachableTrigger(chain, downstream)) {
                bb.calibrateChain(chain.key(), "no-trigger");
                rejected++;
            }
        }
        JustLogger.info("KS10 触发上下文：校验 {} 条链，拒绝 {} 条（无反序列化可达触发者）", checked, rejected);
    }

    /**
     * 入口方法是否存在下游集内调用者。入边为空时并入祖先类型（传递接口/父类链）上
     * 同名方法的调用点——接口/根类声明的虚调用因 CHA 超上限未物化到实现类入边
     * （如 Object.hashCode 的调用点不会连到 Dog.hashCode），与 KS2 反向分发同款。
     */
    private boolean hasReachableTrigger(Chain chain, Set<String> downstream) {
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (!m.strProp("owner").equals(chain.entryClass())
                    || !m.strProp("name").equals(chain.entryMethod())) {
                continue;
            }
            Set<Node> callSites = new HashSet<>();
            collectCallSites(m, callSites);
            if (callSites.isEmpty()) {
                for (String ancestor : ancestors(chain.entryClass())) {
                    Node ancestorNode = bb.graph().findMethodNode(ancestor,
                            chain.entryMethod(), m.strProp("desc"));
                    if (ancestorNode != null) {
                        collectCallSites(ancestorNode, callSites);
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

    /** 祖先类型集合：传递接口 + 父类链（不含自身）。 */
    private Set<String> ancestors(String owner) {
        Set<String> result = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        ClassInfo ci = bb.hierarchy().classInfo(owner);
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
            ClassInfo c = bb.hierarchy().classInfo(cur);
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

    /**
     * 入口/OIS 宿主下游集：从 magic entry 方法与 OIS 读宿主沿调用边 + 字段中介边
     * （下游方法写入字段的读者可经字段流获得污点）BFS，与 KS2 剪枝集同构。
     */
    private Set<String> entryDownstream() {
        var support = bb.originSupport();
        Map<String, List<Node>> callsByMethod = new HashMap<>();
        Map<String, List<String>> fieldsWrittenBy = new HashMap<>();
        Map<String, List<String>> fieldReaders = new HashMap<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            callsByMethod.computeIfAbsent(io.just.sast.analysis.taint.OriginSupport.methodKey(call),
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
                            Node readerNode = methodNodeOf(reader);
                            if (readerNode != null) {
                                work.add(readerNode);
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
}
