package io.just.sast.knowledge.ks2;

import io.just.sast.analysis.taint.ForwardOrigins;
import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.SinkMark;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;

import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * KS2 反向污点引擎（独立知识源，ANALYSIS 阶段）。
 * 自行按规则枚举 sink 候选（不读 KS1 的标记），反向回答"该值是否攻击者可控"，
 * 产物（链 + 裁决）写黑板。上下文不敏感（所有调用点合并），靠预算、去环与 KS3 校准控制噪声。
 *
 * 可控语义（controlled）：
 * 1. ObjectInputStream.readObject/readUnshared/readFields 调用结果无条件可控（反序列化威胁模型）
 * 2. magic entry 的 this / proxy-invoke 的 args 可控
 * 3. 可控对象的字段可控（Serializable 且非 transient；GadgetInspector 传递对象语义）
 * 4. 存入可控值的字段可控（程序字段污点，写者回溯）
 * 5. 可控数组的元素可控；数组元素可控则数组可控
 * 6. 可控 receiver 的方法返回值可控；任一实参可控的返回值可控（passthrough）
 */
public final class BackwardTaintAnalysis implements KnowledgeSource {

    private static final int MAX_CHAINS_PER_SINK = 20;
    /** 每 sink 步数预算：须覆盖分发图扇出（层次修复后图正确变宽），全局预算另行兜底。 */
    private static final int STEP_BUDGET = 200_000;
    /** 全局步数兜底（终止保证）：须随分发图规模放宽，图表越大首达探索越多。 */
    private static final int GLOBAL_BUDGET = 60_000_000;
    private static final int MAX_WRITERS_PER_FIELD = 10;
    private static final int MAX_HOPS = 10;
    /** 单方法调用者枚举上限：OIS.readObject 等枢纽方法调用者极多，上限过低会按边序误截深链。 */
    private static final int MAX_CALLERS = 10_000;
    /** 祖先反向分发（入边为空时的启发式补全）调用点枚举上限：控制探索成本。 */
    private static final int MAX_MERGED_CALLERS = 300;

    private final Set<String> deadEnds = new HashSet<>();
    private final Map<String, Optional<Rule.MagicEntryRule>> entryRuleCache = new HashMap<>();
    /** 双向剪枝：祖先链可达任一 magic entry / OIS 宿主的方法键（回溯只探索这些方法）。 */
    private final Set<String> entryReaching = new HashSet<>();
    private Blackboard bb;
    private OriginSupport support;
    private int globalSteps;

    @Override
    public String id() {
        return "backward-taint";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
        this.support = blackboard.originSupport();
        computeEntryReaching(blackboard);
    }

    /**
     * 双向剪枝集：从 magic entry 方法与 OIS 读宿主出发的下游可达方法
     * （沿调用边 + 字段中介边——下游方法写入的字段，其读者可经字段流获得污点）。
     * 链形如 entry →…→ caller →…→ sink：回溯中跳过不在下游集内的方法——可证明无链完成路径，纯噪声。
     */
    private void computeEntryReaching(Blackboard bb) {
        // 方法键 → 该方法体内的 CALL 节点；方法键 → 其写入的字段键；字段键 → 读它的方法节点
        Map<String, List<Node>> callsByMethod = new HashMap<>();
        Map<String, List<String>> fieldsWrittenBy = new HashMap<>();
        Map<String, List<Node>> fieldReaders = new HashMap<>();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            callsByMethod.computeIfAbsent(OriginSupport.methodKey(call),
                    k -> new ArrayList<>()).add(call);
        }
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = OriginSupport.methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            for (io.just.sast.model.InsnFact insn : info.instructions()) {
                if (insn.op().isFieldRead()) {
                    String fieldKey = insn.fieldRef().owner() + "#" + insn.fieldRef().name();
                    fieldReaders.computeIfAbsent(fieldKey, k -> new ArrayList<>()).add(m);
                } else if (insn.op().isFieldWrite()) {
                    String fieldKey = insn.fieldRef().owner() + "#" + insn.fieldRef().name();
                    fieldsWrittenBy.computeIfAbsent(key, k -> new ArrayList<>(1)).add(fieldKey);
                }
            }
        }
        Deque<Node> work = new ArrayDeque<>();
        for (Node m : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (RuleEngine.matchingEntry(bb.rules(), bb.hierarchy(), m.strProp("owner"),
                    m.strProp("name"), m.strProp("desc")).isPresent()
                    && entryReaching.add(OriginSupport.methodKeyOf(
                            m.strProp("owner"), m.strProp("name"), m.strProp("desc")))) {
                work.add(m);
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (OriginSupport.isOisRead(call)) {
                Node host = bb.graph().findMethodNode(call.strProp("methodOwner"),
                        call.strProp("methodName"), call.strProp("methodDesc"));
                if (host != null && entryReaching.add(OriginSupport.methodKeyOf(
                        host.strProp("owner"), host.strProp("name"), host.strProp("desc")))) {
                    work.add(host);
                }
            }
        }
        while (!work.isEmpty()) {
            Node m = work.poll();
            String key = OriginSupport.methodKeyOf(m.strProp("owner"), m.strProp("name"), m.strProp("desc"));
            List<Node> calls = callsByMethod.get(key);
            if (calls != null) {
                for (Node call : calls) {
                    for (Edge edge : call.out()) {
                        Node callee = edge.to();
                        if (entryReaching.add(OriginSupport.methodKeyOf(callee.strProp("owner"),
                                callee.strProp("name"), callee.strProp("desc")))) {
                            work.add(callee);
                        }
                    }
                }
            }
            // 字段中介：m 写入的字段，其读者可经字段流获得污点（调用边之外的链完成路径）
            List<String> written = fieldsWrittenBy.get(key);
            if (written != null) {
                for (String fieldKey : written) {
                    List<Node> readers = fieldReaders.get(fieldKey);
                    if (readers == null) {
                        continue;
                    }
                    for (Node reader : readers) {
                        if (entryReaching.add(OriginSupport.methodKeyOf(reader.strProp("owner"),
                                reader.strProp("name"), reader.strProp("desc")))) {
                            work.add(reader);
                        }
                    }
                }
            }
        }
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        // 独立枚举 sink 候选：不读 KS1 的标记
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            RuleEngine.matchingSink(bb.rules(), bb.hierarchy(), call).ifPresent(rule ->
                    analyzeSink(call.id(), new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted())));
        }
    }

    private void analyzeSink(long callNodeId, SinkMark mark) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = support.enclosingMethod(call);
        if (method == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return;
        }
        if (!entryReaching.contains(OriginSupport.methodKey(method))) {
            // sink 宿主方法不在入口下游集内：可证明无链
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_PATH"));
            return;
        }
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_STATE"));
            return;
        }
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
        int produced = 0;
        Trace trace = new Trace(call.strProp("owner"), call.strProp("name"));
        for (Rule.TaintedPos pos : mark.tainted()) {
            int depthFromTop;
            if (pos instanceof Rule.TaintedPos.Arg a) {
                depthFromTop = paramCount - 1 - a.index();
            } else {
                depthFromTop = paramCount;
            }
            if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : state.stack().get(state.stack().size() - 1 - depthFromTop).origins()) {
                if (produced >= MAX_CHAINS_PER_SINK) {
                    break;
                }
                produced += controlled(origin, method, 0, trace, mark);
            }
        }
        String verdict;
        if (produced > 0) {
            verdict = "CHAIN";
        } else if (trace.steps > STEP_BUDGET) {
            verdict = "TRUNCATED";
        } else if (trace.tooLong > 0) {
            verdict = "TOO_LONG";
        } else if (trace.unresolved > 0) {
            verdict = "UNRESOLVED";
        } else {
            verdict = "NO_PATH";
        }
        bb.recordOutcome(callNodeId, outcome(call, mark, produced, trace.steps, trace.unresolved, trace.tooLong, verdict));
    }

    /** 返回：该值可控所产出的链数。 */
    private int controlled(ValueOrigin origin, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        if (depth > bb.maxDepth() || trace.steps > STEP_BUDGET || globalSteps > GLOBAL_BUDGET) {
            return 0;
        }
        // 预算尾部截断的结果不可靠，不写入死胡同缓存（防假阴性污染）：全局与每 sink 步数都要看
        boolean nearBudget = globalSteps > GLOBAL_BUDGET * 4 / 5 || trace.steps > STEP_BUDGET * 4 / 5;
        // 深度接近上限的结果受截断影响，不记忆化也不查询（深度无关键的不健全）
        boolean memoizable = depth <= bb.maxDepth() / 2;
        globalSteps++;
        String memoKey = OriginSupport.methodKey(method) + "|" + origin;
        if ((memoizable && deadEnds.contains(memoKey)) || trace.visited.contains(memoKey)) {
            return 0;
        }
        trace.visited.add(memoKey);
        int produced;
        if (origin instanceof ValueOrigin.Param p) {
            produced = controlledParam(p.slot(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.Insn insn) {
            produced = controlledInsn(insn.offset(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.CallResult callResult) {
            produced = controlledCallResult(callResult.callNodeId(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.FieldRead fieldRead) {
            produced = controlledFieldRead(fieldRead, method, depth, trace, mark);
        } else {
            produced = 0; // 常量不可控
        }
        trace.visited.remove(memoKey);
        if (produced == 0 && memoizable && !nearBudget) {
            deadEnds.add(memoKey);
        }
        return produced;
    }

    /** 参数：magic entry 的 this 可控、proxy 入口 args 可控；否则回溯调用者实参（上下文不敏感）。 */
    private int controlledParam(int slot, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        Rule.MagicEntryRule entry = entryRuleOf(method);
        if (entry != null) {
            if (slot == 0) {
                // 入口对象本身由反序列化构造，可控（对象图语义的根）
                return completeChain(mark, entry.entryKind(), method.owner(), method.name(), trace, "this-object");
            }
            if (entry.entryKind().equals("proxyInvoke") && bb.hierarchy().isSerializable(method.owner())) {
                return completeChain(mark, entry.entryKind(), method.owner(), method.name(), trace, "proxy-args");
            }
        }
        Node methodNode = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        if (methodNode == null) {
            return 0;
        }
        // 调用点收集：自身入边；为空时并入祖先类型（传递接口/父类链）上同名方法的入边
        // （接口实现数超 CHA 上限时分发边未物化，具体实现类须经祖先方法节点反查调用点——同前向引擎语义）
        Set<Node> callSites = new java.util.LinkedHashSet<>();
        collectCallSites(methodNode, callSites);
        boolean merged = callSites.isEmpty();
        if (merged) {
            for (String ancestor : ancestorTypes(method.owner())) {
                Node ancestorNode = bb.graph().findMethodNode(ancestor, method.name(), method.descriptor());
                if (ancestorNode != null) {
                    collectCallSites(ancestorNode, callSites);
                }
            }
        }
        int callerCap = merged ? MAX_MERGED_CALLERS : MAX_CALLERS;
        int produced = 0;
        int callers = 0;
        for (Node callerCall : callSites) {
            if (callers >= callerCap) {
                break;
            }
            MethodInfo callerMethod = support.enclosingMethod(callerCall);
            if (callerMethod == null) {
                trace.unresolved++;
                continue;
            }
            if (!entryReaching.contains(OriginSupport.methodKey(callerMethod))) {
                continue; // 调用者祖先链不可达入口：可证明无链，剪枝
            }
            callers++;
            Set<ValueOrigin> argOrigins = support.argOriginAt(callerCall, callerMethod, slot);
            if (argOrigins.isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), HopKind.VIRTUAL_DISPATCH, null, "call",
                    method.descriptor(), Descriptor.paramOrdinal(method.descriptor(), method.isStatic(), slot));
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin argOrigin : argOrigins) {
                produced += controlled(argOrigin, callerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    private void collectCallSites(Node methodNode, Set<Node> out) {
        for (Edge edge : methodNode.in()) {
            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES
                    || edge.type() == EdgeType.LAMBDA) {
                out.add(edge.from());
            }
        }
    }

    /** 祖先类型集合：传递接口 + 父类链（含自身之外的全部祖先，去自身）。 */
    private Set<String> ancestorTypes(String owner) {
        Set<String> result = new java.util.LinkedHashSet<>();
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

    /** 指令产物：数组分配←元素；数组读←数组；其余←消耗的操作数。 */
    private int controlledInsn(int offset, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        ForwardOrigins.Result result = support.origins().compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return 0;
        }
        Op op = method.insnAt(offset).op();
        int produced = 0;
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                produced += controlled(element, method, depth + 1, trace, mark);
            }
        }
        if (produced > 0) {
            return produced;
        }
        int consumed = OriginSupport.consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i).origins()) {
                produced += controlled(operand, method, depth + 1, trace, mark);
            }
        }
        return produced;
    }

    /** 调用返回值：OIS 读无条件可控；可控 receiver 的返回值可控；可控实参的返回值可控。 */
    private int controlledCallResult(long callNodeId, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        if (callNodeId < 0) {
            trace.unresolved++;
            return 0;
        }
        Node call = bb.graph().node(callNodeId);
        if (OriginSupport.isOisRead(call)) {
            // 反序列化威胁模型：OIS 读结果无条件可控（entry = 调用所在方法）
            return completeChain(mark, "deserialization", method.owner(), method.name(),
                    trace, "ois-read:" + call.strProp("name"));
        }
        ForwardOrigins.State state = support.origins().compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return 0;
        }
        int produced = 0;
        String kind = call.strProp("invokeKind");
        boolean calleeStatic = "STATIC".equals(kind);
        if (!calleeStatic) {
            // 可控 receiver → 返回值可控（GadgetInspector 对象语义）
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiverOrigin : state.stack().get(receiverDepth).origins()) {
                    produced += controlled(receiverOrigin, method, depth + 1, trace, mark);
                }
            }
        }
        // passthrough：任一实参可控 → 返回值可控（按被调方法实参槽遍历，wide 参数占 2 槽）
        if (produced == 0) {
            List<Integer> argSlots = Descriptor.argSlots(call.strProp("desc"), calleeStatic);
            int slot = 0;
            for (int i = 0; i < argSlots.size() && produced == 0; i++) {
                for (ValueOrigin argOrigin : support.argOriginAt(call, method, slot)) {
                    produced += controlled(argOrigin, method, depth + 1, trace, mark);
                    if (produced > 0) {
                        break;
                    }
                }
                slot += argSlots.get(i);
            }
        }
        return produced;
    }

    /** 字段读取：静态不可控；可控 receiver 的可序列化字段可控；写入可控值的字段可控。 */
    private int controlledFieldRead(ValueOrigin.FieldRead fieldRead, MethodInfo method, int depth,
                                    Trace trace, SinkMark mark) {
        trace.steps++;
        if (fieldRead.isStatic()) {
            return 0;
        }
        int produced = 0;
        if (isSerializedField(fieldRead.owner(), fieldRead.field())) {
            ChainHop hop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-read", "", null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            produced += controlled(fieldRead.receiver(), method, depth + 1, trace, mark);
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (produced > 0) {
                return produced;
            }
        }
        int writers = 0;
        for (FieldWriterIndex.Writer writer : bb.fieldWriters().writersOf(fieldRead.owner(), fieldRead.field())) {
            if (writers >= MAX_WRITERS_PER_FIELD) {
                trace.unresolved++;
                break;
            }
            MethodInfo writerMethod = support.methodOf(writer.methodOwner(), writer.methodName(), writer.methodDesc());
            if (writerMethod == null) {
                trace.unresolved++;
                continue;
            }
            if (!entryReaching.contains(OriginSupport.methodKey(writerMethod))) {
                continue; // 写者祖先链不可达入口：剪枝
            }
            writers++;
            ForwardOrigins.State state = support.origins().compute(writerMethod).stateBefore().get(writer.insnOffset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(writerMethod.owner(), writerMethod.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-write", "", null);
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin valueOrigin : state.stack().get(state.stack().size() - 1).origins()) {
                produced += controlled(valueOrigin, writerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
            if (produced > 0) {
                return produced;
            }
        }
        return produced;
    }

    /** 链达成：构建 Chain（hops 为 sink→entry 顺序）；跳数超限拒绝。 */
    private int completeChain(SinkMark mark, String entryKind, String entryClass, String entryMethod,
                              Trace trace, String reason) {
        if (trace.hops.size() > MAX_HOPS) {
            trace.tooLong++;
            return 0;
        }
        List<ChainHop> hops = new ArrayList<>(trace.hops);
        hops.add(new ChainHop(entryClass, entryMethod, entryClass, entryMethod, HopKind.ENTRY, null, reason, "", null));
        Chain chain = new Chain(mark.ruleId(), mark.category(), mark.severity(),
                entryClass, entryMethod, entryKind,
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved);
        return bb.addChain(chain) ? 1 : 0;
    }

    // ---- 工具 ----

    /** 入口规则判定（自足契约：按规则匹配含 implementsType 层次校验，不读 KS1 标记），带缓存。 */
    private Rule.MagicEntryRule entryRuleOf(MethodInfo method) {
        String key = OriginSupport.methodKey(method);
        Optional<Rule.MagicEntryRule> cached = entryRuleCache.get(key);
        if (cached != null) {
            return cached.orElse(null);
        }
        Optional<Rule.MagicEntryRule> rule = RuleEngine.matchingEntry(
                bb.rules(), bb.hierarchy(), method.owner(), method.name(), method.descriptor());
        entryRuleCache.put(key, rule);
        return rule.orElse(null);
    }

    /** 字段是否为序列化字段（非静态、非 transient）；类不可解析时保守视为是。 */
    private boolean isSerializedField(String owner, String field) {
        if (!bb.hierarchy().isSerializable(owner)) {
            return false;
        }
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        if (cls == null || cls.field(field) == null) {
            return true; // 类不可解析时保守
        }
        return !Modifier.isTransient(cls.field(field).access());
    }

    private static HopKind hopKindOf(EdgeType type) {
        return switch (type) {
            case DISPATCHES -> HopKind.VIRTUAL_DISPATCH;
            case LAMBDA -> HopKind.LAMBDA;
            default -> HopKind.DIRECT_CALL;
        };
    }

    private SinkOutcome outcome(Node call, SinkMark mark, int chains, int steps, int unresolved,
                                int tooLong, String verdict) {
        return new SinkOutcome(mark.ruleId(), mark.category(),
                call.strProp("owner"), call.strProp("name"),
                call.strProp("methodOwner"), call.strProp("methodName"),
                chains, verdict, steps, unresolved, tooLong);
    }

    /** 一次回溯的路径与统计。 */
    private static final class Trace {
        final String sinkOwner;
        final String sinkMethod;
        final List<ChainHop> hops = new ArrayList<>();
        final Set<String> visited = new HashSet<>();
        int unresolved;
        int tooLong;
        int steps;

        Trace(String sinkOwner, String sinkMethod) {
            this.sinkOwner = sinkOwner;
            this.sinkMethod = sinkMethod;
        }
    }
}
