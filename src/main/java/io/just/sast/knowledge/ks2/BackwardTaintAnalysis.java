package io.just.sast.knowledge.ks2;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.MagicEntryMark;
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
import io.just.sast.model.InsnFact;
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
import java.util.Set;

/**
 * KS2 反向污点引擎（独立知识源，与 KS1 交叉并行）。
 * 不等待 KS1 的标记：自行按规则枚举 sink 候选，反向回答"该值是否攻击者可控"，
 * 产物（链 + 裁决）写黑板，校准 KS1 的标记。
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
    private static final int STEP_BUDGET = 50_000;
    private static final int GLOBAL_BUDGET = 20_000_000;
    private static final int MAX_WRITERS_PER_FIELD = 10;
    private static final int MAX_HOPS = 10;
    private static final int MAX_CALLERS = 1000;

    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new HashMap<>();
    private final Set<String> deadEnds = new HashSet<>();
    private final ForwardOrigins origins = new ForwardOrigins(callIdByKey);
    private Blackboard bb;
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
        for (Node call : blackboard.graph().nodesOfType(NodeType.CALL)) {
            callIdByKey.put(methodKey(call) + "@" + call.strProp("offset"), call.id());
        }
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        // 独立枚举 sink 候选：不读 KS1 的标记，与 KS1 交叉并行
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            RuleEngine.matchingSink(bb.rules(), call).ifPresent(rule ->
                    analyzeSink(call.id(), new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted())));
        }
    }

    private void analyzeSink(long callNodeId, SinkMark mark) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = enclosingMethod(call);
        if (method == null) {
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return;
        }
        ForwardOrigins.Result result = origins.compute(method);
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
            Set<ValueOrigin> slotOrigins = state.stack().get(state.stack().size() - 1 - depthFromTop);
            for (ValueOrigin origin : slotOrigins) {
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
        // 预算尾部截断的结果不可靠，不写入死胡同缓存（防假阴性污染）
        boolean nearBudget = globalSteps > GLOBAL_BUDGET * 4 / 5;
        // 深度接近上限的结果受截断影响，不记忆化也不查询（深度无关键的不健全）
        boolean memoizable = depth <= bb.maxDepth() / 2;
        globalSteps++;
        String memoKey = methodKey(method) + "|" + origin;
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

    /** 参数：magic entry 的 this 可控、proxy 入口 args 可控；否则回溯调用者实参（调用点敏感）。 */
    private int controlledParam(int slot, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        MagicEntryMark entry = entryOfMethod(method);
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
        Node entryCallSite = trace.callSiteStack.peek();
        int produced = 0;
        int callers = 0;
        for (Edge edge : methodNode.in()) {
            if (callers >= MAX_CALLERS) {
                break;
            }
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                    && edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            if (entryCallSite != null && edge.from() != entryCallSite) {
                continue;
            }
            callers++;
            Node callerCall = edge.from();
            MethodInfo callerMethod = enclosingMethod(callerCall);
            if (callerMethod == null) {
                trace.unresolved++;
                continue;
            }
            Set<ValueOrigin> argOrigins = argOriginAt(callerCall, callerMethod, slot);
            if (argOrigins.isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), hopKindOf(edge.type()), null, "call");
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

    /** 指令产物：数组分配←元素；数组读←数组；其余←消耗的操作数。 */
    private int controlledInsn(int offset, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        ForwardOrigins.Result result = origins.compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return 0;
        }
        InsnFact insn = method.insnAt(offset);
        Op op = insn.op();
        int produced = 0;
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                produced += controlled(element, method, depth + 1, trace, mark);
            }
        }
        if (produced > 0) {
            return produced;
        }
        int consumed = consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i)) {
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
        if (isOisRead(call)) {
            // 反序列化威胁模型：OIS 读结果无条件可控（entry = 调用所在方法）
            return completeChain(mark, "deserialization", method.owner(), method.name(),
                    trace, "ois-read:" + call.strProp("name"));
        }
        ForwardOrigins.State state = origins.compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return 0;
        }
        int produced = 0;
        String kind = call.strProp("invokeKind");
        if (!"STATIC".equals(kind)) {
            // 可控 receiver → 返回值可控（GadgetInspector 对象语义）
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiverOrigin : state.stack().get(receiverDepth)) {
                    produced += controlled(receiverOrigin, method, depth + 1, trace, mark);
                }
            }
        }
        // passthrough：任一实参可控 → 返回值可控
        if (produced == 0) {
            int argc = Descriptor.paramCount(call.strProp("desc")) + ("STATIC".equals(kind) ? 0 : 1);
            for (int slot = 0; slot < argc && produced == 0; slot++) {
                Set<ValueOrigin> argOrigins = argOriginAt(call, method, slot);
                for (ValueOrigin argOrigin : argOrigins) {
                    produced += controlled(argOrigin, method, depth + 1, trace, mark);
                    if (produced > 0) {
                        break;
                    }
                }
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
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-read");
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
            writers++;
            MethodInfo writerMethod = methodOf(writer.methodOwner(), writer.methodName(), writer.methodDesc());
            if (writerMethod == null) {
                trace.unresolved++;
                continue;
            }
            ForwardOrigins.State state = origins.compute(writerMethod).stateBefore().get(writer.insnOffset());
            if (state == null || state.stack().isEmpty()) {
                continue;
            }
            ChainHop hop = new ChainHop(writerMethod.owner(), writerMethod.name(),
                    method.owner(), method.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-write");
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin valueOrigin : state.stack().get(state.stack().size() - 1)) {
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
        hops.add(new ChainHop(entryClass, entryMethod, entryClass, entryMethod, HopKind.ENTRY, null, reason));
        Chain chain = new Chain(mark.ruleId(), mark.category(), mark.severity(),
                entryClass, entryMethod, entryKind,
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved);
        return bb.addChain(chain) ? 1 : 0;
    }

    // ---- 工具 ----

    private Set<ValueOrigin> argOriginAt(Node callerCall, MethodInfo callerMethod, int slot) {
        ForwardOrigins.State state = origins.compute(callerMethod)
                .stateBefore().get(callerCall.prop("offset"));
        if (state == null) {
            return Set.of();
        }
        int paramCount = Descriptor.paramCount(callerCall.strProp("desc"));
        int depthFromTop = paramCount - slot;
        if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 1 - depthFromTop);
    }

    private MethodInfo enclosingMethod(Node call) {
        return methodOf(call.strProp("methodOwner"), call.strProp("methodName"), call.strProp("methodDesc"));
    }

    private MethodInfo methodOf(String owner, String name, String desc) {
        String key = owner + "#" + name + desc;
        MethodInfo cached = methodCache.get(key);
        if (cached != null) {
            return cached;
        }
        ClassInfo cls = bb.hierarchy().classInfo(owner);
        MethodInfo method = cls != null ? cls.method(name, desc) : null;
        if (method != null) {
            methodCache.put(key, method);
        }
        return method;
    }

    private MagicEntryMark entryOfMethod(MethodInfo method) {
        Node node = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        return node != null ? bb.entryOf(node.id()) : null;
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

    private static boolean isOisRead(Node call) {
        String owner = call.strProp("owner");
        String name = call.strProp("name");
        return "java/io/ObjectInputStream".equals(owner)
                && (name.equals("readObject") || name.equals("readUnshared") || name.equals("readFields"));
    }

    private static HopKind hopKindOf(EdgeType type) {
        return switch (type) {
            case DISPATCHES -> HopKind.VIRTUAL_DISPATCH;
            case LAMBDA -> HopKind.LAMBDA;
            default -> HopKind.DIRECT_CALL;
        };
    }

    private static int consumedCount(Op op) {
        return switch (op) {
            case NEW -> 0;
            case INEG, LNEG, FNEG, DNEG, I2L, I2F, I2D, L2I, L2F, L2D,
                    F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
                    ARRAYLENGTH, CHECKCAST, INSTANCEOF -> 1;
            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD,
                    IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
                    IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV,
                    IREM, LREM, FREM, DREM, ISHL, LSHL, ISHR, LSHR, IUSHR, LUSHR,
                    IAND, LAND, IOR, LOR, IXOR, LXOR, LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> 2;
            default -> 0;
        };
    }

    private SinkOutcome outcome(Node call, SinkMark mark, int chains, int steps, int unresolved,
                                int tooLong, String verdict) {
        return new SinkOutcome(mark.ruleId(), mark.category(),
                call.strProp("owner"), call.strProp("name"),
                call.strProp("methodOwner"), call.strProp("methodName"),
                chains, verdict, steps, unresolved, tooLong);
    }

    private static String methodKey(MethodInfo method) {
        return method.owner() + "#" + method.name() + method.descriptor();
    }

    private static String methodKey(Node call) {
        return call.strProp("methodOwner") + "#" + call.strProp("methodName") + call.strProp("methodDesc");
    }

    /** 一次回溯的路径与统计。 */
    private static final class Trace {
        final String sinkOwner;
        final String sinkMethod;
        final List<ChainHop> hops = new ArrayList<>();
        final Set<String> visited = new HashSet<>();
        final Deque<Node> callSiteStack = new ArrayDeque<>();
        int unresolved;
        int tooLong;
        int steps;

        Trace(String sinkOwner, String sinkMethod) {
            this.sinkOwner = sinkOwner;
            this.sinkMethod = sinkMethod;
        }
    }
}
