package io.just.sast.analysis.taint;

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
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * KS2 反向污点引擎：精度闸门。
 * 从 sink 的污点位置出发，反向回溯"谁影响了这个值"，直至触及 magic entry。
 * 参数位置对齐为强制约束；字段敏感（通过 FieldWriterIndex）；深度与数量上限防爆。
 */
public final class BackwardTaintAnalysis implements KnowledgeSource {

    /** 每个 sink 最多产出的链数。 */
    private static final int MAX_CHAINS_PER_SINK = 20;

    /** 每个 sink 的分析步数预算。 */
    private static final int STEP_BUDGET = 50_000;

    /** 全部分析的全局步数预算（防总耗时失控）。 */
    private static final int GLOBAL_BUDGET = 1_500_000;

    /** 每个字段回溯的写入点上限。 */
    private static final int MAX_WRITERS_PER_FIELD = 10;

    /** 每个调用点回溯的候选目标上限。 */
    private static final int MAX_TARGETS_PER_CALL = 15;

    /** 链跳数上限（不含 ENTRY）：真实链 2~8 跳，超出多为巧合链。 */
    private static final int MAX_HOPS = 10;

    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new HashMap<>();
    /** 已确认的死胡同（确定性分析：一次无产出则永远无产出）。 */
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
        return Set.of(EventType.SINK_MARKED);
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
        if (event.type() != EventType.SINK_MARKED) {
            return;
        }
        SinkMark mark = (SinkMark) event.payload();
        analyzeSink(event.nodeId(), mark);
    }

    private void analyzeSink(long callNodeId, SinkMark mark) {
        Node call = bb.graph().node(callNodeId);
        MethodInfo method = enclosingMethod(call);
        if (method == null) {
            bb.qualityNote(callNodeId, "enclosing-method-unresolved");
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "UNRESOLVED"));
            return;
        }
        ForwardOrigins.Result result = origins.compute(method);
        ForwardOrigins.State state = result.stateBefore().get(call.prop("offset"));
        if (state == null) {
            bb.qualityNote(callNodeId, "no-state");
            bb.recordOutcome(callNodeId, outcome(call, mark, 0, 0, 0, 0, "NO_STATE"));
            return;
        }
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
        int produced = 0;
        Trace trace = new Trace(call.strProp("owner"), call.strProp("name"));
        for (Rule.TaintedPos pos : mark.tainted()) {
            int depthFromTop;
            if (pos instanceof Rule.TaintedPos.Arg a) {
                // 栈布局：[... receiver, arg0, arg1, ..., argN(栈顶)]，argN 距栈顶 0
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
                produced += explore(origin, method, 0, trace, mark);
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
        bb.recordOutcome(callNodeId, outcome(call, mark, produced, trace.steps,
                trace.unresolved, trace.tooLong, verdict));
    }

    private SinkOutcome outcome(Node call, SinkMark mark, int chains, int steps, int unresolved,
                                int tooLong, String verdict) {
        return new SinkOutcome(mark.ruleId(), mark.category(),
                call.strProp("owner"), call.strProp("name"),
                call.strProp("methodOwner"), call.strProp("methodName"),
                chains, verdict, steps, unresolved, tooLong);
    }

    /** 返回该次探索产出的链数。 */
    private int explore(ValueOrigin origin, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        if (depth > bb.maxDepth() || trace.steps > STEP_BUDGET || globalSteps > GLOBAL_BUDGET) {
            return 0;
        }
        globalSteps++;
        String memoKey = methodKey(method) + "|" + origin;
        if (deadEnds.contains(memoKey) || trace.visited.contains(memoKey)) {
            return 0;
        }
        trace.visited.add(memoKey);
        int produced = 0;
        if (origin instanceof ValueOrigin.Param p) {
            produced = exploreParam(p.slot(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.Insn insn) {
            produced = exploreInsn(insn.offset(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.CallResult callResult) {
            produced = exploreCallResult(callResult.callNodeId(), method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.FieldRead fieldRead) {
            produced = exploreFieldRead(fieldRead, method, depth, trace, mark);
        } else if (origin instanceof ValueOrigin.Constant) {
            // 常量不可控，回溯终止
        } else {
            JustLogger.debug("未知值来源: {}", origin.getClass().getSimpleName());
        }
        trace.visited.remove(memoKey);
        if (produced == 0) {
            deadEnds.add(memoKey);
        }
        return produced;
    }

    /** 需求到达参数槽位：代理入口参数直接可控（handler 需可序列化）；否则回溯到调用者实参。
     *  若从某调用点进入（调用点敏感），只映射回该调用点的实参。 */
    private int exploreParam(int slot, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        MagicEntryMark entry = entryOfMethod(method);
        if (entry != null && entry.entryKind().equals("proxyInvoke") && slot >= 1
                && bb.hierarchy().isSerializable(method.owner())) {
            return completeChain(mark, entry, method, trace, "proxy-args");
        }
        Node methodNode = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        if (methodNode == null) {
            return 0;
        }
        Node entryCallSite = trace.callSiteStack.peek();
        int produced = 0;
        for (Edge edge : methodNode.in()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                    && edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            if (entryCallSite != null && edge.from() != entryCallSite) {
                continue; // 调用点敏感：只沿进入时的调用点回传
            }
            Node callerCall = edge.from();
            MethodInfo callerMethod = enclosingMethod(callerCall);
            if (callerMethod == null) {
                trace.unresolved++;
                continue;
            }
            if (edge.type() == EdgeType.LAMBDA) {
                trace.unresolved++; // lambda 捕获变量回溯 v0.1 不建模
                continue;
            }
            Set<ValueOrigin> argOrigins = argOriginAt(callerCall, callerMethod, slot);
            if (argOrigins.isEmpty()) {
                trace.unresolved++;
                continue;
            }
            ChainHop hop = new ChainHop(callerMethod.owner(), callerMethod.name(),
                    method.owner(), method.name(), hopKindOf(edge.type()), null, "call");
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin argOrigin : argOrigins) {
                produced += explore(argOrigin, callerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** 需求到达指令产物：回溯该指令消耗的操作数（按消费个数精确截取栈顶）；数组分配回溯元素存储。 */
    private int exploreInsn(int offset, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        trace.steps++;
        ForwardOrigins.Result result = origins.compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return 0;
        }
        InsnFact insn = method.insnAt(offset);
        int produced = 0;
        // 数组元素：xASTORE 存入的值可控制数组内容
        Op op = insn.op();
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                produced += explore(element, method, depth + 1, trace, mark);
            }
        }
        int consumed = consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i)) {
                produced += explore(operand, method, depth + 1, trace, mark);
            }
        }
        return produced;
    }

    /** 需求到达调用返回值：进入所有候选目标，回溯其 RETURN 操作数；OIS 读在 magic entry 内即链达成。 */
    private int exploreCallResult(long callNodeId, MethodInfo method, int depth, Trace trace, SinkMark mark) {
        if (callNodeId < 0) {
            // JDK 懒加载类内部的调用无图节点，返回流不做建模
            trace.unresolved++;
            return 0;
        }
        trace.steps++;
        Node call = bb.graph().node(callNodeId);
        if (isOisRead(call) && entryOfMethod(method) != null) {
            MagicEntryMark entry = entryOfMethod(method);
            return completeChain(mark, entry, method, trace, "ois-read:" + call.strProp("name"));
        }
        int produced = 0;
        int targets = 0;
        for (Edge edge : call.out()) {
            if (targets >= MAX_TARGETS_PER_CALL) {
                trace.unresolved++;
                break;
            }
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES
                    && edge.type() != EdgeType.LAMBDA) {
                continue;
            }
            targets++;
            Node target = edge.to();
            MethodInfo targetMethod = methodInfoOfNode(target);
            if (targetMethod == null) {
                trace.unresolved++;
                bb.qualityNote(callNodeId, "unresolved-target:" + target.strProp("owner")
                        + "#" + target.strProp("name"));
                continue;
            }
            ChainHop hop = new ChainHop(method.owner(), method.name(),
                    targetMethod.owner(), targetMethod.name(), hopKindOf(edge.type()), null, "return-flow");
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            trace.callSiteStack.push(call);
            for (InsnFact insn : targetMethod.instructions()) {
                if (!insn.op().isReturn() || insn.op() == Op.RETURN || insn.op() == Op.ATHROW) {
                    continue;
                }
                ForwardOrigins.State state = origins.compute(targetMethod).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin returnOrigin : state.stack().get(state.stack().size() - 1)) {
                    produced += explore(returnOrigin, targetMethod, depth + 1, trace, mark);
                }
            }
            trace.callSiteStack.pop();
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** 需求到达字段读取：静态字段不可控；magic entry 内读 this 字段即链达成；否则回溯字段写入点。 */
    private int exploreFieldRead(ValueOrigin.FieldRead fieldRead, MethodInfo method, int depth,
                                 Trace trace, SinkMark mark) {
        trace.steps++;
        if (fieldRead.isStatic()) {
            return 0; // 静态字段不经反序列化，攻击者不可控
        }
        MagicEntryMark entry = entryOfMethod(method);
        boolean receiverIsThis = fieldRead.receiver() instanceof ValueOrigin.Param p && p.slot() == 0;
        if (entry != null && receiverIsThis && method.owner().equals(fieldRead.owner())) {
            return completeChain(mark, entry, method, trace, "field:" + fieldRead.field());
        }
        int produced = 0;
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
            ChainHop hop = new ChainHop(method.owner(), method.name(),
                    writerMethod.owner(), writerMethod.name(), HopKind.FIELD_FLOW, fieldRead.field(), "field-write");
            int unresolvedBefore = trace.unresolved;
            trace.hops.add(hop);
            for (ValueOrigin valueOrigin : state.stack().get(state.stack().size() - 1)) {
                produced += explore(valueOrigin, writerMethod, depth + 1, trace, mark);
            }
            trace.hops.remove(trace.hops.size() - 1);
            trace.unresolved = unresolvedBefore;
        }
        return produced;
    }

    /** 链达成：构建 Chain（hops 为 sink→entry 顺序）；跳数超限拒绝。 */
    private int completeChain(SinkMark mark, MagicEntryMark entry, MethodInfo entryMethod, Trace trace, String reason) {
        if (trace.hops.size() > MAX_HOPS) {
            trace.tooLong++;
            return 0;
        }
        List<ChainHop> hops = new ArrayList<>(trace.hops);
        hops.add(new ChainHop(entryMethod.owner(), entryMethod.name(),
                entryMethod.owner(), entryMethod.name(), HopKind.ENTRY, null, reason));
        Chain chain = new Chain(mark.ruleId(), mark.category(), mark.severity(),
                entryMethod.owner(), entryMethod.name(), entry.entryKind(),
                trace.sinkOwner, trace.sinkMethod, hops, trace.unresolved);
        return bb.addChain(chain) ? 1 : 0;
    }

    // ---- 工具 ----

    /** 调用点参数槽位（含 this=0）在调用者栈中的来源集合。 */
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

    private MethodInfo methodInfoOfNode(Node node) {
        return methodOf(node.strProp("owner"), node.strProp("name"), node.strProp("desc"));
    }

    private MagicEntryMark entryOfMethod(MethodInfo method) {
        Node node = bb.graph().findMethodNode(method.owner(), method.name(), method.descriptor());
        return node != null ? bb.entryOf(node.id()) : null;
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
        /** 返回流进入目标方法时经过的调用点（调用点敏感性）。 */
        final java.util.Deque<Node> callSiteStack = new java.util.ArrayDeque<>();
        int unresolved;
        int tooLong;
        int steps;

        Trace(String sinkOwner, String sinkMethod) {
            this.sinkOwner = sinkOwner;
            this.sinkMethod = sinkMethod;
        }
    }
}
