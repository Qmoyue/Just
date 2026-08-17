package io.just.sast.knowledge.ks4;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.MagicEntryMark;
import io.just.sast.config.Rule;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Edge;
import io.just.sast.cpg.graph.EdgeType;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.knowledge.ks2.ForwardOrigins;
import io.just.sast.knowledge.ks2.ValueOrigin;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * KS4 前向对象污点引擎（独立知识源，与 KS1/KS2/KS3 交叉并行）。
 * GadgetInspector 式正向：从 magic entry / OIS 读出发，方法摘要 + 事实不动点，
 * worklist 只处理受影响方法；不动点后一次性做 sink 判定。
 * 事实单调只增，路径取最短；deadEnds 按事实版本失效。
 */
public final class ForwardTaintKnowledgeSource implements KnowledgeSource {

    private static final int MAX_DEPTH = 20;
    private static final int MAX_ROUNDS = 32;
    private static final int MAX_HOPS = 10;
    /** 判定步数预算（有界恢复：预算耗尽停止扩散，保留已有事实与 sink 判定）。 */
    private static final int STEP_BUDGET = 3_000_000;
    /** 方法效果处理上限。 */
    private static final int METHOD_PASS_CAP = 300_000;

    /** 事实：键 → 前向路径（首元素为 ENTRY hop）。 */
    private final Map<String, List<ChainHop>> thisTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> fieldTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> returnTainted = new HashMap<>();
    private final Map<String, List<ChainHop>> paramTainted = new HashMap<>();
    /** 死胡同缓存：键 = 事实版本 + "|" + 方法 + "|" + origin。 */
    private final Set<String> deadEnds = new HashSet<>();
    private final Set<String> visiting = new HashSet<>();

    /** 字段读者索引：fieldKey → 方法集合（新字段事实时入队）。 */
    private final Map<String, Set<String>> fieldReaders = new HashMap<>();
    /** 调用者索引：方法键 → 调用点（return 事实传播用，含接口反向分发）。 */
    private final Map<String, List<Node>> callers = new HashMap<>();

    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new HashMap<>();
    private final ForwardOrigins origins = new ForwardOrigins(callIdByKey);
    /** 反序列化可达方法集（前向 BFS 边界：只在该子集内传播）。 */
    private final Set<String> reachable = new HashSet<>();
    private static final int REACHABLE_CAP = 200_000;
    private static final int INTERFACE_EXPAND_CAP = 100;
    private Blackboard bb;
    private int factCount;
    private int steps;
    private int methodPasses;
    private final Deque<String> queue = new ArrayDeque<>();

    @Override
    public String id() {
        return "forward-taint";
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
        buildIndexes();
    }

    private void buildIndexes() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = methodOf(method.strProp("owner"), method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            String key = methodKey(info);
            for (InsnFact insn : info.instructions()) {
                if (insn.op().isFieldRead()) {
                    fieldReaders.computeIfAbsent(insn.fieldRef().owner() + "#" + insn.fieldRef().name(),
                            k -> new HashSet<>()).add(key);
                }
            }
            for (Edge edge : method.in()) {
                if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                    callers.computeIfAbsent(key, k -> new ArrayList<>()).add(edge.from());
                }
            }
        }
        // 接口反向分发：接口方法节点的调用点并入实现类方法（同 KS2 语义）
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = method.strProp("owner");
            MethodInfo info = methodOf(owner, method.strProp("name"), method.strProp("desc"));
            if (info == null || !method.in().isEmpty()) {
                continue;
            }
            for (String itf : bb.hierarchy().transitiveInterfaces(owner)) {
                Node itfNode = bb.graph().findMethodNode(itf, info.name(), info.descriptor());
                if (itfNode != null) {
                    for (Edge edge : itfNode.in()) {
                        if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                            callers.computeIfAbsent(methodKey(info), k -> new ArrayList<>()).add(edge.from());
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
        computeReachable();
        seedEntries();
        int rounds = 0;
        while (!queue.isEmpty() && rounds < MAX_ROUNDS && steps < STEP_BUDGET
                && methodPasses < METHOD_PASS_CAP) {
            rounds++;
            Deque<String> current = new ArrayDeque<>(queue);
            queue.clear();
            while (!current.isEmpty() && steps < STEP_BUDGET && methodPasses < METHOD_PASS_CAP) {
                String key = current.poll();
                MethodInfo method = resolveMethodKey(key);
                if (method != null) {
                    methodPasses++;
                    processEffects(method);
                }
            }
        }
        // 不动点后一次性 sink 判定（仅可达子集内的 sink）
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (reachable.contains(methodKey(call))) {
                RuleEngine.matchingSink(bb.rules(), call).ifPresent(rule -> checkSink(call, rule));
            }
        }
        io.just.sast.util.JustLogger.info("KS4 前向污点：可达 {} 个方法，事实 {} 个，轮数 {}",
                reachable.size(), factCount, rounds);
    }

    /** 前向可达集：从 magic entry 与 OIS 宿主出发，沿调用边 BFS（接口按上限展开）。 */
    private void computeReachable() {
        Deque<String> bfs = new ArrayDeque<>();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            if (bb.entryOf(method.id()) != null && reachable.add(methodNodeKey(method))) {
                bfs.add(methodNodeKey(method));
            }
        }
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            if (isOisRead(call) && reachable.add(methodKey(call))) {
                bfs.add(methodKey(call));
            }
        }
        while (!bfs.isEmpty() && reachable.size() < REACHABLE_CAP) {
            String key = bfs.poll();
            MethodInfo method = resolveMethodKey(key);
            if (method == null) {
                continue;
            }
            for (InsnFact insn : method.instructions()) {
                if (!insn.op().isInvoke()) {
                    continue;
                }
                Long callId = callIdByKey.get(key + "@" + insn.offset());
                if (callId == null) {
                    continue;
                }
                Node call = bb.graph().node(callId);
                for (Edge edge : call.out()) {
                    if ((edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES)
                            && reachable.add(methodNodeKey(edge.to()))) {
                        bfs.add(methodNodeKey(edge.to()));
                    }
                }
                // 仅当调用边未物化实现（出边 ≤1，即声明目标）时按上限展开接口
                if (call.out().size() > 1) {
                    continue;
                }
                List<String> impls = bb.hierarchy().implementers(call.strProp("owner"), 500);
                if (impls != null) {
                    int expanded = 0;
                    for (String impl : impls) {
                        if (expanded >= INTERFACE_EXPAND_CAP) {
                            break;
                        }
                        expanded++;
                        String resolved = bb.hierarchy().resolveMethod(impl, call.strProp("name"),
                                call.strProp("desc"));
                        if (resolved != null && reachable.add(methodKeyOf(resolved, call.strProp("name"),
                                call.strProp("desc")))) {
                            bfs.add(methodKeyOf(resolved, call.strProp("name"), call.strProp("desc")));
                        }
                    }
                }
            }
        }
    }

    /** 种子：magic entry 的 this 是反序列化对象；入队其所在类的全部方法。 */
    private void seedEntries() {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MagicEntryMark entry = bb.entryOf(method.id());
            if (entry == null) {
                continue;
            }
            ChainHop entryHop = new ChainHop(entry.className(), method.strProp("name"),
                    entry.className(), method.strProp("name"), HopKind.ENTRY, null, entry.entryKind());
            addThis(entry.className(), List.of(entryHop));
        }
    }

    /** 方法效果：PUTFIELD 存污点值 → 字段事实；RETURN 污点值 → 返回事实。 */
    private void processEffects(MethodInfo method) {
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isFieldWrite() && op != Op.PUTSTATIC) {
                ForwardOrigins.State state = origins.compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1)) {
                    List<ChainHop> path = tainted(value, method, 0);
                    if (path != null) {
                        addField(insn.fieldRef().owner(), insn.fieldRef().name(), path);
                    }
                }
            } else if (op.isReturn() && op != Op.RETURN && op != Op.ATHROW) {
                ForwardOrigins.State state = origins.compute(method).stateBefore().get(insn.offset());
                if (state == null || state.stack().isEmpty()) {
                    continue;
                }
                for (ValueOrigin value : state.stack().get(state.stack().size() - 1)) {
                    List<ChainHop> path = tainted(value, method, 0);
                    if (path != null) {
                        addReturn(methodKey(method), path);
                    }
                }
            }
        }
    }

    /** sink 判定：污点位置的值带污点 → 链达成。 */
    private void checkSink(Node call, Rule.SinkRule rule) {
        MethodInfo method = enclosingMethod(call);
        if (method == null) {
            return;
        }
        ForwardOrigins.State state = origins.compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return;
        }
        int paramCount = Descriptor.paramCount(call.strProp("desc"));
        for (Rule.TaintedPos pos : rule.tainted()) {
            int depthFromTop;
            if (pos instanceof Rule.TaintedPos.Arg a) {
                depthFromTop = paramCount - 1 - a.index();
            } else {
                depthFromTop = paramCount;
            }
            if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
                continue;
            }
            for (ValueOrigin origin : state.stack().get(state.stack().size() - 1 - depthFromTop)) {
                List<ChainHop> path = tainted(origin, method, 0);
                if (path == null) {
                    continue;
                }
                List<ChainHop> hops = new ArrayList<>(path);
                Collections.reverse(hops); // 前向路径翻转为 sink→entry
                ChainHop entry = hops.get(hops.size() - 1);
                Chain chain = new Chain(rule.id(), rule.category(), rule.severity(),
                        entry.fromOwner(), entry.fromName(), entry.reason() == null ? "?" : entry.reason(),
                        call.strProp("owner"), call.strProp("name"), hops, 0);
                bb.addChain(chain);
            }
        }
    }

    /** 值污点判定：返回前向路径（含 ENTRY hop 在首），无污点返回 null。 */
    private List<ChainHop> tainted(ValueOrigin origin, MethodInfo method, int depth) {
        if (depth > MAX_DEPTH || steps > STEP_BUDGET) {
            return null;
        }
        steps++;
        String key = factCount + "|" + methodKey(method) + "|" + origin;
        if (deadEnds.contains(key) || visiting.contains(key)) {
            return null;
        }
        visiting.add(key);
        List<ChainHop> path;
        if (origin instanceof ValueOrigin.Param p) {
            path = taintedParam(p.slot(), method);
        } else if (origin instanceof ValueOrigin.FieldRead f) {
            path = f.isStatic() ? null : fieldTainted.get(f.owner() + "#" + f.field());
        } else if (origin instanceof ValueOrigin.CallResult c) {
            path = taintedCallResult(c.callNodeId(), method, depth);
        } else if (origin instanceof ValueOrigin.Insn i) {
            path = taintedInsn(i.offset(), method, depth);
        } else {
            path = null; // 常量不可控
        }
        visiting.remove(key);
        if (path == null) {
            deadEnds.add(key);
        }
        return path;
    }

    private List<ChainHop> taintedParam(int slot, MethodInfo method) {
        if (slot == 0) {
            List<ChainHop> path = thisTainted.get(method.owner());
            if (path != null) {
                return path;
            }
        }
        return paramTainted.get(methodKey(method) + "#" + slot);
    }

    private List<ChainHop> taintedCallResult(long callNodeId, MethodInfo method, int depth) {
        if (callNodeId < 0) {
            return null;
        }
        Node call = bb.graph().node(callNodeId);
        if (isOisRead(call)) {
            ChainHop entryHop = new ChainHop(method.owner(), method.name(),
                    method.owner(), method.name(), HopKind.ENTRY, null, "deserialization");
            return List.of(entryHop);
        }
        ForwardOrigins.State state = origins.compute(method).stateBefore().get(call.prop("offset"));
        if (state == null) {
            return null;
        }
        List<ChainHop> best = null;
        String kind = call.strProp("invokeKind");
        if (!"STATIC".equals(kind)) {
            int receiverDepth = state.stack().size() - 1 - Descriptor.paramCount(call.strProp("desc"));
            if (receiverDepth >= 0 && receiverDepth < state.stack().size()) {
                for (ValueOrigin receiver : state.stack().get(receiverDepth)) {
                    List<ChainHop> receiverPath = tainted(receiver, method, depth + 1);
                    if (receiverPath != null) {
                        for (Edge edge : call.out()) {
                            if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                                addThis(edge.to().strProp("owner"), hopTo(receiverPath, method,
                                        edge.to().strProp("owner"), edge.to().strProp("name"), edge.type()));
                            }
                        }
                        best = receiverPath;
                    }
                }
            }
        }
        int argc = Descriptor.paramCount(call.strProp("desc")) + ("STATIC".equals(kind) ? 0 : 1);
        for (int slot = 0; slot < argc; slot++) {
            for (ValueOrigin argOrigin : argOriginAt(call, method, slot)) {
                List<ChainHop> argPath = tainted(argOrigin, method, depth + 1);
                if (argPath == null) {
                    continue;
                }
                if (best == null) {
                    best = argPath;
                }
                for (Edge edge : call.out()) {
                    if (edge.type() == EdgeType.INVOKES || edge.type() == EdgeType.DISPATCHES) {
                        addParam(edge.to().strProp("owner"), edge.to().strProp("name"),
                                edge.to().strProp("desc"), slot, hopTo(argPath, method,
                                        edge.to().strProp("owner"), edge.to().strProp("name"), edge.type()));
                    }
                }
            }
        }
        for (Edge edge : call.out()) {
            if (edge.type() != EdgeType.INVOKES && edge.type() != EdgeType.DISPATCHES) {
                continue;
            }
            List<ChainHop> returnPath = returnTainted.get(methodNodeKey(edge.to()));
            if (returnPath != null && best == null) {
                best = returnPath;
            }
        }
        return best;
    }

    private List<ChainHop> taintedInsn(int offset, MethodInfo method, int depth) {
        ForwardOrigins.Result result = origins.compute(method);
        ForwardOrigins.State state = result.stateBefore().get(offset);
        if (state == null) {
            return null;
        }
        Op op = method.insnAt(offset).op();
        if (op == Op.NEWARRAY || op == Op.ANEWARRAY || op == Op.MULTIANEWARRAY) {
            for (ValueOrigin element : result.arrayElements().getOrDefault(new ValueOrigin.Insn(offset), Set.of())) {
                List<ChainHop> path = tainted(element, method, depth + 1);
                if (path != null) {
                    return path;
                }
            }
        }
        int consumed = consumedCount(op);
        int start = Math.max(0, state.stack().size() - consumed);
        for (int i = start; i < state.stack().size(); i++) {
            for (ValueOrigin operand : state.stack().get(i)) {
                List<ChainHop> path = tainted(operand, method, depth + 1);
                if (path != null) {
                    return path;
                }
            }
        }
        return null;
    }

    // ---- 事实写入（键去重，路径更短才替换；受影响方法入队） ----

    private void addThis(String className, List<ChainHop> path) {
        if (path.size() > MAX_HOPS || !shorter(thisTainted.get(className), path)) {
            return;
        }
        thisTainted.put(className, path);
        factCount++;
        ClassInfo cls = bb.hierarchy().classInfo(className);
        if (cls != null) {
            for (MethodInfo method : cls.methods()) {
                if (reachable.contains(methodKey(method))) {
                    queue.add(methodKey(method));
                }
            }
        }
    }

    private void addField(String owner, String field, List<ChainHop> path) {
        String key = owner + "#" + field;
        if (path.size() > MAX_HOPS || !shorter(fieldTainted.get(key), path)) {
            return;
        }
        fieldTainted.put(key, path);
        factCount++;
        Set<String> readers = fieldReaders.get(key);
        if (readers != null) {
            queue.addAll(readers);
        }
    }

    private void addReturn(String methodKey, List<ChainHop> path) {
        if (path.size() > MAX_HOPS || !shorter(returnTainted.get(methodKey), path)) {
            return;
        }
        returnTainted.put(methodKey, path);
        factCount++;
        List<Node> callerCalls = callers.get(methodKey);
        if (callerCalls != null) {
            for (Node caller : callerCalls) {
                if (reachable.contains(methodKey(caller))) {
                    queue.add(methodKey(caller));
                }
            }
        }
    }

    private void addParam(String owner, String name, String desc, int slot, List<ChainHop> path) {
        String methodKey = methodKeyOf(owner, name, desc);
        String key = methodKey + "#" + slot;
        if (path.size() > MAX_HOPS || !shorter(paramTainted.get(key), path)) {
            return;
        }
        paramTainted.put(key, path);
        factCount++;
        queue.add(methodKey);
    }

    private static boolean shorter(List<ChainHop> existing, List<ChainHop> candidate) {
        return existing == null || candidate.size() < existing.size();
    }

    private static List<ChainHop> hopTo(List<ChainHop> parent, MethodInfo from,
                                        String toOwner, String toName, EdgeType type) {
        if (parent.size() >= MAX_HOPS) {
            return parent;
        }
        List<ChainHop> path = new ArrayList<>(parent);
        path.add(new ChainHop(from.owner(), from.name(), toOwner, toName,
                type == EdgeType.DISPATCHES ? HopKind.VIRTUAL_DISPATCH : HopKind.DIRECT_CALL, null, "call"));
        return path;
    }

    // ---- 工具 ----

    private MethodInfo resolveMethodKey(String key) {
        int sep = key.indexOf('#');
        int paren = key.indexOf('(', sep);
        if (sep < 0 || paren < 0) {
            return null;
        }
        return methodOf(key.substring(0, sep), key.substring(sep + 1, paren), key.substring(paren));
    }

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
        String key = methodKeyOf(owner, name, desc);
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

    private static boolean isOisRead(Node call) {
        String owner = call.strProp("owner");
        String name = call.strProp("name");
        return "java/io/ObjectInputStream".equals(owner)
                && (name.equals("readObject") || name.equals("readUnshared") || name.equals("readFields"));
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

    private static String methodNodeKey(Node method) {
        return method.strProp("owner") + "#" + method.strProp("name") + method.strProp("desc");
    }

    private static String methodKeyOf(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
