package io.just.sast.analysis.taint;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Graph;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * 共享分析支撑（经黑板分发，KS2/KS4/KS5 复用同一实例）：
 * 调用点索引、方法解析缓存、跨方法实参定位、公共判定谓词。
 */
public final class OriginSupport {

    private final ForwardOrigins origins;
    private final Map<String, Long> callIdByKey = new HashMap<>();
    private final Map<String, MethodInfo> methodCache = new HashMap<>();
    private final ClassHierarchy hierarchy;

    public OriginSupport(Graph graph, ClassHierarchy hierarchy) {
        this.hierarchy = hierarchy;
        this.origins = new ForwardOrigins(callIdByKey);
        for (Node call : graph.nodesOfType(NodeType.CALL)) {
            callIdByKey.put(methodKey(call) + "@" + call.strProp("offset"), call.id());
        }
    }

    public ForwardOrigins origins() {
        return origins;
    }

    /** 调用点 id：方法键 + "@" + 指令 offset → CALL 节点 id；不存在返回 null。 */
    public Long callId(String methodKey, int offset) {
        return callIdByKey.get(methodKey + "@" + offset);
    }

    public MethodInfo methodOf(String owner, String name, String desc) {
        String key = methodKeyOf(owner, name, desc);
        MethodInfo cached = methodCache.get(key);
        if (cached != null) {
            return cached;
        }
        ClassInfo cls = hierarchy.classInfo(owner);
        MethodInfo method = cls != null ? cls.method(name, desc) : null;
        if (method != null) {
            methodCache.put(key, method);
        }
        return method;
    }

    /** CALL 节点所在的方法。 */
    public MethodInfo enclosingMethod(Node call) {
        return methodOf(call.strProp("methodOwner"), call.strProp("methodName"), call.strProp("methodDesc"));
    }

    /**
     * 调用点实参来源：slot 为被调方法的局部参数槽（实例方法 receiver=0，long/double 参数占 2 槽）。
     * 按参数序数定位调用点栈上的实参（receiver 深度 = paramCount，arg i 深度 = paramCount-1-i，
     * cat-2 实参与 cat-1 一样各占一个栈条目）；返回空集表示该位置无来源记录。
     */
    public Set<ValueOrigin> argOriginAt(Node callerCall, MethodInfo callerMethod, int slot) {
        ForwardOrigins.State state = origins.compute(callerMethod)
                .stateBefore().get(callerCall.prop("offset"));
        if (state == null) {
            return Set.of();
        }
        String desc = callerCall.strProp("desc");
        boolean calleeStatic = "STATIC".equals(callerCall.strProp("invokeKind"));
        int ordinal = Descriptor.paramOrdinal(desc, calleeStatic, slot);
        if (ordinal == -2) {
            return Set.of();
        }
        int paramCount = Descriptor.paramCount(desc);
        int depthFromTop = ordinal == -1 ? paramCount : paramCount - 1 - ordinal;
        if (depthFromTop < 0 || depthFromTop >= state.stack().size()) {
            return Set.of();
        }
        return state.stack().get(state.stack().size() - 1 - depthFromTop).origins();
    }

    /** ObjectInputStream 读调用（反序列化数据源，无条件可控）。 */
    public static boolean isOisRead(Node call) {
        String owner = call.strProp("owner");
        String name = call.strProp("name");
        return "java/io/ObjectInputStream".equals(owner)
                && (name.equals("readObject") || name.equals("readUnshared") || name.equals("readFields"));
    }

    /** 指令按值消耗的栈条目数（cat-2 值亦为单条目，条目数 = 值数）。 */
    public static int consumedCount(Op op) {
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

    public static String methodKey(MethodInfo method) {
        return method.owner() + "#" + method.name() + method.descriptor();
    }

    /** CALL 节点所在方法的键。 */
    public static String methodKey(Node call) {
        return methodKeyOf(call.strProp("methodOwner"), call.strProp("methodName"), call.strProp("methodDesc"));
    }

    public static String methodKeyOf(String owner, String name, String desc) {
        return owner + "#" + name + desc;
    }
}
