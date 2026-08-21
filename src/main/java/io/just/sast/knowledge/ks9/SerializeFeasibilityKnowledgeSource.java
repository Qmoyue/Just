package io.just.sast.knowledge.ks9;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.FieldInfo;
import io.just.sast.util.JustLogger;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * KS9 序列化可行性校准（CALIBRATION 阶段，借鉴 JDD 可利用性验证的静态可判定子集）。
 * 攻击者要在接收端构造出链所需的对象图，链上 FIELD_FLOW 涉及字段的运行时值类型必须可序列化
 * （Java 序列化规范：非 transient 字段的实际值须 Serializable，否则写端无法生成该载荷）。
 * 仅校验**声明类自身可序列化**的字段（攻击者对象图的合理代理）；框架管线对象
 * （序列化器/过滤器等非序列化类）的字段跳过——它们不经反序列化构造，前提不适用。
 * 声明类型 T 与其已加载子类型闭包中均无 Serializable → 链物理不可能，拒绝；
 * Object 型字段天然通行；类型/Serializable 标记不可解析 → 保守通过。
 */
public final class SerializeFeasibilityKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;
    /** 类型 → 是否可能承载可序列化运行时值（记忆化）。 */
    private final Map<String, Boolean> serializablePossible = new HashMap<>();

    @Override
    public String id() {
        return "serialize-feasibility";
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
        int rejected = 0;
        for (Chain chain : bb.chains()) {
            String reason = rejectReason(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                rejected++;
            }
        }
        JustLogger.info("KS9 序列化可行性：校验 {} 条链，拒绝 {} 条", bb.chains().size(), rejected);
    }

    /** 返回拒绝理由；null 表示通过（含无法判定的保守情况）。 */
    String rejectReason(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() != HopKind.FIELD_FLOW || hop.field() == null) {
                continue;
            }
            String declaring = bb.hierarchy().resolveField(hop.toOwner(), hop.field());
            if (declaring == null || !bb.hierarchy().isSerializable(declaring)) {
                continue; // 不可解析或框架管线对象（非序列化声明类）：前提不适用
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            FieldInfo field = cls != null ? cls.field(hop.field()) : null;
            if (field == null || !field.descriptor().startsWith("L")) {
                continue; // 原语/数组/不可解析：保守通过
            }
            String typeClass = field.descriptor().substring(1, field.descriptor().length() - 1);
            if (bb.hierarchy().classInfo(typeClass) == null
                    || bb.hierarchy().classInfo("java/io/Serializable") == null) {
                continue; // 类型或 Serializable 标记不可解析：无法证明不可能
            }
            if (!serializableValuePossible(typeClass)) {
                return "non-serializable-field:" + declaring + "." + hop.field() + ":" + typeClass;
            }
        }
        return null;
    }

    /** 声明类型自身或其已加载子类型闭包中是否存在 Serializable（运行时值可承载的判定，记忆化）。 */
    private boolean serializableValuePossible(String type) {
        Boolean cached = serializablePossible.get(type);
        if (cached != null) {
            return cached;
        }
        serializablePossible.put(type, Boolean.FALSE); // 类层次无环，占位防自引用
        boolean result = bb.hierarchy().isSubtypeOf(type, "java/io/Serializable");
        if (!result) {
            if (ancestorChainUnresolvable(type)) {
                serializablePossible.put(type, Boolean.TRUE); // 祖先不可解析：无法证明不可能
                return true;
            }
            for (String sub : bb.hierarchy().loadedSubtypes(type)) {
                if (serializableValuePossible(sub)) {
                    result = true;
                    break;
                }
            }
        }
        serializablePossible.put(type, result);
        return result;
    }

    /** 父类链上是否存在不可解析类（无法证明子类型关系失败）。 */
    private boolean ancestorChainUnresolvable(String type) {
        String cur = type;
        Set<String> visited = new HashSet<>();
        while (cur != null && visited.add(cur)) {
            ClassInfo ci = bb.hierarchy().classInfo(cur);
            if (ci == null) {
                return true;
            }
            cur = ci.superName();
        }
        return false;
    }
}
