package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import io.just.sast.model.FieldInfo;
import io.just.sast.util.JustLogger;

import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 * 链校验知识源（CALIBRATION 阶段，合并原 KS3 PASM + KS8 类型流 + KS9 序列化可行性）。
 * 三层校验均保守——只拒绝可证明不可能的链：
 * 1. 可行性：字段声明存在 / 方法可解析（原 KS3）
 * 2. 类型流：来源类型（final 精确）与形参类型非子类型关系（原 KS8）
 * 3. 序列化可行性：字段声明类型无可序列化子类闭包（原 KS9）
 */
public final class ChainValidatorKnowledgeSource implements KnowledgeSource {

    private static final Set<String> TRIGGER_NOT_REQUIRED = Set.of(
            "readObject", "readObjectNoData", "readExternal", "proxyInvoke", "deserialization");

    private Blackboard bb;
    // KS9 缓存
    private final java.util.Map<String, Boolean> serializablePossible = new HashMap<>();

    @Override
    public String id() {
        return "chain-validator";
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
        int pasm = 0;
        int typeflow = 0;
        int serialize = 0;
        for (Chain chain : bb.chains()) {
            // 1. PASM 可行性（原 KS3）
            String reason = pasmReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                pasm++;
                continue;
            }
            // 2. 类型流（原 KS8）
            reason = typeflowReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                typeflow++;
                continue;
            }
            // 3. 序列化可行性（原 KS9）
            reason = serializeReject(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                serialize++;
            }
        }
        JustLogger.info("链校验：PASM 拒绝 {}，类型流拒绝 {}，序列化拒绝 {}（共 {} 条）",
                pasm, typeflow, serialize, bb.chains().size());
    }

    // ---- 1. PASM 可行性（原 KS3） ----

    private String pasmReject(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() == HopKind.ENTRY || hop.kind() == HopKind.LAMBDA) {
                continue;
            }
            if (hop.kind() == HopKind.FIELD_FLOW) {
                String declaring = bb.hierarchy().resolveField(hop.fromOwner(), hop.field());
                if (declaring == null && bb.hierarchy().superclassChainResolvable(hop.fromOwner())) {
                    return "field-not-declared:" + hop.fromOwner() + "." + hop.field();
                }
                continue;
            }
            if (hop.desc() == null || hop.desc().isEmpty()) {
                continue;
            }
            if (bb.hierarchy().classInfo(hop.toOwner()) == null) {
                continue;
            }
            if (bb.hierarchy().resolveMethod(hop.toOwner(), hop.toName(), hop.desc()) == null) {
                return "method-not-declared:" + hop.toOwner() + "." + hop.toName() + hop.desc();
            }
        }
        return null;
    }

    // ---- 2. 类型流（原 KS8） ----

    private String typeflowReject(Chain chain) {
        var hops = chain.hops();
        for (int i = 0; i + 1 < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.argOrdinal() == null || hop.desc() == null || hop.desc().isEmpty()) {
                continue;
            }
            String param = Descriptor.paramType(hop.desc(), hop.argOrdinal());
            if (param == null || !param.startsWith("L")) {
                continue;
            }
            String source = sourceType(hops.get(i + 1), chain);
            if (source == null || !source.startsWith("L")) {
                continue;
            }
            String sourceClass = source.substring(1, source.length() - 1);
            String paramClass = param.substring(1, param.length() - 1);
            var sourceInfo = bb.hierarchy().classInfo(sourceClass);
            if (sourceInfo == null || bb.hierarchy().classInfo(paramClass) == null) {
                continue;
            }
            if (!Modifier.isFinal(sourceInfo.access())) {
                continue; // 非 final 上界不可证
            }
            if (!bb.hierarchy().isSubtypeOf(sourceClass, paramClass)) {
                return "typeflow:" + sourceClass + "-!->" + paramClass;
            }
        }
        return null;
    }

    private String sourceType(ChainHop hop, Chain chain) {
        if (hop.kind() == HopKind.ENTRY) {
            return "L" + chain.entryClass() + ";";
        }
        if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
            String declaring = bb.hierarchy().resolveField(hop.toOwner(), hop.field());
            if (declaring == null) {
                return null;
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            if (cls == null || cls.field(hop.field()) == null) {
                return null;
            }
            return cls.field(hop.field()).descriptor();
        }
        if (hop.argOrdinal() != null && hop.desc() != null && !hop.desc().isEmpty()) {
            return Descriptor.paramType(hop.desc(), hop.argOrdinal());
        }
        return null;
    }

    // ---- 3. 序列化可行性（原 KS9） ----

    private String serializeReject(Chain chain) {
        for (ChainHop hop : chain.hops()) {
            if (hop.kind() != HopKind.FIELD_FLOW || hop.field() == null) {
                continue;
            }
            String declaring = bb.hierarchy().resolveField(hop.toOwner(), hop.field());
            if (declaring == null || !bb.hierarchy().isSerializable(declaring)) {
                continue;
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            FieldInfo field = cls != null ? cls.field(hop.field()) : null;
            if (field == null || !field.descriptor().startsWith("L")) {
                continue;
            }
            String typeClass = field.descriptor().substring(1, field.descriptor().length() - 1);
            if (bb.hierarchy().classInfo(typeClass) == null
                    || bb.hierarchy().classInfo("java/io/Serializable") == null) {
                continue;
            }
            if (!serializableValuePossible(typeClass)) {
                return "non-serializable-field:" + declaring + "." + hop.field() + ":" + typeClass;
            }
        }
        return null;
    }

    private boolean serializableValuePossible(String type) {
        Boolean cached = serializablePossible.get(type);
        if (cached != null) {
            return cached;
        }
        serializablePossible.put(type, Boolean.FALSE);
        boolean result = bb.hierarchy().isSubtypeOf(type, "java/io/Serializable");
        if (!result) {
            if (ancestorChainUnresolvable(type)) {
                serializablePossible.put(type, Boolean.TRUE);
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
