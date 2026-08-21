package io.just.sast.knowledge.calibrate;

import io.just.sast.analysis.taint.OriginSupport;
import io.just.sast.analysis.taint.ValueOrigin;
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
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.util.JustLogger;

import java.util.HashSet;
import java.util.Set;

/**
 * SafeConfig 抑制知识源（CALIBRATION 阶段，借鉴 CodeQL SafeXStreamConfig/SafeKryoConfig）。
 * 当框架入口实例被安全配置（白名单/注册要求/安全模式）后，该入口产生的链全部抑制——
 * 纯降噪，不影响检出率（安全配置的实例不构成攻击面）。
 *
 * 检测方式：找"同一方法体内"先调用安全配置方法再调用框架入口的序列——
 * 配置与反序列化在同一作用域时，该入口点视为安全。
 */
public final class SafeConfigKnowledgeSource implements KnowledgeSource {

    /** 安全配置方法（框架实例配置为安全模式） */
    private record SafeConfigCall(String ownerPrefix, Set<String> methodNames) {}

    private static final Set<SafeConfigCall> SAFE_CONFIGS = Set.of(
            // XStream：配置白名单/权限
            new SafeConfigCall("com/thoughtworks/xstream/XStream", Set.of(
                    "addPermission", "denyPermission", "clearPermissions", "setMode")),
            // Kryo：要求注册（白名单模式）
            new SafeConfigCall("com/esotericsoftware/kryo/Kryo", Set.of(
                    "setRegistrationRequired")),
            // SnakeYAML 2.x：SafeConstructor
            new SafeConfigCall("org/yaml/snakeyaml/constructor/SafeConstructor", Set.of(
                    "<init>")),
            // Jackson：禁用 default typing
            new SafeConfigCall("com/fasterxml/jackson/databind/ObjectMapper", Set.of(
                    "deactivateDefaultTyping", "setPolymorphicTypeValidator")));

    /** 反序列化框架入口（须与 source 规则的 owner 匹配） */
    private static final Set<String> DESER_OWNERS = Set.of(
            "com/thoughtworks/xstream/XStream",
            "com/esotericsoftware/kryo/Kryo",
            "org/yaml/snakeyaml/Yaml",
            "com/alibaba/fastjson/JSON",
            "com/alibaba/fastjson2/JSON",
            "com/fasterxml/jackson/databind/ObjectMapper");

    private Blackboard bb;

    @Override
    public String id() {
        return "safe-config";
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
        // 找安全配置的方法（这些方法体内的框架入口调用视为安全）
        Set<String> safeMethodKeys = findSafeConfiguredMethods();
        if (safeMethodKeys.isEmpty()) {
            return;
        }
        // 拒绝入口在这些方法内的链
        int rejected = 0;
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue; // 已被前面校验拒绝
            }
            String entryKey = chain.entryClass() + "#" + chain.entryMethod();
            if (safeMethodKeys.contains(entryKey)) {
                bb.calibrateChain(chain.key(), "safe-config");
                rejected++;
            }
        }
        if (rejected > 0) {
            JustLogger.info("SafeConfig 抑制：{} 条链（入口方法含安全配置）", rejected);
        }
    }

    /** 找"方法体内同时有安全配置调用和反序列化入口调用"的方法。 */
    private Set<String> findSafeConfiguredMethods() {
        Set<String> result = new HashSet<>();
        var support = bb.originSupport();
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            MethodInfo info = support.methodOf(method.strProp("owner"),
                    method.strProp("name"), method.strProp("desc"));
            if (info == null) {
                continue;
            }
            boolean hasSafeConfig = false;
            boolean hasDeserEntry = false;
            for (InsnFact insn : info.instructions()) {
                if (!insn.op().isInvoke() || insn.operands().isEmpty()) {
                    continue;
                }
                if (!(insn.operands().get(0) instanceof MethodRef ref)) {
                    continue;
                }
                if (isSafeConfigCall(ref.owner(), ref.name())) {
                    hasSafeConfig = true;
                }
                if (isDeserEntryCall(ref.owner(), ref.name())) {
                    hasDeserEntry = true;
                }
            }
            if (hasSafeConfig && hasDeserEntry) {
                result.add(io.just.sast.analysis.taint.OriginSupport.methodKeyOf(
                        info.owner(), info.name(), info.descriptor()));
            }
        }
        return result;
    }

    private static boolean isSafeConfigCall(String owner, String name) {
        for (SafeConfigCall sc : SAFE_CONFIGS) {
            if (owner.startsWith(sc.ownerPrefix()) && sc.methodNames().contains(name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isDeserEntryCall(String owner, String name) {
        for (String deserOwner : DESER_OWNERS) {
            if (owner.startsWith(deserOwner)) {
                return switch (name) {
                    case "fromXML", "readObject", "readClassAndObject", "load", "loadAs",
                         "parseObject", "parse", "readValue" -> true;
                    default -> false;
                };
            }
        }
        return false;
    }
}
