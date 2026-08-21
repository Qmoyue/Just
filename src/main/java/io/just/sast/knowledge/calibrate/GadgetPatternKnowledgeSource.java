package io.just.sast.knowledge.calibrate;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.util.JustLogger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 已知 gadget 模式识别（CALIBRATION 阶段，借鉴 JDD 可利用性验证 + marshalsec 链分类）。
 * 当链路径同时包含已知 gadget 家族的关键类组合时，提升证据分并标注模式名。
 * 不产链不拒链——纯排序增强，帮分析者一眼识别"这是 CC1 型链"。
 */
public final class GadgetPatternKnowledgeSource implements KnowledgeSource {

    /** 已知 gadget 模式：名称 + 必须同时出现的类前缀集合 + 证据加分。 */
    private record Pattern(String name, Set<String> requiredClasses, int bonus) {}

    private static final List<Pattern> PATTERNS = List.of(
            new Pattern("CC1", Set.of(
                    "org/apache/commons/collections/functors/InvokerTransformer",
                    "org/apache/commons/collections/functors/ChainedTransformer"), 3),
            new Pattern("CC2", Set.of(
                    "org/apache/commons/collections/functors/InvokerTransformer",
                    "org/apache/commons/collections/comparators/TransformingComparator"), 3),
            new Pattern("CC3", Set.of(
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
                    "org/apache/commons/collections/functors/InstantiateTransformer"), 3),
            new Pattern("CC5", Set.of(
                    "javax/management/BadAttributeValueExpReader",
                    "org/apache/commons/collections/keyvalue/TiedMapEntry",
                    "org/apache/commons/collections/map/LazyMap"), 3),
            new Pattern("CC6", Set.of(
                    "org/apache/commons/collections/keyvalue/TiedMapEntry",
                    "org/apache/commons/collections/map/LazyMap"), 2),
            new Pattern("CC7", Set.of(
                    "java/util/Hashtable",
                    "org/apache/commons/collections/map/LazyMap"), 2),
            new Pattern("Spring1", Set.of(
                    "org/springframework/core/SerializableTypeWrapper$MethodInvokeTypeProvider",
                    "org/springframework/aop/framework/AdvisedSupport"), 3),
            new Pattern("Rome", Set.of(
                    "com/sun/syndication/feed/impl/EqualsBean",
                    "com/sun/syndication/feed/impl/ToStringBean"), 3),
            new Pattern("Jdk7u21", Set.of(
                    "sun/reflect/annotation/AnnotationInvocationHandler",
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"), 2),
            new Pattern("CB1", Set.of(
                    "org/apache/commons/beanutils/BeanComparator",
                    "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"), 3),
            new Pattern("SignedObject二次反序列化", Set.of(
                    "java/security/SignedObject",
                    "com/sun/syndication/feed/impl/EqualsBean"), 3));

    private Blackboard bb;

    @Override
    public String id() {
        return "gadget-pattern";
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
        Map<String, Integer> patternCounts = new HashMap<>();
        for (Chain chain : bb.chains()) {
            if (bb.calibrationOf(chain.key()) != null) {
                continue;
            }
            String matched = matchPattern(chain);
            if (matched != null) {
                patternCounts.merge(matched, 1, Integer::sum);
                // 标注在 evidence 列（通过 qualityNote 附着）
                bb.qualityNote(-1, "gadget-pattern:" + matched);
            }
        }
        if (!patternCounts.isEmpty()) {
            JustLogger.info("已知 gadget 模式：{}",
                    patternCounts.entrySet().stream()
                            .map(e -> e.getKey() + "×" + e.getValue())
                            .collect(java.util.stream.Collectors.joining(", ")));
        }
    }

    /** 链路径是否同时包含某模式的全部关键类。 */
    private String matchPattern(Chain chain) {
        // 收集链路径上出现的所有类
        Set<String> pathClasses = new java.util.HashSet<>();
        pathClasses.add(chain.entryClass());
        for (ChainHop hop : chain.hops()) {
            pathClasses.add(hop.fromOwner());
            pathClasses.add(hop.toOwner());
        }
        for (Pattern pattern : PATTERNS) {
            if (pathClasses.stream().mapToLong(c ->
                    pattern.requiredClasses().stream().filter(c::startsWith).count())
                    .sum() >= pattern.requiredClasses().size()) {
                return pattern.name();
            }
        }
        return null;
    }
}
