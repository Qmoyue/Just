package io.just.sast.config;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Node;

import java.util.Optional;

/** 规则匹配共享工具（KS1/KS2/KS4/KS5 各自独立枚举时共用，非知识源）。 */
public final class RuleEngine {

    private RuleEngine() {}

    /** 匹配 sink 规则（含 owner 层次解析：调用点 owner 为规则 owner 的子类型/实现类时命中）。 */
    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, ClassHierarchy hierarchy, Node call) {
        return matchingSink(rules, hierarchy, call.strProp("owner"), call.strProp("name"), call.strProp("desc"));
    }

    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, ClassHierarchy hierarchy,
                                                       String owner, String name, String desc) {
        for (Rule.SinkRule rule : rules.sinks()) {
            Rule.CallMatcher call = rule.call();
            if (call.matches(owner, name, desc)) {
                return Optional.of(rule);
            }
            // 层次命中：调用点 owner 为规则 owner（字面量类型）的子类型/实现类
            String ownerType = call.ownerType();
            if (ownerType != null && call.matchesRest(name, desc)
                    && hierarchy.isSubtypeOf(owner, ownerType)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }

    /** 匹配 magic-entry 规则（含 implementsType 层次校验）。 */
    public static Optional<Rule.MagicEntryRule> matchingEntry(RuleSet rules, ClassHierarchy hierarchy,
                                                              String owner, String name, String desc) {
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            if (rule.method().matches(name, desc)
                    && (rule.implementsType() == null || hierarchy.isSubtypeOf(owner, rule.implementsType()))) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }
}
