package io.just.sast.config;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.cpg.graph.Node;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * 规则匹配引擎（各 KS 共用，经黑板分发同一实例）。
 * 匹配结果按 (owner|name|desc) 缓存，层次命中由 ClassHierarchy 判定。
 */
public final class RuleEngine {

    private RuleEngine() {}

    private static final Map<String, Optional<Rule.SinkRule>> sinkCache = new HashMap<>();

    /** 精确匹配 + 层次命中（调用点 owner 为规则 owner 子类型/实现类时命中）。 */
    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, ClassHierarchy hierarchy, Node call) {
        return matchingSink(rules, hierarchy, call.strProp("owner"), call.strProp("name"), call.strProp("desc"));
    }

    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, ClassHierarchy hierarchy,
                                                String owner, String name, String desc) {
        String cacheKey = owner + "|" + name + "|" + desc;
        return sinkCache.computeIfAbsent(cacheKey, k -> {
            for (Rule.SinkRule rule : rules.sinks()) {
                Rule.CallMatcher call = rule.call();
                if (call.matches(owner, name, desc)) {
                    return Optional.of(rule);
                }
                String ownerType = call.ownerType();
                if (ownerType != null && call.matchesRest(name, desc)
                        && hierarchy.isSubtypeOf(owner, ownerType)) {
                    return Optional.of(rule);
                }
            }
            return Optional.empty();
        });
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

    /** 匹配 source 规则（框架桥接用）。 */
    public static Optional<Rule.SourceRule> matchingSource(RuleSet rules, String owner, String name, String desc) {
        for (Rule.SourceRule rule : rules.sources()) {
            if (rule.call().matches(owner, name, desc)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }
}
