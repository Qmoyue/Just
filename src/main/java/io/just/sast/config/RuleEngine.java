package io.just.sast.config;

import io.just.sast.cpg.graph.Node;

import java.util.Optional;

/** 规则匹配共享工具（KS1 与 KS2 各自独立枚举时共用，非知识源）。 */
public final class RuleEngine {

    private RuleEngine() {}

    /** 匹配 sink 规则：返回第一条命中的规则。 */
    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, Node call) {
        return matchingSink(rules, call.strProp("owner"), call.strProp("name"), call.strProp("desc"));
    }

    public static Optional<Rule.SinkRule> matchingSink(RuleSet rules, String owner, String name, String desc) {
        for (Rule.SinkRule rule : rules.sinks()) {
            if (rule.call().matches(owner, name, desc)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }

    /** 匹配 magic-entry 规则：返回第一条命中的规则（implementsType 校验由调用方提供）。 */
    public static Optional<Rule.MagicEntryRule> matchingEntry(RuleSet rules, String name, String desc) {
        for (Rule.MagicEntryRule rule : rules.magicEntries()) {
            if (rule.method().matches(name, desc)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }
}
