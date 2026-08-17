package io.just.sast.config;

import java.util.List;

/** 编译后的规则集。 */
public record RuleSet(List<Rule.SinkRule> sinks, List<Rule.MagicEntryRule> magicEntries) {

    public static final RuleSet EMPTY = new RuleSet(List.of(), List.of());
}
