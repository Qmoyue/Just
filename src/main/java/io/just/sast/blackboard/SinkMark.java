package io.just.sast.blackboard;

import io.just.sast.config.Rule;

import java.util.List;

/** sink 标记（KS1 产物，挂在 CALL 节点上）。 */
public record SinkMark(String ruleId, String category, String severity, List<Rule.TaintedPos> tainted) {}
