package io.just.sast.blackboard;

/** magic entry 标记（KS1 产物，挂在 METHOD 节点上）。 */
public record MagicEntryMark(String ruleId, String entryKind, String className) {}
