package io.just.sast.blackboard;

/** KS2 对某个 sink 的分析裁决（KS2 纠错 KS1 的机器可读记录）。 */
public record SinkOutcome(
        String ruleId, String category,
        String sinkOwner, String sinkMethod,
        String enclosingClass, String enclosingMethod,
        int chainsFound, String verdict, int steps, int unresolved, int tooLong) {}
