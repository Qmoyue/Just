package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

/** 置信度评分：按路径证据分级（不依赖 sink 匹配方式）。 */
public final class ConfidenceScorer {

    private ConfidenceScorer() {}

    public static String score(Chain chain) {
        boolean hasWeak = false;
        for (ChainHop hop : chain.hops()) {
            HopKind kind = hop.kind();
            if (kind == HopKind.VIRTUAL_DISPATCH || kind == HopKind.LAMBDA || kind == HopKind.FIELD_FLOW) {
                hasWeak = true;
            }
        }
        if (chain.unresolvedHops() > 0) {
            return hasWeak ? "LOW" : "MEDIUM";
        }
        return hasWeak ? "MEDIUM" : "HIGH";
    }
}
