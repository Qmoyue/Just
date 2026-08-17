package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

/** 置信度评分：按路径证据分级（不依赖 sink 匹配方式）。 */
public final class ConfidenceScorer {

    private ConfidenceScorer() {}

    public static String score(Chain chain) {
        return switch (rank(chain)) {
            case 0 -> "HIGH";
            case 1 -> "MEDIUM";
            default -> "LOW";
        };
    }

    /**
     * 置信度等级（数字越小越高，供排序）：
     * 0 = HIGH（全程直接调用、无未解析）
     * 1 = MEDIUM（含 CHA 虚分发/lambda 等弱证据）
     * 2 = LOW（含未解析跳）
     * 字段流转（FIELD_FLOW）是反序列化链的正常证据，不降级。
     */
    public static int rank(Chain chain) {
        boolean weak = false;
        for (ChainHop hop : chain.hops()) {
            HopKind kind = hop.kind();
            if (kind == HopKind.VIRTUAL_DISPATCH || kind == HopKind.LAMBDA) {
                weak = true;
            }
        }
        if (chain.unresolvedHops() > 0) {
            return weak ? 2 : 1;
        }
        return weak ? 1 : 0;
    }
}
