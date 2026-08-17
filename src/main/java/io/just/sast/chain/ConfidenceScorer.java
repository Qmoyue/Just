package io.just.sast.chain;

import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.HopKind;

/**
 * 证据化置信度评分：逐跳证据 + 入口权重 + 严重度加成，产出可复核的分值与分桶。
 * 分值依据（每条链的 CSV evidence 列可逐项核对）：
 * 逐跳：DIRECT_CALL +1；FIELD_FLOW +1（带字段名）；VIRTUAL_DISPATCH 0；LAMBDA 0
 * 入口：readObject/readResolve/readObjectNoData/readExternal/hashCode/proxyInvoke +2；
 *       equals/compareTo/compare/toString/finalize +1；deserialization（OIS 源）+1
 * 严重度：HIGH +1
 * 惩罚：unresolved × 2
 * 分桶：score ≥ 5 → HIGH；≥ 3 → MEDIUM；否则 LOW
 */
public final class ConfidenceScorer {

    private ConfidenceScorer() {}

    public static String score(Chain chain) {
        return switch (rank(chain)) {
            case 0 -> "HIGH";
            case 1 -> "MEDIUM";
            default -> "LOW";
        };
    }

    /** 证据分值（越大越可信，供排序与分桶）。 */
    public static int evidenceScore(Chain chain) {
        int points = 0;
        for (ChainHop hop : chain.hops()) {
            points += switch (hop.kind()) {
                case DIRECT_CALL, FIELD_FLOW -> 1;
                case VIRTUAL_DISPATCH, LAMBDA -> 0;
                case ENTRY -> 0;
            };
        }
        points += entryWeight(chain.entryKind());
        if ("HIGH".equals(chain.severity())) {
            points += 1;
        }
        points -= chain.unresolvedHops() * 2;
        return points;
    }

    /** 置信度等级（数字越小越高）。 */
    public static int rank(Chain chain) {
        int score = evidenceScore(chain);
        return score >= 5 ? 0 : score >= 3 ? 1 : 2;
    }

    private static int entryWeight(String entryKind) {
        if (entryKind == null) {
            return 0;
        }
        return switch (entryKind) {
            case "readObject", "readResolve", "readObjectNoData", "readExternal",
                    "hashCode", "proxyInvoke" -> 2;
            case "equals", "compareTo", "compare", "toString", "finalize" -> 1;
            case "deserialization" -> 1;
            default -> 1;
        };
    }
}
