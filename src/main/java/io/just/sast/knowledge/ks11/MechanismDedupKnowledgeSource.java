package io.just.sast.knowledge.ks11;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.chain.ConfidenceScorer;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * KS11 机制去重校准（CALIBRATION 阶段）：同一"机制尾"（sink + 类别 + 去首跳的路径签名）
 * 的多入口链按**入口家族**（类路径前两段，如 com.google / java.util）各留一条最优代表
 * （未解析少 → 链短 → 证据分高），同家族其余变体以 mechanism-duplicate 拒绝。
 * 动机：KS6/KS7 的"任意入口 × 同一机制"笛卡尔积对人工审阅是纯噪音——同机制内
 * 不同家族=不同攻击面（值得各留一行），同家族变体才是重复。
 */
public final class MechanismDedupKnowledgeSource implements KnowledgeSource {

    /** 每个机制组保留的入口家族数上限。 */
    private static final int MAX_FAMILIES = 5;

    private Blackboard bb;

    @Override
    public String id() {
        return "mechanism-dedup";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        Map<String, List<Chain>> groups = new LinkedHashMap<>();
        for (Chain chain : bb.chains()) {
            groups.computeIfAbsent(mechanismKey(chain), k -> new ArrayList<>()).add(chain);
        }
        int rejected = 0;
        for (List<Chain> group : groups.values()) {
            group.sort(Comparator.<Chain>comparingInt(Chain::unresolvedHops)
                    .thenComparingInt(c -> c.hops().size())
                    .thenComparingInt(c -> -ConfidenceScorer.evidenceScore(c))
                    .thenComparing(Chain::key));
            Set<String> keptFamilies = new java.util.LinkedHashSet<>();
            boolean familyCapReached = false;
            for (Chain chain : group) {
                String family = entryFamily(chain.entryClass());
                if (keptFamilies.contains(family)) {
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    rejected++;
                    continue;
                }
                if (familyCapReached) {
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    rejected++;
                    continue;
                }
                if (keptFamilies.size() >= MAX_FAMILIES) {
                    familyCapReached = true;
                    bb.calibrateChain(chain.key(), "mechanism-duplicate");
                    rejected++;
                    continue;
                }
                keptFamilies.add(family);
            }
        }
        JustLogger.info("KS11 机制去重：{} 组机制，去重拒绝 {} 条", groups.size(), rejected);
    }

    /** 入口家族：类路径前两段（不足取全部），如 com.google / java.util / 无包类取类名。 */
    private static String entryFamily(String entryClass) {
        String[] parts = entryClass.split("/");
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1];
        }
        return entryClass;
    }

    /**
     * 机制尾签名：sink + 类别 + 跳列表去掉首跳（入口侧最近一跳，随入口变化）后的
     * 方法/类型/字段序列。同签名的链=同一机制的不同入口变体。
     */
    private static String mechanismKey(Chain chain) {
        StringBuilder sb = new StringBuilder();
        sb.append(chain.sinkClass()).append('.').append(chain.sinkMethod())
                .append('|').append(chain.category()).append('|');
        List<ChainHop> hops = chain.hops();
        for (int i = 1; i < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.kind() == HopKind.ENTRY) {
                continue;
            }
            sb.append(hop.toOwner()).append('.').append(hop.toName()).append('.')
                    .append(hop.field() != null ? hop.field() : "").append(';');
        }
        return sb.toString();
    }
}
