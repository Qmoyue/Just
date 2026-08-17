package io.just.sast.knowledge.ks3;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.SinkMark;
import io.just.sast.blackboard.SinkOutcome;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;
import io.just.sast.knowledge.ks2.BackwardEngine;
import io.just.sast.util.JustLogger;

import java.util.Set;

/**
 * KS3 上下文敏感补分析（校准 KS2 的裁决）。
 * 对 KS2 粗扫未命中的 sink（NO_PATH/UNRESOLVED/TOO_LONG）做补分析：
 * 返回流进入目标方法 + 调用点敏感（参数需求只回传进入时的调用点），
 * 消除全调用者扇出噪声，提升命中能力。
 */
public final class ContextRefineKnowledgeSource implements KnowledgeSource {

    private static final Set<String> REFINE_VERDICTS = Set.of("NO_PATH", "UNRESOLVED", "TOO_LONG");

    @Override
    public String id() {
        return "context-refine";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public void init(Blackboard blackboard) {
        // 引擎按需创建
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        BackwardEngine engine = new BackwardEngine(bb, BackwardEngine.Options.refine(bb.maxDepth()));
        int refined = 0;
        int chainsBefore = bb.chains().size();
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            SinkOutcome outcome = bb.sinkOutcomes().get(call.id());
            if (outcome == null || !REFINE_VERDICTS.contains(outcome.verdict())) {
                continue; // KS2 已命中或未标记的 sink 不补分析
            }
            SinkMark mark = bb.sinkOf(call.id());
            if (mark == null) {
                mark = RuleEngine.matchingSink(bb.rules(), call)
                        .map(rule -> new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted()))
                        .orElse(null);
            }
            if (mark == null) {
                continue;
            }
            refined++;
            engine.analyzeSink(call.id(), mark);
        }
        JustLogger.info("KS3 补分析 {} 个未命中 sink，新增链 {} 条",
                refined, bb.chains().size() - chainsBefore);
    }
}
