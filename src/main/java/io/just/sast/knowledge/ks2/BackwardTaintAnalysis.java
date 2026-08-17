package io.just.sast.knowledge.ks2;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.SinkMark;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;

import java.util.Set;

/**
 * KS2 反向污点引擎（独立知识源，与 KS1 交叉并行）。
 * 宽网粗扫：自行枚举 sink 候选（不读 KS1 标记），以 controlled 语义反向分析，
 * 链与裁决写黑板。未命中的 sink 由 KS3 上下文敏感补分析接管。
 */
public final class BackwardTaintAnalysis implements KnowledgeSource {

    @Override
    public String id() {
        return "backward-taint";
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
        BackwardEngine engine = new BackwardEngine(bb, BackwardEngine.Options.sweep(bb.maxDepth()));
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            RuleEngine.matchingSink(bb.rules(), call).ifPresent(rule ->
                    engine.analyzeSink(call.id(), new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted())));
        }
    }
}
