package io.just.sast.knowledge.ks1;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.MagicEntryMark;
import io.just.sast.blackboard.SinkMark;
import io.just.sast.config.RuleEngine;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;

import java.util.Set;

/**
 * KS1 模式匹配引擎（独立知识源，ANALYSIS 阶段）。
 * 高召回预筛：按规则圈定 sink 起点（CALL 节点，含 owner 层次命中）与 magic-entry 终点（METHOD 节点），写黑板。
 * 标记仅供报告层消费；其他知识源按契约自行匹配规则，不读本标记。
 */
public final class PatternKnowledgeSource implements KnowledgeSource {

    @Override
    public String id() {
        return "pattern";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public void init(Blackboard blackboard) {
        // 规则已随黑板注入，无额外初始化
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() == EventType.SCAN_START) {
            markSinks(bb);
            markMagicEntries(bb);
        }
    }

    private void markSinks(Blackboard bb) {
        for (Node call : bb.graph().nodesOfType(NodeType.CALL)) {
            RuleEngine.matchingSink(bb.rules(), bb.hierarchy(), call).ifPresent(rule ->
                    bb.markSink(call.id(), new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted())));
        }
    }

    private void markMagicEntries(Blackboard bb) {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = method.strProp("owner");
            RuleEngine.matchingEntry(bb.rules(), bb.hierarchy(), owner,
                            method.strProp("name"), method.strProp("desc"))
                    .ifPresent(rule ->
                            bb.markMagicEntry(method.id(), new MagicEntryMark(rule.id(), rule.entryKind(), owner)));
        }
    }
}
