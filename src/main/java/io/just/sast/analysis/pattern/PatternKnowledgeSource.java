package io.just.sast.analysis.pattern;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.MagicEntryMark;
import io.just.sast.blackboard.SinkMark;
import io.just.sast.config.Rule;
import io.just.sast.cpg.graph.Node;
import io.just.sast.cpg.graph.NodeType;

import java.util.Set;

/**
 * KS1 模式匹配引擎：高召回预筛。
 * 标记 sink 起点（CALL 节点）与 magic-entry 终点（METHOD 节点），流式发事件。
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
            for (Rule.SinkRule rule : bb.rules().sinks()) {
                if (rule.call().matches(call.strProp("owner"), call.strProp("name"), call.strProp("desc"))) {
                    bb.markSink(call.id(), new SinkMark(rule.id(), rule.category(), rule.severity(), rule.tainted()));
                    break;
                }
            }
        }
    }

    private void markMagicEntries(Blackboard bb) {
        for (Node method : bb.graph().nodesOfType(NodeType.METHOD)) {
            String owner = method.strProp("owner");
            for (Rule.MagicEntryRule rule : bb.rules().magicEntries()) {
                if (!rule.method().matches(method.strProp("name"), method.strProp("desc"))) {
                    continue;
                }
                if (rule.implementsType() != null && !bb.hierarchy().isSubtypeOf(owner, rule.implementsType())) {
                    continue;
                }
                bb.markMagicEntry(method.id(), new MagicEntryMark(rule.id(), rule.entryKind(), owner));
                break;
            }
        }
    }
}
