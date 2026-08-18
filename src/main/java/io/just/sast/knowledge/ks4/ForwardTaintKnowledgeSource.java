package io.just.sast.knowledge.ks4;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;

import java.util.Set;

/**
 * KS4 前向对象污点引擎（粗扫，独立知识源，与 KS1/KS2 交叉并行）。
 * GadgetInspector 式正向：类级事实、无接口/代理展开，速度快。
 * 精扫（接口/代理/反射补全）由 KS5 以同一引擎执行。
 */
public final class ForwardTaintKnowledgeSource implements KnowledgeSource {

    @Override
    public String id() {
        return "forward-taint";
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
        if (event.type() == EventType.SCAN_START) {
            new ForwardEngine(bb, ForwardEngine.Options.coarse()).run();
        }
    }
}
