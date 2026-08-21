package io.just.sast.knowledge.engine;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.util.JustLogger;

import java.util.Set;

/**
 * 前向对象污点知识源（ANALYSIS 阶段，合并原 KS4 粗扫 + KS5 精扫）。
 * 同一 ForwardEngine 两轮扫描（coarse → refined），共享一次 buildIndexes。
 * GadgetInspector 式正向：magic entry / OIS 读种子 → 对象污点事实不动点 → sink 判定。
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
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        // 粗扫（类级事实 + 可达剪枝）
        new ForwardEngine(bb, ForwardEngine.Options.coarse()).run();
        // 精扫（接口/代理/反射精化选项，复用同一次 buildIndexes 的索引）
        new ForwardEngine(bb, ForwardEngine.Options.refined()).run();
    }
}
