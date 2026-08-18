package io.just.sast.knowledge.ks5;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.knowledge.ks4.ForwardEngine;

import java.util.Set;

/**
 * KS5 分配点敏感 + 接口/代理/反射补全（精扫，与 KS4 共用前向引擎）。
 * 污点命中接口调用（实现>枚举上限未物化）时按上限展开实现类；
 * Proxy.newProxyInstance 的 handler 串入；Method.invoke 常量方法名反射解析。
 * 补齐 KS4 类级粗扫在接口扇出处的漏报，实现完整调用链挖掘。
 */
public final class AllocationSensitiveTaintKnowledgeSource implements KnowledgeSource {

    @Override
    public String id() {
        return "alloc-taint";
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
            new ForwardEngine(bb, ForwardEngine.Options.refined()).run();
        }
    }
}
