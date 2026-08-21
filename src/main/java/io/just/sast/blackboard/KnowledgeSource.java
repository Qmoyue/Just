package io.just.sast.blackboard;

import java.util.Set;

/**
 * 知识源接口（插件化扩展点）。
 * 知识源之间零直接调用：只读写黑板，通过事件协作。
 * 契约：ANALYSIS 阶段知识源必须自足（自行用 RuleEngine 匹配 sink/entry，不读其他知识源产物）；
 * 控制器串行两阶段调度（ANALYSIS → CALIBRATION），知识源无需线程安全。
 */
public interface KnowledgeSource {

    /** 唯一标识。 */
    String id();

    /** 关心的事件类型。 */
    Set<EventType> interests();

    /** 执行阶段，默认 ANALYSIS。 */
    default Phase phase() {
        return Phase.ANALYSIS;
    }

    /** 初始化（规则编译、索引准备）；异常由控制器隔离，不中断其他知识源。 */
    void init(Blackboard blackboard);

    /** 响应事件。 */
    void onEvent(Blackboard blackboard, Event event);
}
