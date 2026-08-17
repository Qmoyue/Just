package io.just.sast.blackboard;

import java.util.Set;

/**
 * 知识源接口（插件化扩展点）。
 * 知识源之间零直接调用：只读写黑板，通过事件协作。
 */
public interface KnowledgeSource {

    /** 唯一标识。 */
    String id();

    /** 关心的事件类型。 */
    Set<EventType> interests();

    /** 初始化（规则编译、索引准备）。 */
    void init(Blackboard blackboard);

    /** 响应事件。 */
    void onEvent(Blackboard blackboard, Event event);
}
