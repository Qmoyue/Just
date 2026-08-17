package io.just.sast.blackboard;

import io.just.sast.util.JustLogger;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 黑板控制器：事件循环调度知识源。
 * 只做 FIFO 调度与分发，不做评分决策；事件队列清空即不动点。
 */
public final class Controller {

    private final Blackboard blackboard;
    private final List<KnowledgeSource> sources;

    public Controller(Blackboard blackboard, List<KnowledgeSource> sources) {
        this.blackboard = blackboard;
        this.sources = sources;
    }

    public void run() {
        Map<EventType, Set<KnowledgeSource>> subscribers = new EnumMap<>(EventType.class);
        for (KnowledgeSource ks : sources) {
            ks.init(blackboard);
            for (EventType type : ks.interests()) {
                subscribers.computeIfAbsent(type, t -> new java.util.LinkedHashSet<>()).add(ks);
            }
        }
        blackboard.publish(Event.of(EventType.SCAN_START, -1, null));
        int dispatched = 0;
        while (blackboard.hasEvents()) {
            Event event = blackboard.poll();
            if (event == null) {
                break;
            }
            Set<KnowledgeSource> interested = subscribers.get(event.type());
            if (interested == null) {
                continue;
            }
            for (KnowledgeSource ks : interested) {
                try {
                    ks.onEvent(blackboard, event);
                    dispatched++;
                } catch (Exception e) {
                    JustLogger.error("知识源 {} 处理事件 {} 失败: {}", ks.id(), event.type(), e.getMessage());
                }
            }
        }
        JustLogger.info("黑板分析完成：分发事件 {} 次，sink {} 个，entry {} 个，链 {} 条",
                dispatched, blackboard.sinkCount(), blackboard.entryCount(), blackboard.chains().size());
    }
}
