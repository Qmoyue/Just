package io.just.sast.blackboard;

import io.just.sast.util.JustLogger;

import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 黑板控制器：串行三阶段调度。
 * ANALYSIS（SCAN_START）产出分析 → COMPOSITION（SCAN_ANALYZED）组装多级链
 * → CALIBRATION（SCAN_COMPLETE）校准全部链。
 * 只做调度不做评分决策；init/onEvent 异常按知识源隔离（含 Error），不中断全扫。
 */
public final class Controller {

    /** 单阶段事件派生上限（有界恢复：防事件风暴）。 */
    private static final int MAX_DISPATCH = 1_000_000;

    private final Blackboard blackboard;
    private final List<KnowledgeSource> sources;

    public Controller(Blackboard blackboard, List<KnowledgeSource> sources) {
        this.blackboard = blackboard;
        this.sources = sources;
    }

    public void run() {
        Map<Phase, Map<EventType, Set<KnowledgeSource>>> subsByPhase = new EnumMap<>(Phase.class);
        for (KnowledgeSource ks : sources) {
            try {
                ks.init(blackboard);
            } catch (Throwable e) {
                JustLogger.error("知识源 {} 初始化失败（已隔离）: {}", ks.id(), e.toString());
            }
            Map<EventType, Set<KnowledgeSource>> subs =
                    subsByPhase.computeIfAbsent(ks.phase(), p -> new EnumMap<>(EventType.class));
            for (EventType type : ks.interests()) {
                subs.computeIfAbsent(type, t -> new java.util.LinkedHashSet<>()).add(ks);
            }
        }
        int dispatched = 0;
        blackboard.publish(Event.of(EventType.SCAN_START, -1, null));
        dispatched += drain(subsByPhase.getOrDefault(Phase.ANALYSIS, Map.of()));
        blackboard.publish(Event.of(EventType.SCAN_ANALYZED, -1, null));
        dispatched += drain(subsByPhase.getOrDefault(Phase.COMPOSITION, Map.of()));
        blackboard.publish(Event.of(EventType.SCAN_COMPLETE, -1, null));
        dispatched += drain(subsByPhase.getOrDefault(Phase.CALIBRATION, Map.of()));
        JustLogger.info("黑板分析完成：分发事件 {} 次，sink {} 个，entry {} 个，链 {} 条",
                dispatched, blackboard.sinkCount(), blackboard.entryCount(), blackboard.chains().size());
    }

    /** 排空事件队列，按阶段订阅表分发。 */
    private int drain(Map<EventType, Set<KnowledgeSource>> subs) {
        int dispatched = 0;
        while (blackboard.hasEvents()) {
            if (dispatched >= MAX_DISPATCH) {
                JustLogger.warn("事件派生超上限 {}，本阶段提前结束", MAX_DISPATCH);
                blackboard.clearEvents();
                break;
            }
            Event event = blackboard.poll();
            if (event == null) {
                break;
            }
            Set<KnowledgeSource> interested = subs.get(event.type());
            if (interested == null) {
                continue;
            }
            for (KnowledgeSource ks : interested) {
                try {
                    ks.onEvent(blackboard, event);
                    dispatched++;
                } catch (Throwable e) {
                    JustLogger.error("知识源 {} 处理事件 {} 失败（已隔离）: {}", ks.id(), event.type(), e.toString());
                    if (JustLogger.isDebug()) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return dispatched;
    }
}
