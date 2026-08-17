package io.just.sast.blackboard;

import io.just.sast.analysis.hierarchy.ClassHierarchy;
import io.just.sast.config.RuleSet;
import io.just.sast.cpg.build.FieldWriterIndex;
import io.just.sast.cpg.graph.Graph;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 黑板 = CPG 图 + 标记 + 链产物 + 事件队列。
 * 知识源通过本对象读写共享状态，互不直接调用。
 */
public final class Blackboard {

    private final Graph graph;
    private final ClassHierarchy hierarchy;
    private final FieldWriterIndex fieldWriters;
    private final RuleSet rules;
    private final int maxDepth;

    private final Map<Long, SinkMark> sinkMarks = new HashMap<>();
    private final Map<Long, MagicEntryMark> entryMarks = new HashMap<>();
    private final Map<Long, SinkOutcome> sinkOutcomes = new HashMap<>();
    private final List<Chain> chains = new ArrayList<>();
    private final Set<String> chainKeys = new HashSet<>();
    private final Map<Long, List<String>> qualityNotes = new HashMap<>();
    private final Deque<Event> queue = new ArrayDeque<>();
    private final Set<Long> pendingSinks = new HashSet<>();

    public Blackboard(Graph graph, ClassHierarchy hierarchy, FieldWriterIndex fieldWriters,
                      RuleSet rules, int maxDepth) {
        this.graph = graph;
        this.hierarchy = hierarchy;
        this.fieldWriters = fieldWriters;
        this.rules = rules;
        this.maxDepth = maxDepth;
    }

    public Graph graph() {
        return graph;
    }

    public ClassHierarchy hierarchy() {
        return hierarchy;
    }

    public FieldWriterIndex fieldWriters() {
        return fieldWriters;
    }

    public RuleSet rules() {
        return rules;
    }

    public int maxDepth() {
        return maxDepth;
    }

    // ---- 标记（KS1 写） ----

    public void markSink(long callNodeId, SinkMark mark) {
        sinkMarks.put(callNodeId, mark);
        publish(Event.of(EventType.SINK_MARKED, callNodeId, mark));
    }

    public void markMagicEntry(long methodNodeId, MagicEntryMark mark) {
        entryMarks.put(methodNodeId, mark);
        publish(Event.of(EventType.MAGIC_ENTRY_MARKED, methodNodeId, mark));
    }

    public SinkMark sinkOf(long callNodeId) {
        return sinkMarks.get(callNodeId);
    }

    // ---- sink 裁决（KS2 写，反馈给 KS1 的结果） ----

    public void recordOutcome(long callNodeId, SinkOutcome outcome) {
        sinkOutcomes.put(callNodeId, outcome);
    }

    public Map<Long, SinkOutcome> sinkOutcomes() {
        return sinkOutcomes;
    }

    public boolean isMagicEntry(long methodNodeId) {
        return entryMarks.containsKey(methodNodeId);
    }

    public MagicEntryMark entryOf(long methodNodeId) {
        return entryMarks.get(methodNodeId);
    }

    public int sinkCount() {
        return sinkMarks.size();
    }

    public int entryCount() {
        return entryMarks.size();
    }

    // ---- 链产物（KS2 写） ----

    /** 记录链；按 key 去重。返回是否为新链。 */
    public synchronized boolean addChain(Chain chain) {
        if (chainKeys.add(chain.key())) {
            chains.add(chain);
            publish(Event.of(EventType.CHAIN_FOUND, -1, chain));
            return true;
        }
        return false;
    }

    public List<Chain> chains() {
        return chains;
    }

    // ---- 质量注释 ----

    public void qualityNote(long callNodeId, String note) {
        qualityNotes.computeIfAbsent(callNodeId, k -> new ArrayList<>(1)).add(note);
    }

    public List<String> qualityNotesOf(long callNodeId) {
        List<String> list = qualityNotes.get(callNodeId);
        return list != null ? list : List.of();
    }

    // ---- 事件 ----

    public void publish(Event event) {
        synchronized (queue) {
            queue.addLast(event);
        }
    }

    Event poll() {
        synchronized (queue) {
            return queue.pollFirst();
        }
    }

    boolean hasEvents() {
        synchronized (queue) {
            return !queue.isEmpty();
        }
    }
}
