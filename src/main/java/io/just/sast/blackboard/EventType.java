package io.just.sast.blackboard;

/** 黑板事件类型（封闭集合）。 */
public enum EventType {
    /** 扫描启动，触发 KS1 全量标记 */
    SCAN_START,
    /** KS1 标记了一个 sink */
    SINK_MARKED,
    /** KS1 标记了一个 magic entry */
    MAGIC_ENTRY_MARKED,
    /** KS2 完成一条链 */
    CHAIN_FOUND
}
