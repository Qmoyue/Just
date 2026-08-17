package io.just.sast.blackboard;

/** 黑板事件。 */
public record Event(EventType type, long nodeId, Object payload) {

    public static Event of(EventType type, long nodeId, Object payload) {
        return new Event(type, nodeId, payload);
    }
}
