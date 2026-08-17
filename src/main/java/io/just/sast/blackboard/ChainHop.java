package io.just.sast.blackboard;

/** 链上的一跳。 */
public record ChainHop(
        String fromOwner, String fromName,
        String toOwner, String toName,
        HopKind kind, String field, String reason) {}
