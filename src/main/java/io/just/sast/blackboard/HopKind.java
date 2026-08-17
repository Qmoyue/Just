package io.just.sast.blackboard;

/** 链跳类型。 */
public enum HopKind {
    DIRECT_CALL,
    VIRTUAL_DISPATCH,
    LAMBDA,
    FIELD_FLOW,
    ENTRY
}
