package io.just.sast.blackboard;

/** 链上的一跳。desc 为目标方法描述符（entry/字段跳为空），供 PASM 校验。 */
public record ChainHop(
        String fromOwner, String fromName,
        String toOwner, String toName,
        HopKind kind, String field, String reason, String desc) {}
