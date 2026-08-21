package io.just.sast.blackboard;

/**
 * 链上的一跳。desc 为目标方法描述符（entry/字段跳为空），供 PASM 校验；
 * argOrdinal 为被传播值在目标方法形参中的序数（0 基，receiver/未知为 null），供类型流校准。
 */
public record ChainHop(
        String fromOwner, String fromName,
        String toOwner, String toName,
        HopKind kind, String field, String reason, String desc,
        Integer argOrdinal) {}
