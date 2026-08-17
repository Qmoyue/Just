package io.just.sast.model;

/** MethodHandle 引用（invokedynamic bootstrap 参数等）。 */
public record HandleRef(int tag, String owner, String name, String descriptor) {}
