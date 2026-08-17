package io.just.sast.model;

/** 方法引用（内部名 + 名称 + JVM 描述符）。 */
public record MethodRef(String owner, String name, String descriptor) {}
