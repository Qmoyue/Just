package io.just.sast.model;

/** 字段引用。 */
public record FieldRef(String owner, String name, String descriptor) {}
