package io.just.sast.model;

import java.lang.reflect.Modifier;

/** 字段事实。 */
public record FieldInfo(String owner, String name, String descriptor, int access) {

    public boolean isStatic() {
        return Modifier.isStatic(access);
    }
}
