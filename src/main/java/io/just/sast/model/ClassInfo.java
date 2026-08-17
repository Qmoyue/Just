package io.just.sast.model;

import java.lang.reflect.Modifier;
import java.util.List;

/** 类事实。 */
public record ClassInfo(
        String internalName,
        String superName,
        List<String> interfaces,
        int access,
        List<MethodInfo> methods,
        List<FieldInfo> fields) {

    public boolean isInterface() {
        return Modifier.isInterface(access);
    }

    public MethodInfo method(String name, String descriptor) {
        for (MethodInfo m : methods) {
            if (m.name().equals(name) && m.descriptor().equals(descriptor)) {
                return m;
            }
        }
        return null;
    }
}
