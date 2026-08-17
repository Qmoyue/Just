package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Node;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 字段写入点索引：(ownerClass, fieldName) → PUTFIELD/PUTSTATIC 写入点。 */
public final class FieldWriterIndex {

    /** 字段写入点。 */
    public record Writer(String ownerClass, String methodOwner, String methodName, String methodDesc,
                         int insnOffset) {}

    private final Map<String, List<Writer>> writers = new HashMap<>();

    public void add(String fieldOwner, String fieldName, String ownerClass,
                    String methodOwner, String methodName, String methodDesc,
                    int insnOffset, boolean isStatic) {
        writers.computeIfAbsent(key(fieldOwner, fieldName), k -> new ArrayList<>(1))
                .add(new Writer(ownerClass, methodOwner, methodName, methodDesc, insnOffset));
    }

    public List<Writer> writersOf(String fieldOwner, String fieldName) {
        List<Writer> list = writers.get(key(fieldOwner, fieldName));
        return list != null ? list : List.of();
    }

    public int fieldCount() {
        return writers.size();
    }

    private static String key(String owner, String name) {
        return owner + "#" + name;
    }
}
