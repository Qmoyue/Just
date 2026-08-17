package io.just.sast.analysis.hierarchy;

import io.just.sast.frontend.asm.JrtClassSource;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 类层次契约：JDK 懒加载、subtype 判定、方法解析（沿父类）。 */
class ClassHierarchyTest {

    private final ClassHierarchy hierarchy = new ClassHierarchy(Map.of(), new JrtClassSource());

    @Test
    void lazyLoadsJdkClasses() {
        assertTrue(hierarchy.classInfo("java/util/HashMap") != null, "HashMap 应从 jrtfs 懒加载");
        assertFalse(hierarchy.classInfo("java/util/NoSuchClass99") != null);
    }

    @Test
    void subtypeAndSerializable() {
        assertTrue(hierarchy.isSubtypeOf("java/lang/String", "java/lang/Object"));
        assertTrue(hierarchy.isSubtypeOf("java/util/HashMap", "java/util/Map"));
        assertTrue(hierarchy.isSerializable("java/util/HashMap"), "HashMap 实现 Serializable");
        assertTrue(hierarchy.isSerializable("java/lang/String"));
        assertFalse(hierarchy.isSerializable("java/lang/Object"));
    }

    @Test
    void resolvesInheritedMethod() {
        // HashMap 未声明 hashCode，应解析到 AbstractMap
        assertEquals("java/util/AbstractMap",
                hierarchy.resolveMethod("java/util/HashMap", "hashCode", "()I"));
        // 未声明的名字返回 null
        assertEquals(null,
                hierarchy.resolveMethod("java/util/HashMap", "noSuchMethod99", "()V"));
    }
}
