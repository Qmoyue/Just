package io.just.sast.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 描述符解析契约。 */
class DescriptorTest {

    @Test
    void countsParams() {
        assertEquals(0, Descriptor.paramCount("()V"));
        assertEquals(1, Descriptor.paramCount("(Ljava/lang/String;)V"));
        assertEquals(4, Descriptor.paramCount("(IJLjava/lang/String;[Ljava/lang/Object;)V"));
    }

    @Test
    void computesArgSlots() {
        // 实例方法：this + int + long + String + Object[]
        assertEquals(List.of(1, 1, 2, 1, 1),
                Descriptor.argSlots("(IJLjava/lang/String;[Ljava/lang/Object;)V", false));
        // 静态方法：无 this
        assertEquals(List.of(1, 2, 1, 1),
                Descriptor.argSlots("(IJLjava/lang/String;[Ljava/lang/Object;)V", true));
    }
}
