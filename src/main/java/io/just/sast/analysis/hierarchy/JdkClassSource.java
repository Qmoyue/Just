package io.just.sast.analysis.hierarchy;

import io.just.sast.model.ClassInfo;

/** JDK 类来源（由 frontend 层实现，避免分析层依赖 ASM）。 */
public interface JdkClassSource {

    /** 按内部名加载 JDK 类；不可用返回 null。 */
    ClassInfo load(String internalName);
}
