package io.just.sast.cpg.graph;

/** CPG 边类型（反射/代理不建边，由前向精扫按需展开）。 */
public enum EdgeType {
    /** 静态/特殊调用：唯一目标 */
    INVOKES,
    /** 虚调用/接口调用：CHA 候选（多边） */
    DISPATCHES,
    /** invokedynamic → lambda 实现方法 */
    LAMBDA
}
