package io.just.sast.cpg.graph;

/** CPG 边类型。 */
public enum EdgeType {
    /** 静态/特殊调用：唯一目标 */
    INVOKES,
    /** 虚调用/接口调用：CHA 候选（多边） */
    DISPATCHES,
    /** 反射调用解析边 */
    REFLECTIVE,
    /** 动态代理：接口调用 → InvocationHandler.invoke */
    PROXY,
    /** invokedynamic → lambda 实现方法 */
    LAMBDA,
    /** 污点路径上的方法迁移（KS2 产物，label = hop 类型） */
    TAINT
}
