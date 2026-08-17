package io.just.sast.analysis.taint;

/** 值来源（正向抽象解释的产物，反向污点的输入）。 */
public sealed interface ValueOrigin
        permits ValueOrigin.Param, ValueOrigin.Insn, ValueOrigin.CallResult,
                ValueOrigin.FieldRead, ValueOrigin.Constant, ValueOrigin.Unknown {

    /** 方法参数/局部槽位（槽位 = 参数索引，含 this=0）。 */
    record Param(int slot) implements ValueOrigin {}

    /** 指令产物（NEW/数组读/算术/转换等）。 */
    record Insn(int offset) implements ValueOrigin {}

    /** 调用返回值。 */
    record CallResult(long callNodeId) implements ValueOrigin {}

    /** 字段读取（owner=声明类，isStatic=GETSTATIC，receiver=规范化后的接收者来源）。 */
    record FieldRead(String owner, String field, boolean isStatic, ValueOrigin receiver)
            implements ValueOrigin {}

    /** 常量（回溯死胡同）。 */
    record Constant(Object value) implements ValueOrigin {}

    /** 不可解析。 */
    record Unknown() implements ValueOrigin {}
}
