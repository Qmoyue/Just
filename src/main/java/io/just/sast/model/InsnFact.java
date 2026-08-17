package io.just.sast.model;

import java.util.List;

/** 单条指令事实。offset 与 MethodInfo.instructions 的列表下标一致。 */
public record InsnFact(int offset, Op op, List<Object> operands) {

    /** var 类指令（xLOAD/xSTORE/RET）的局部变量槽位。 */
    public int varIndex() {
        return (Integer) operands.get(0);
    }

    /** 跳转类指令（IF 系/GOTO/JSR）的目标偏移。 */
    public int jumpTarget() {
        return (Integer) operands.get(0);
    }

    /** 方法调用类指令的方法引用。 */
    public MethodRef methodRef() {
        return (MethodRef) operands.get(0);
    }

    /** 字段类指令的字段引用。 */
    public FieldRef fieldRef() {
        return (FieldRef) operands.get(0);
    }

    /** 类型类指令（NEW/CHECKCAST/INSTANCEOF/ANEWARRAY）的类型。 */
    public TypeRef typeRef() {
        return (TypeRef) operands.get(0);
    }

    /** 常量类指令（LDC）的常量值（String/Integer/Long/Float/Double/TypeRef/HandleRef）。 */
    public Object constant() {
        return operands.get(0);
    }
}
