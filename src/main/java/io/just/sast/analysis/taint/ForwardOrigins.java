package io.just.sast.analysis.taint;

import io.just.sast.cpg.build.Cfg;
import io.just.sast.cpg.build.CfgEdge;
import io.just.sast.model.Descriptor;
import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.MethodRef;
import io.just.sast.model.Op;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 方法内正向抽象解释：计算每条指令执行前的栈/局部变量值来源。
 * 惰性计算 + 缓存；栈槽合并 = 来源集合并（收敛）。
 */
public final class ForwardOrigins {

    /** 某点的值来源状态。 */
    public record State(List<Set<ValueOrigin>> stack, List<Set<ValueOrigin>> locals) {

        public State merge(State other) {
            List<Set<ValueOrigin>> mergedStack = new ArrayList<>();
            int depth = Math.min(stack.size(), other.stack.size());
            for (int i = 0; i < depth; i++) {
                mergedStack.add(union(stack.get(i), other.stack.get(i)));
            }
            List<Set<ValueOrigin>> mergedLocals = new ArrayList<>(locals.size());
            for (int i = 0; i < locals.size(); i++) {
                mergedLocals.add(union(locals.get(i), other.locals.get(i)));
            }
            return new State(mergedStack, mergedLocals);
        }

        private static Set<ValueOrigin> union(Set<ValueOrigin> a, Set<ValueOrigin> b) {
            if (a.isEmpty()) {
                return b;
            }
            if (b.isEmpty() || a.equals(b)) {
                return a;
            }
            LinkedHashSet<ValueOrigin> merged = new LinkedHashSet<>(a);
            merged.addAll(b);
            return merged;
        }
    }

    /** 方法级结果。 */
    public record Result(Map<Integer, State> stateBefore,
                         Map<ValueOrigin, Set<ValueOrigin>> arrayElements) {}

    private static final Set<ValueOrigin> UNKNOWN = Set.of(new ValueOrigin.Unknown());

    private final Map<String, Long> callIdByKey;
    private final Map<String, Result> cache = new HashMap<>();

    public ForwardOrigins(Map<String, Long> callIdByKey) {
        this.callIdByKey = callIdByKey;
    }

    public Result compute(MethodInfo method) {
        String key = CfgKey.of(method);
        Result cached = cache.get(key);
        if (cached != null) {
            return cached;
        }
        Result result = analyze(method);
        cache.put(key, result);
        return result;
    }

    private Result analyze(MethodInfo method) {
        Map<Integer, List<CfgEdge>> cfg = Cfg.compute(method);
        int maxLocals = maxLocals(method);
        List<Set<ValueOrigin>> initLocals = new ArrayList<>(maxLocals);
        for (int i = 0; i < maxLocals; i++) {
            initLocals.add(new LinkedHashSet<>());
        }
        // 参数槽位初始化
        List<Integer> argSlots = Descriptor.argSlots(method.descriptor(), method.isStatic());
        int slot = 0;
        for (int argIdx = 0; argIdx < argSlots.size(); argIdx++) {
            initLocals.get(slot).add(new ValueOrigin.Param(slot));
            slot += argSlots.get(argIdx);
        }

        Map<Integer, State> before = new HashMap<>();
        Map<ValueOrigin, Set<ValueOrigin>> arrayElements = new HashMap<>();
        Deque<Integer> worklist = new ArrayDeque<>();
        State entry = new State(new ArrayList<>(), initLocals);
        before.put(0, entry);
        worklist.add(0);
        while (!worklist.isEmpty()) {
            int offset = worklist.poll();
            State state = before.get(offset);
            if (state == null) {
                continue;
            }
            State out = transfer(method, method.insnAt(offset), state, arrayElements);
            for (CfgEdge edge : cfg.getOrDefault(offset, List.of())) {
                State old = before.get(edge.targetOffset());
                State merged = old == null ? out : old.merge(out);
                if (!merged.equals(old)) {
                    before.put(edge.targetOffset(), merged);
                    worklist.add(edge.targetOffset());
                }
            }
        }
        return new Result(before, arrayElements);
    }

    private int maxLocals(MethodInfo method) {
        int max = 0;
        for (InsnFact insn : method.instructions()) {
            Op op = insn.op();
            if (op.isLoad() || op.isStore() || op == Op.IINC || op == Op.RET) {
                max = Math.max(max, insn.varIndex() + 1);
            }
        }
        return Math.max(max, Descriptor.argSlots(method.descriptor(), method.isStatic())
                .stream().mapToInt(Integer::intValue).sum());
    }

    private State transfer(MethodInfo method, InsnFact insn, State in, Map<ValueOrigin, Set<ValueOrigin>> arrayElements) {
        List<Set<ValueOrigin>> stack = new ArrayList<>(in.stack());
        List<Set<ValueOrigin>> locals = new ArrayList<>(in.locals());
        Op op = insn.op();
        switch (op) {
            case NOP, GOTO, JSR, RET, TABLESWITCH, LOOKUPSWITCH -> {
                // 无栈变化
            }
            case ACONST_NULL, ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5,
                    LCONST_0, LCONST_1, FCONST_0, FCONST_1, FCONST_2, DCONST_0, DCONST_1, BIPUSH, SIPUSH ->
                    push(stack, Set.of(new ValueOrigin.Constant(op.name())));
            case LDC -> push(stack, Set.of(new ValueOrigin.Constant(insn.constant())));
            case ILOAD, LLOAD, FLOAD, DLOAD, ALOAD -> push(stack, local(locals, insn.varIndex()));
            case ISTORE, LSTORE, FSTORE, DSTORE, ASTORE -> locals.set(insn.varIndex(), pop(stack));
            case IINC -> locals.set(insn.varIndex(),
                    union(local(locals, insn.varIndex()), Set.of(new ValueOrigin.Insn(insn.offset()))));
            case GETSTATIC, GETFIELD -> {
                if (op == Op.GETFIELD) {
                    ValueOrigin receiver = canonicalReceiver(pop(stack));
                    push(stack, Set.of(new ValueOrigin.FieldRead(
                            insn.fieldRef().owner(), insn.fieldRef().name(), false, receiver)));
                } else {
                    push(stack, Set.of(new ValueOrigin.FieldRead(
                            insn.fieldRef().owner(), insn.fieldRef().name(), true,
                            new ValueOrigin.Unknown())));
                }
            }
            case PUTSTATIC -> pop(stack);
            case PUTFIELD -> {
                pop(stack);
                pop(stack);
            }
            case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE, INVOKEDYNAMIC -> {
                int argc = callArgCount(insn, op);
                for (int i = 0; i < argc; i++) {
                    pop(stack);
                }
                Long callId = callIdByKey.get(CfgKey.of(method) + "@" + insn.offset());
                push(stack, Set.of(new ValueOrigin.CallResult(callId == null ? -1 : callId)));
            }
            case NEW, NEWARRAY, ANEWARRAY, MULTIANEWARRAY -> {
                int pops = op == Op.NEW ? 0 : op == Op.MULTIANEWARRAY ? (Integer) insn.operands().get(1) : 1;
                for (int i = 0; i < pops; i++) {
                    pop(stack);
                }
                push(stack, Set.of(new ValueOrigin.Insn(insn.offset())));
            }
            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                pop(stack);
                pop(stack);
                push(stack, Set.of(new ValueOrigin.Insn(insn.offset())));
            }
            case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE, SASTORE -> {
                Set<ValueOrigin> value = pop(stack);
                pop(stack); // index
                Set<ValueOrigin> array = pop(stack);
                for (ValueOrigin arr : array) {
                    arrayElements.computeIfAbsent(arr, k -> new LinkedHashSet<>()).addAll(value);
                }
            }
            case ARRAYLENGTH, CHECKCAST, INSTANCEOF -> {
                pop(stack);
                push(stack, Set.of(new ValueOrigin.Insn(insn.offset())));
            }
            case MONITORENTER, MONITOREXIT, ATHROW -> pop(stack);
            case IRETURN, LRETURN, FRETURN, DRETURN, ARETURN -> pop(stack);
            case RETURN -> {
            }
            case POP -> pop(stack);
            case POP2 -> {
                pop(stack);
                pop(stack);
            }
            case DUP -> {
                Set<ValueOrigin> v = top(stack);
                push(stack, v);
            }
            case DUP_X1 -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                push(stack, v1);
                push(stack, v2);
                push(stack, v1);
            }
            case DUP_X2 -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                Set<ValueOrigin> v3 = pop(stack);
                push(stack, v1);
                push(stack, v3);
                push(stack, v2);
                push(stack, v1);
            }
            case DUP2 -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                push(stack, v2);
                push(stack, v1);
                push(stack, v2);
                push(stack, v1);
            }
            case DUP2_X1 -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                Set<ValueOrigin> v3 = pop(stack);
                push(stack, v2);
                push(stack, v1);
                push(stack, v3);
                push(stack, v2);
                push(stack, v1);
            }
            case DUP2_X2 -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                Set<ValueOrigin> v3 = pop(stack);
                Set<ValueOrigin> v4 = pop(stack);
                push(stack, v2);
                push(stack, v1);
                push(stack, v4);
                push(stack, v3);
                push(stack, v2);
                push(stack, v1);
            }
            case SWAP -> {
                Set<ValueOrigin> v1 = pop(stack);
                Set<ValueOrigin> v2 = pop(stack);
                push(stack, v1);
                push(stack, v2);
            }
            case IADD, LADD, FADD, DADD, ISUB, LSUB, FSUB, DSUB,
                    IMUL, LMUL, FMUL, DMUL, IDIV, LDIV, FDIV, DDIV,
                    IREM, LREM, FREM, DREM, ISHL, LSHL, ISHR, LSHR, IUSHR, LUSHR,
                    IAND, LAND, IOR, LOR, IXOR, LXOR, LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> {
                pop(stack);
                pop(stack);
                push(stack, Set.of(new ValueOrigin.Insn(insn.offset())));
            }
            case INEG, LNEG, FNEG, DNEG, I2L, I2F, I2D, L2I, L2F, L2D,
                    F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S -> {
                pop(stack);
                push(stack, Set.of(new ValueOrigin.Insn(insn.offset())));
            }
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE, IFNULL, IFNONNULL -> pop(stack);
            case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                    IF_ACMPEQ, IF_ACMPNE -> {
                pop(stack);
                pop(stack);
            }
            default -> {
                // 未知/未覆盖指令：不做栈变化，保持保守（来源可能缺失，但不会错）
            }
        }
        return new State(stack, locals);
    }

    /** 规范化 receiver：优先 Param(0)（this），否则取首个来源，保证 memo 键稳定。 */
    private static ValueOrigin canonicalReceiver(Set<ValueOrigin> set) {
        for (ValueOrigin origin : set) {
            if (origin instanceof ValueOrigin.Param p && p.slot() == 0) {
                return origin;
            }
        }
        return set.isEmpty() ? new ValueOrigin.Unknown() : set.iterator().next();
    }

    private int callArgCount(InsnFact insn, Op op) {
        if (op == Op.INVOKEDYNAMIC) {
            return Descriptor.paramCount(insn.operands().isEmpty() ? "()V"
                    : ((io.just.sast.model.InvokeDynamicRef) insn.operands().get(0)).descriptor());
        }
        MethodRef ref = insn.methodRef();
        return Descriptor.paramCount(ref.descriptor()) + (op == Op.INVOKESTATIC ? 0 : 1);
    }

    private static Set<ValueOrigin> local(List<Set<ValueOrigin>> locals, int var) {
        return var < locals.size() && !locals.get(var).isEmpty() ? locals.get(var) : UNKNOWN;
    }

    private static Set<ValueOrigin> top(List<Set<ValueOrigin>> stack) {
        return stack.isEmpty() ? UNKNOWN : stack.get(stack.size() - 1);
    }

    private static Set<ValueOrigin> pop(List<Set<ValueOrigin>> stack) {
        return stack.isEmpty() ? UNKNOWN : stack.remove(stack.size() - 1);
    }

    private static void push(List<Set<ValueOrigin>> stack, Set<ValueOrigin> origin) {
        stack.add(origin);
    }

    private static Set<ValueOrigin> union(Set<ValueOrigin> a, Set<ValueOrigin> b) {
        if (a.isEmpty()) {
            return b;
        }
        if (b.isEmpty() || a.equals(b)) {
            return a;
        }
        LinkedHashSet<ValueOrigin> merged = new LinkedHashSet<>(a);
        merged.addAll(b);
        return merged;
    }

    /** 方法缓存键。 */
    public static final class CfgKey {
        private CfgKey() {}

        public static String of(MethodInfo m) {
            return m.owner() + "#" + m.name() + m.descriptor();
        }
    }
}
