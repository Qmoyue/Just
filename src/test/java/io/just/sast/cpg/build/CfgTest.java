package io.just.sast.cpg.build;

import io.just.sast.model.InsnFact;
import io.just.sast.model.MethodInfo;
import io.just.sast.model.Op;
import io.just.sast.model.TryCatchFact;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CFG 契约：条件/无条件跳转、返回无后继、异常边。
 * 指令流：
 * 0 ILOAD 1 | 1 IFEQ→4 | 2 GOTO→6 | 3 IRETURN | 4 ICONST_1 | 5 IRETURN | 6 ICONST_0 | 7 IRETURN
 * try-catch: [0,3) → 6
 */
class CfgTest {

    private MethodInfo method() {
        List<InsnFact> insns = List.of(
                new InsnFact(0, Op.ILOAD, List.of(1)),
                new InsnFact(1, Op.IFEQ, List.of(4)),
                new InsnFact(2, Op.GOTO, List.of(6)),
                new InsnFact(3, Op.IRETURN, List.of()),
                new InsnFact(4, Op.ICONST_1, List.of()),
                new InsnFact(5, Op.IRETURN, List.of()),
                new InsnFact(6, Op.ICONST_0, List.of()),
                new InsnFact(7, Op.IRETURN, List.of()));
        return new MethodInfo("t/C", "m", "()V", 0, insns,
                List.of(new TryCatchFact(0, 3, 6, "java/lang/Exception")), false);
    }

    @Test
    void computesSuccessors() {
        Map<Integer, List<CfgEdge>> cfg = Cfg.compute(method());

        // 偏移 0：SEQ 到下一指令 + 异常边（位于 try-catch [0,3) 内）
        assertEquals(2, cfg.get(0).size());
        assertTrue(cfg.get(0).stream().anyMatch(e -> e.targetOffset() == 1 && e.label() == CfgLabel.SEQ));

        // 条件跳转：FALSE 到下一指令，TRUE 到目标；另加异常边
        List<CfgEdge> at1 = cfg.get(1);
        assertTrue(at1.stream().anyMatch(e -> e.targetOffset() == 2 && e.label() == CfgLabel.FALSE));
        assertTrue(at1.stream().anyMatch(e -> e.targetOffset() == 4 && e.label() == CfgLabel.JUMP));
        assertTrue(at1.stream().anyMatch(e -> e.targetOffset() == 6 && e.label() == CfgLabel.EXCEPTION));

        assertTrue(cfg.get(2).stream().anyMatch(e -> e.targetOffset() == 6 && e.label() == CfgLabel.JUMP));

        // 返回指令无后继
        assertEquals(0, cfg.getOrDefault(3, List.of()).size());
        assertEquals(0, cfg.getOrDefault(5, List.of()).size());
        assertEquals(0, cfg.getOrDefault(7, List.of()).size());

        // 异常边覆盖 [0,3)：0、1、2 均有 handler 边，3 无
        assertTrue(cfg.getOrDefault(0, List.of()).stream().anyMatch(e -> e.targetOffset() == 6));
        assertTrue(cfg.getOrDefault(2, List.of()).stream().anyMatch(e -> e.targetOffset() == 6));
        assertTrue(cfg.getOrDefault(3, List.of()).stream().noneMatch(e -> e.label() == CfgLabel.EXCEPTION));
    }
}
