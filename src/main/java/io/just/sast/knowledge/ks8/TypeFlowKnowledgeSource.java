package io.just.sast.knowledge.ks8;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.blackboard.Phase;
import io.just.sast.model.ClassInfo;
import io.just.sast.model.Descriptor;
import java.lang.reflect.Modifier;
import io.just.sast.util.JustLogger;

import java.util.Set;

/**
 * KS8 类型流校准（CALIBRATION 阶段）：逐跳值类型相容性校验（借鉴 FLASH/JDD 精确化，保守实现）。
 * 链跳按 sink-first 存储：hop i 的形参接收的值来源是 hop i+1 的产出
 * （参数链：上一跳形参类型 / 字段声明类型 / 入口类）。双方均为可解析类类型且不满足子类型关系
 * → 链可证明不可能，拒绝。Object 形参/数组/原语/任一方不可解析 → 保守通过。
 */
public final class TypeFlowKnowledgeSource implements KnowledgeSource {

    private Blackboard bb;

    @Override
    public String id() {
        return "typeflow";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_COMPLETE);
    }

    @Override
    public Phase phase() {
        return Phase.CALIBRATION;
    }

    @Override
    public void init(Blackboard blackboard) {
        this.bb = blackboard;
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_COMPLETE) {
            return;
        }
        int rejected = 0;
        for (Chain chain : bb.chains()) {
            String reason = rejectReason(chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                rejected++;
            }
        }
        JustLogger.info("KS8 类型流：校验 {} 条链，拒绝 {} 条", bb.chains().size(), rejected);
    }

    /** 返回拒绝理由；null 表示通过（含无法判定的保守情况）。 */
    String rejectReason(Chain chain) {
        var hops = chain.hops();
        for (int i = 0; i + 1 < hops.size(); i++) {
            ChainHop hop = hops.get(i);
            if (hop.argOrdinal() == null || hop.desc() == null || hop.desc().isEmpty()) {
                continue;
            }
            String param = Descriptor.paramType(hop.desc(), hop.argOrdinal());
            if (param == null || !param.startsWith("L")) {
                continue; // 原语/数组形参不承载对象污点链，保守通过
            }
            String source = sourceType(hops.get(i + 1), chain);
            if (source == null || !source.startsWith("L")) {
                continue;
            }
            String sourceClass = source.substring(1, source.length() - 1);
            String paramClass = param.substring(1, param.length() - 1);
            var sourceInfo = bb.hierarchy().classInfo(sourceClass);
            if (sourceInfo == null || bb.hierarchy().classInfo(paramClass) == null) {
                continue; // 任一方不可解析：保守通过
            }
            // 声明类型只是运行时值的上界：仅当来源类型为 final 类（无子类 ⇒ 精确）时
            // "非子类型"才可证明不可行（如 Object 声明流入 Map 形参，运行时可为 HashMap——不可拒）
            if (!Modifier.isFinal(sourceInfo.access())) {
                continue;
            }
            if (!bb.hierarchy().isSubtypeOf(sourceClass, paramClass)) {
                return "typeflow:" + sourceClass + "-!->" + paramClass;
            }
        }
        return null;
    }

    /** 值来源类型描述符：入口跳 → 入口类；字段跳 → 字段声明类型；调用跳 → 其形参类型。 */
    private String sourceType(ChainHop hop, Chain chain) {
        if (hop.kind() == HopKind.ENTRY) {
            return "L" + chain.entryClass() + ";";
        }
        if (hop.kind() == HopKind.FIELD_FLOW && hop.field() != null) {
            String declaring = bb.hierarchy().resolveField(hop.toOwner(), hop.field());
            if (declaring == null) {
                return null;
            }
            ClassInfo cls = bb.hierarchy().classInfo(declaring);
            if (cls == null || cls.field(hop.field()) == null) {
                return null;
            }
            return cls.field(hop.field()).descriptor();
        }
        if (hop.argOrdinal() != null && hop.desc() != null && !hop.desc().isEmpty()) {
            return Descriptor.paramType(hop.desc(), hop.argOrdinal());
        }
        return null;
    }
}
