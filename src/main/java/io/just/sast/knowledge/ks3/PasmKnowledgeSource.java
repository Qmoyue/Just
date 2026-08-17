package io.just.sast.knowledge.ks3;

import io.just.sast.blackboard.Blackboard;
import io.just.sast.blackboard.Chain;
import io.just.sast.blackboard.ChainHop;
import io.just.sast.blackboard.Event;
import io.just.sast.blackboard.EventType;
import io.just.sast.blackboard.HopKind;
import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * KS3 PASM 链可行性验证（校准 KS2/KS4 产出的链）。
 * 局部可证校验（每跳独立可证，不做全局类型游走——链跳混合污点值与承载对象两类流，
 * 全局游走不健全）：
 * 1. FIELD_FLOW(f)：字段 f 必须声明于 fromOwner 或其父类
 * 2. 调用跳：目标方法必须在 toOwner 上可解析（声明或继承）
 * 不可解析的类/方法保守通过（只拒绝可证明不可能的链）。
 */
public final class PasmKnowledgeSource implements KnowledgeSource {

    @Override
    public String id() {
        return "pasm";
    }

    @Override
    public Set<EventType> interests() {
        return Set.of(EventType.SCAN_START);
    }

    @Override
    public void init(Blackboard blackboard) {
        // 校验无需额外初始化
    }

    @Override
    public void onEvent(Blackboard bb, Event event) {
        if (event.type() != EventType.SCAN_START) {
            return;
        }
        int rejected = 0;
        for (Chain chain : bb.chains()) {
            String reason = validate(bb, chain);
            if (reason != null) {
                bb.calibrateChain(chain.key(), reason);
                rejected++;
            }
        }
        JustLogger.info("KS3 PASM：校验 {} 条链，拒绝 {} 条", bb.chains().size(), rejected);
    }

    /** 返回拒绝理由；null 表示通过（含无法判定的保守情况）。 */
    private String validate(Blackboard bb, Chain chain) {
        List<ChainHop> hops = new ArrayList<>(chain.hops());
        Collections.reverse(hops); // entry→sink
        for (ChainHop hop : hops) {
            if (hop.kind() == HopKind.ENTRY || hop.kind() == HopKind.LAMBDA) {
                continue;
            }
            if (hop.kind() == HopKind.FIELD_FLOW) {
                String declaring = bb.hierarchy().resolveField(hop.fromOwner(), hop.field());
                if (declaring == null) {
                    return "field-not-declared:" + hop.fromOwner() + "." + hop.field();
                }
                continue;
            }
            // 调用跳：目标方法须在 toOwner 上可解析（声明或继承）
            if (hop.desc() == null || hop.desc().isEmpty()) {
                continue; // 无描述符无法校验，保守通过
            }
            if (bb.hierarchy().classInfo(hop.toOwner()) == null) {
                continue; // 类不可解析，保守通过
            }
            String resolved = bb.hierarchy().resolveMethod(hop.toOwner(), hop.toName(), hop.desc());
            if (resolved == null) {
                return "method-not-declared:" + hop.toOwner() + "." + hop.toName() + hop.desc();
            }
        }
        return null;
    }
}
