package io.just.sast.cli;

import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.knowledge.ks1.PatternKnowledgeSource;
import io.just.sast.knowledge.ks2.BackwardTaintAnalysis;
import io.just.sast.knowledge.ks3.PasmKnowledgeSource;
import io.just.sast.knowledge.ks4.ForwardTaintKnowledgeSource;
import io.just.sast.knowledge.ks5.AllocationSensitiveTaintKnowledgeSource;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/** 知识源装配：内置 KS1-KS5 + ServiceLoader 发现的插件（按 id 去重，内置在前）。 */
public final class KnowledgeSources {

    private KnowledgeSources() {}

    public static List<KnowledgeSource> discover() {
        List<KnowledgeSource> sources = new ArrayList<>();
        sources.add(new PatternKnowledgeSource());
        sources.add(new BackwardTaintAnalysis());
        sources.add(new ForwardTaintKnowledgeSource());
        sources.add(new AllocationSensitiveTaintKnowledgeSource());
        sources.add(new PasmKnowledgeSource()); // 最后运行：校验全部链
        for (KnowledgeSource plugin : ServiceLoader.load(KnowledgeSource.class)) {
            if (sources.stream().noneMatch(s -> s.id().equals(plugin.id()))) {
                sources.add(plugin);
            }
        }
        return sources;
    }
}
