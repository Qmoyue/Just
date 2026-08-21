package io.just.sast.cli;

import io.just.sast.blackboard.KnowledgeSource;
import io.just.sast.util.JustLogger;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

/** 知识源装配：ServiceLoader 单轨注册（内置与插件统一经 META-INF/services 声明）。 */
public final class KnowledgeSources {

    private KnowledgeSources() {}

    public static List<KnowledgeSource> discover() {
        List<KnowledgeSource> sources = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (KnowledgeSource ks : ServiceLoader.load(KnowledgeSource.class)) {
            if (!ids.add(ks.id())) {
                JustLogger.warn("知识源 id 重复，已忽略: {}", ks.id());
            } else {
                sources.add(ks);
            }
        }
        return sources;
    }
}
