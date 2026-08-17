package io.just.sast.config;

import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 内置规则契约：sink 四类、magic entry 十类、Method.invoke 规则存在。 */
class YamlRuleLoaderTest {

    @Test
    void loadsDefaultRules() throws Exception {
        RuleSet rules;
        try (InputStream in = getClass().getResourceAsStream("/rules/default-rules.yaml")) {
            rules = new YamlRuleLoader().load(in);
        }
        assertEquals(17, rules.sinks().size());
        assertEquals(11, rules.magicEntries().size());

        Rule.SinkRule invoke = rules.sinks().stream()
                .filter(s -> s.id().equals("JUST-SINK-REFLECTIVE-INVOKE"))
                .findFirst().orElseThrow();
        assertEquals("REFLECTIVE_INVOKE", invoke.category());
        assertTrue(invoke.tainted().stream().anyMatch(t -> t instanceof Rule.TaintedPos.Arg a && a.index() == 1),
                "Method.invoke 第 1 个参数（args 数组）应标记为污点位置");

        assertTrue(rules.magicEntries().stream().anyMatch(e ->
                e.entryKind().equals("readObject") && e.implementsType().equals("java/io/Serializable")));
    }
}
