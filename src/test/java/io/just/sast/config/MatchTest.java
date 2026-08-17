package io.just.sast.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 规则匹配契约：精确 + 锚定正则。 */
class MatchTest {

    @Test
    void exactMatch() {
        Match m = Match.of("java/lang/Runtime");
        assertTrue(m.matches("java/lang/Runtime"));
        assertFalse(m.matches("java/lang/RuntimeX"));
        assertFalse(m.matches(null));
    }

    @Test
    void anchoredRegex() {
        Match m = Match.of("~lookup|list|bind");
        assertTrue(m.matches("lookup"));
        assertTrue(m.matches("bind"));
        assertFalse(m.matches("xlookupx"), "正则必须锚定，中缀不应命中");
        assertFalse(m.matches("lookup2"));
    }
}
