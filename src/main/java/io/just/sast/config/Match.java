package io.just.sast.config;

import java.util.regex.Pattern;

/** 匹配器：精确字符串，或以 "~" 前缀表示锚定正则。 */
public record Match(String pattern) {

    public Match {
        pattern = pattern.strip();
        // YAML 中 ~"a|b" 的引号会进入标量，剥掉以防备选被引号拆散（"a / b"）
        if (pattern.startsWith("~")) {
            String rest = pattern.substring(1).strip();
            if (rest.length() >= 2 && rest.startsWith("\"") && rest.endsWith("\"")) {
                pattern = "~" + rest.substring(1, rest.length() - 1);
            }
        }
    }

    public static Match of(String raw) {
        return new Match(raw);
    }

    /** 是否为正则匹配。 */
    public boolean isRegex() {
        return pattern.startsWith("~");
    }

    public boolean matches(String value) {
        if (value == null) {
            return false;
        }
        if (isRegex()) {
            return Pattern.compile("^(?:" + pattern.substring(1) + ")$").matcher(value).matches();
        }
        return pattern.equals(value);
    }

    @Override
    public String toString() {
        return pattern;
    }
}
