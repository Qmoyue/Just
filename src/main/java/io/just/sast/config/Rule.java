package io.just.sast.config;

import java.util.List;

/** 规则模型：sink（起点）与 magic-entry（终点）。 */
public sealed interface Rule {

    String id();

    /** 调用匹配：owner/name/descriptor，descriptor 为 null 表示不限制。 */
    record CallMatcher(Match owner, Match name, Match descriptor) {

        public boolean matches(String owner, String name, String desc) {
            return this.owner.matches(owner) && this.name.matches(name)
                    && (descriptor == null || descriptor.matches(desc));
        }
    }

    /** 方法匹配（用于 magic-entry）。 */
    record MethodMatcher(Match name, Match descriptor) {

        public boolean matches(String name, String desc) {
            return this.name.matches(name) && (descriptor == null || descriptor.matches(desc));
        }
    }

    /** 污点位置：第 index 个参数，或 receiver。 */
    sealed interface TaintedPos {
        record Arg(int index) implements TaintedPos {}
        enum Receiver implements TaintedPos { INSTANCE }
    }

    /** sink 规则：调用匹配 + 需要污点的位置。 */
    record SinkRule(String id, String category, String severity, CallMatcher call, List<TaintedPos> tainted)
            implements Rule {}

    /**
     * magic-entry 规则：方法匹配 + 所在类需实现 implementsType（如 java/io/Serializable）。
     * implementsType 为 null 表示不限制。
     */
    record MagicEntryRule(String id, String entryKind, MethodMatcher method, String implementsType)
            implements Rule {}
}
