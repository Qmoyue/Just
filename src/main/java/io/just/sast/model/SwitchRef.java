package io.just.sast.model;

import java.util.List;

/** switch 指令操作数。 */
public record SwitchRef(List<SwitchCase> cases, int defaultOffset) {}
