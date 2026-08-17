package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;

import java.util.List;
import java.util.Map;

/** 前端加载结果。 */
public record LoadResult(Map<String, ClassInfo> classes, List<ParseDiagnostic> diagnostics, int filesScanned) {

    public int classCount() {
        return classes.size();
    }

    public int diagnosticCount() {
        return diagnostics.size();
    }
}
