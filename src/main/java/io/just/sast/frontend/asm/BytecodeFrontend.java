package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import io.just.sast.util.JustLogger;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 字节码前端：目标 JAR/目录 → 解析为自研 model。
 * 单类解析失败不中断全扫，记录诊断。
 */
public final class BytecodeFrontend {

    private final JarReader jarReader = new JarReader();
    private final ClassFileReader classFileReader = new ClassFileReader();

    public LoadResult load(List<Path> targets) {
        List<ParseDiagnostic> diagnostics = new ArrayList<>();
        Map<String, ClassInfo> classes = new LinkedHashMap<>();
        int files = 0;
        for (Path target : targets) {
            try {
                for (ClassBytes cb : jarReader.read(target)) {
                    files++;
                    try {
                        ClassInfo info = classFileReader.read(cb.bytes());
                        classes.putIfAbsent(info.internalName(), info);
                    } catch (Exception e) {
                        diagnostics.add(new ParseDiagnostic(cb.origin(), e.getClass().getSimpleName() + ": " + e.getMessage()));
                    }
                }
            } catch (IOException e) {
                diagnostics.add(new ParseDiagnostic(target.toString(), e.getMessage()));
                JustLogger.error("读取输入失败 {}: {}", target, e.getMessage());
            }
        }
        return new LoadResult(classes, List.copyOf(diagnostics), files);
    }
}
