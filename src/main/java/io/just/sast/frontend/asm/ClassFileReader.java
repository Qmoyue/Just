package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

/** 单个 class 字节 → ClassInfo。majorVersion 提取自 class 文件头（前 8 字节偏移 6-7）。 */
public final class ClassFileReader {

    private final FactsExtractor extractor = new FactsExtractor();
    /** 最近一次 read 的 class 文件 major version（0=尚未读取/无效）。 */
    private int lastMajorVersion;

    public ClassInfo read(byte[] bytes) {
        lastMajorVersion = extractMajorVersion(bytes);
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
        return extractor.extract(node);
    }

    public int majorVersion() {
        return lastMajorVersion;
    }

    /** class 文件头：CA FE BA BE | minor(u2) | major(u2)，major 在偏移 6-7。 */
    private static int extractMajorVersion(byte[] bytes) {
        if (bytes.length < 8) {
            return 0;
        }
        return ((bytes[6] & 0xFF) << 8) | (bytes[7] & 0xFF);
    }
}
