package io.just.sast.frontend.asm;

import io.just.sast.model.ClassInfo;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

/** 单个 class 字节 → ClassInfo。 */
public final class ClassFileReader {

    private final FactsExtractor extractor = new FactsExtractor();

    public ClassInfo read(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES);
        return extractor.extract(node);
    }
}
