package io.just.sast.testutil;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.objectweb.asm.Opcodes.*;

/** 合成 fixture jar：ASM 动态生成字节码（不依赖 javac）。 */
public final class FixtureJars {

    private FixtureJars() {}

    /**
     * 五件套：
     * - fx/FieldGadget：Serializable，readObject 中 exec(this.cmd) → 应出链
     * - fx/SafeGadget：Serializable，readObject 中 exec("fixed") → 不应出链（常量不可控）
     * - fx/NonSerializableGadget：同上但未实现 Serializable → 不应出链（非入口）
     * - fx/ReceiverGadget：equals 读 ((ReceiverGadget)o).cmd（receiver 非 this）→ 不应出链
     * - fx/StaticGadget：readObject 读静态字段 exec → 不应出链（静态字段不可控）
     */
    public static Path buildGadgets(Path dir) throws IOException {
        Map<String, byte[]> classes = new HashMap<>();
        classes.put("fx/FieldGadget.class", gadget(true, true));
        classes.put("fx/SafeGadget.class", gadget(true, false));
        classes.put("fx/NonSerializableGadget.class", gadget(false, true));
        classes.put("fx/ReceiverGadget.class", receiverGadget());
        classes.put("fx/StaticGadget.class", staticGadget());
        return writeJar(dir.resolve("gadgets.jar"), classes);
    }

    private static byte[] receiverGadget() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_SUPER, "fx/ReceiverGadget", null, "java/lang/Object",
                new String[]{"java/io/Serializable"});
        cw.visitField(ACC_PUBLIC, "cmd", "Ljava/lang/String;", null, null).visitEnd();
        MethodVisitor init = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(ALOAD, 0);
        init.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor equals = cw.visitMethod(ACC_PUBLIC, "equals", "(Ljava/lang/Object;)Z", null, null);
        equals.visitCode();
        equals.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        equals.visitVarInsn(ALOAD, 1);
        equals.visitTypeInsn(CHECKCAST, "fx/ReceiverGadget");
        equals.visitFieldInsn(GETFIELD, "fx/ReceiverGadget", "cmd", "Ljava/lang/String;");
        equals.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        equals.visitInsn(POP);
        equals.visitInsn(ICONST_1);
        equals.visitInsn(IRETURN);
        equals.visitMaxs(2, 2);
        equals.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] staticGadget() {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(V17, ACC_PUBLIC | ACC_SUPER, "fx/StaticGadget", null, "java/lang/Object",
                new String[]{"java/io/Serializable"});
        cw.visitField(ACC_PUBLIC | ACC_STATIC, "cmd", "Ljava/lang/String;", null, null).visitEnd();
        MethodVisitor init = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(ALOAD, 0);
        init.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor readObject = cw.visitMethod(ACC_PRIVATE, "readObject",
                "(Ljava/io/ObjectInputStream;)V", null, null);
        readObject.visitCode();
        readObject.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        readObject.visitFieldInsn(GETSTATIC, "fx/StaticGadget", "cmd", "Ljava/lang/String;");
        readObject.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        readObject.visitInsn(POP);
        readObject.visitInsn(RETURN);
        readObject.visitMaxs(2, 1);
        readObject.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] gadget(boolean serializable, boolean useField) {
        ClassWriter cw = new ClassWriter(0);
        String[] interfaces = serializable ? new String[]{"java/io/Serializable"} : null;
        cw.visit(V17, ACC_PUBLIC | ACC_SUPER, "fx/" + (serializable
                        ? (useField ? "FieldGadget" : "SafeGadget") : "NonSerializableGadget"),
                null, "java/lang/Object", interfaces);
        if (useField) {
            cw.visitField(ACC_PUBLIC, "cmd", "Ljava/lang/String;", null, null).visitEnd();
        }
        MethodVisitor init = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(ALOAD, 0);
        init.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();

        MethodVisitor readObject = cw.visitMethod(ACC_PRIVATE, "readObject",
                "(Ljava/io/ObjectInputStream;)V", null, null);
        readObject.visitCode();
        readObject.visitMethodInsn(INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                "()Ljava/lang/Runtime;", false);
        if (useField) {
            readObject.visitVarInsn(ALOAD, 0);
            readObject.visitFieldInsn(GETFIELD,
                    serializable ? "fx/FieldGadget" : "fx/NonSerializableGadget",
                    "cmd", "Ljava/lang/String;");
        } else {
            readObject.visitLdcInsn("fixed");
        }
        readObject.visitMethodInsn(INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", false);
        readObject.visitInsn(POP);
        readObject.visitInsn(RETURN);
        readObject.visitMaxs(2, 1);
        readObject.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static Path writeJar(Path jar, Map<String, byte[]> classes) throws IOException {
        try (OutputStream out = Files.newOutputStream(jar);
             JarOutputStream jos = new JarOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                jos.putNextEntry(new JarEntry(entry.getKey()));
                jos.write(entry.getValue());
                jos.closeEntry();
            }
        }
        return jar;
    }
}
