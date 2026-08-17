package io.just.sast.integration;

import io.just.sast.blackboard.Chain;
import io.just.sast.cli.ScanPipeline;
import io.just.sast.testutil.FixtureJars;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 合成 fixture 契约：
 * 1. 字段可控的 readObject → exec 链被检出
 * 2. 常量参数的 exec 不报（不可控）
 * 3. 非 Serializable 类的 readObject 不报（非入口）
 * 4. receiver 非 this 的字段读取不报（攻击者只控 this 的字段）
 * 5. 静态字段读取不报（静态不经反序列化）
 */
class SyntheticGadgetTest {

    @Test
    void fieldGadgetFoundButNegativesNot(@TempDir Path dir) throws Exception {
        Path jar = FixtureJars.buildGadgets(dir);
        ScanPipeline.ScanResult result =
                ScanPipeline.run(jar, null, dir.resolve("out"), null, 20, false, false);
        List<Chain> chains = result.chains();

        assertTrue(chains.stream().anyMatch(c ->
                        c.entryClass().equals("fx/FieldGadget")
                                && c.entryMethod().equals("readObject")
                                && c.sinkClass().equals("java/lang/Runtime")
                                && c.sinkMethod().equals("exec")),
                "FieldGadget.readObject → Runtime.exec 应出链");

        assertFalse(chains.stream().anyMatch(c -> c.entryClass().equals("fx/SafeGadget")),
                "SafeGadget（常量参数）不应出链");

        assertFalse(chains.stream().anyMatch(c -> c.entryClass().equals("fx/NonSerializableGadget")),
                "NonSerializableGadget 不应出链");

        assertFalse(chains.stream().anyMatch(c -> c.entryClass().equals("fx/ReceiverGadget")),
                "ReceiverGadget（receiver 非 this）不应出链");

        assertFalse(chains.stream().anyMatch(c -> c.entryClass().equals("fx/StaticGadget")),
                "StaticGadget（静态字段）不应出链");
    }
}
