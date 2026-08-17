package io.just.sast.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** IO 工具。 */
public final class IoUtil {

    private IoUtil() {}

    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        in.transferTo(out);
        return out.toByteArray();
    }
}
