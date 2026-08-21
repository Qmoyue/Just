package io.just.sast.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/** IO 工具。 */
public final class IoUtil {

    /** 单条目读取上限（64MB）：防 zip 炸弹单条目 OOM。 */
    private static final int MAX_ENTRY_BYTES = 64 * 1024 * 1024;

    private IoUtil() {}

    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        byte[] buffer = new byte[8192];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) >= 0) {
            total += n;
            if (total > MAX_ENTRY_BYTES) {
                throw new IOException("条目超过单条目上限 " + MAX_ENTRY_BYTES + " 字节");
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
