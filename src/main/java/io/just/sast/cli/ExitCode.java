package io.just.sast.cli;

/** 退出码。 */
public enum ExitCode {
    /** 扫描成功 */
    OK(0),
    /** 参数/配置错误 */
    USAGE(2),
    /** 内部错误 */
    INTERNAL(3);

    private final int code;

    ExitCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }
}
