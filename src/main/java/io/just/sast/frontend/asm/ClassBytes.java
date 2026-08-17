package io.just.sast.frontend.asm;

/** 从输入中读取到的单个 class 字节。 */
public record ClassBytes(String className, byte[] bytes, String origin) {}
