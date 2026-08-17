package io.just.sast.cpg.build;

/** 一条 CFG 后继。 */
public record CfgEdge(int targetOffset, CfgLabel label) {}
