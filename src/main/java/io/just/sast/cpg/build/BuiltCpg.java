package io.just.sast.cpg.build;

import io.just.sast.cpg.graph.Graph;

/** CPG 构建产物。 */
public record BuiltCpg(Graph graph, FieldWriterIndex fieldWriters) {}
