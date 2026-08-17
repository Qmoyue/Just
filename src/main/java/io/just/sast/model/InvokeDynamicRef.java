package io.just.sast.model;

import java.util.List;

/** invokedynamic 指令操作数。 */
public record InvokeDynamicRef(String name, String descriptor, HandleRef bootstrap, List<Object> bootstrapArgs) {}
