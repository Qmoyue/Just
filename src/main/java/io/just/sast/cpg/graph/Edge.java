package io.just.sast.cpg.graph;

/** 图边：类型 + 标签（如 dispatch 类型、TAINT hop 类型）。 */
public final class Edge {

    private final Node from;
    private final Node to;
    private final EdgeType type;
    private final String label;

    Edge(Node from, Node to, EdgeType type, String label) {
        this.from = from;
        this.to = to;
        this.type = type;
        this.label = label;
    }

    public Node from() {
        return from;
    }

    public Node to() {
        return to;
    }

    public EdgeType type() {
        return type;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return from.id() + " -" + type + "(" + label + ")-> " + to.id();
    }
}
