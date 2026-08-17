package io.just.sast.cpg.graph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** 图节点：不可变 id/type/props + 可变质量注释 + 邻接表。 */
public final class Node {

    private final long id;
    private final NodeType type;
    private final Map<String, Object> props;
    private final Map<String, Object> notes = new HashMap<>();
    private final List<Edge> out = new ArrayList<>(2);
    private final List<Edge> in = new ArrayList<>(1);

    Node(long id, NodeType type, Map<String, Object> props) {
        this.id = id;
        this.type = type;
        this.props = Map.copyOf(props);
    }

    /** 分析过程中追加的质量注释（props 不可变，notes 供知识源写）。 */
    public void propsNote(String key, Object value) {
        notes.put(key, value);
    }

    public long id() {
        return id;
    }

    public NodeType type() {
        return type;
    }

    public Object prop(String key) {
        return props.get(key);
    }

    public String strProp(String key) {
        Object v = props.get(key);
        return v != null ? v.toString() : null;
    }

    public List<Edge> out() {
        return out;
    }

    public List<Edge> in() {
        return in;
    }

    void addOut(Edge e) {
        out.add(e);
    }

    void addIn(Edge e) {
        in.add(e);
    }

    @Override
    public String toString() {
        return type + "#" + id + props;
    }
}
