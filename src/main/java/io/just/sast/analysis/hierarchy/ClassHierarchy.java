package io.just.sast.analysis.hierarchy;

import io.just.sast.model.ClassInfo;
import io.just.sast.model.MethodInfo;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 类层次：子类索引、subtype 判定、Serializable 判定、方法解析（沿父类+接口，支持 default method）。
 * JDK 类按需懒加载。
 */
public final class ClassHierarchy {

    private final Map<String, ClassInfo> classes;
    private final JdkClassSource jdk;
    private final Map<String, List<String>> directSubtypes = new HashMap<>();
    private final Map<String, Boolean> subtypeCache = new HashMap<>();
    private final Map<String, String> resolveCache = new HashMap<>();
    private final Map<String, List<String>> implementersCache = new HashMap<>();

    public ClassHierarchy(Map<String, ClassInfo> initial, JdkClassSource jdk) {
        this.classes = new HashMap<>(initial);
        this.jdk = jdk;
        for (ClassInfo c : initial.values()) {
            indexSubtypes(c);
        }
    }

    private void indexSubtypes(ClassInfo c) {
        if (c.superName() != null) {
            directSubtypes.computeIfAbsent(c.superName(), k -> new ArrayList<>(1)).add(c.internalName());
        }
        for (String itf : c.interfaces()) {
            directSubtypes.computeIfAbsent(itf, k -> new ArrayList<>(1)).add(c.internalName());
        }
    }

    /** 取类信息，未知类走 JDK 懒加载。 */
    public ClassInfo classInfo(String internalName) {
        ClassInfo c = classes.get(internalName);
        if (c == null && jdk != null) {
            c = jdk.load(internalName);
            if (c != null) {
                classes.put(internalName, c);
                indexSubtypes(c);
            }
        }
        return c;
    }

    public int classCount() {
        return classes.size();
    }

    /** 已加载类中 name 的直接子类型。 */
    public List<String> loadedSubtypes(String internalName) {
        List<String> list = directSubtypes.get(internalName);
        return list != null ? list : List.of();
    }

    /** 类的传递接口（含父类继承），供接口反向分发使用。 */
    public List<String> transitiveInterfaces(String internalName) {
        List<String> result = new ArrayList<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(internalName);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                continue;
            }
            for (String itf : ci.interfaces()) {
                if (visited.add(itf)) {
                    result.add(itf);
                    queue.add(itf);
                }
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
        }
        return result;
    }

    /** a 是否为 b 的子类型（沿父类 + 传递接口）。 */
    public boolean isSubtypeOf(String a, String b) {
        if (a.equals(b)) {
            return true;
        }
        String key = a + "->" + b;
        Boolean cached = subtypeCache.get(key);
        if (cached != null) {
            return cached;
        }
        boolean result = computeSubtype(a, b);
        subtypeCache.put(key, result);
        return result;
    }

    private boolean computeSubtype(String a, String b) {
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(a);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                continue;
            }
            if (b.equals(ci.superName())) {
                return true;
            }
            if (ci.interfaces().contains(b)) {
                return true;
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(ci.interfaces());
        }
        return false;
    }

    public boolean isSerializable(String internalName) {
        return isSubtypeOf(internalName, "java/io/Serializable");
    }

    /**
     * 解析方法声明位置：沿父类+接口找第一个声明 (name, desc) 的类。
     * 未找到返回 null。
     */
    public String resolveMethod(String owner, String name, String desc) {
        String key = owner + "#" + name + desc;
        if (resolveCache.containsKey(key)) {
            return resolveCache.get(key);
        }
        String result = computeResolve(owner, name, desc);
        resolveCache.put(key, result);
        return result;
    }

    private String computeResolve(String owner, String name, String desc) {
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(owner);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            ClassInfo ci = classInfo(cur);
            if (ci == null) {
                continue;
            }
            MethodInfo m = ci.method(name, desc);
            if (m != null) {
                return cur;
            }
            if (ci.superName() != null) {
                queue.add(ci.superName());
            }
            queue.addAll(ci.interfaces());
        }
        return null;
    }

    /** 字段解析：沿父类链找字段声明类；未找到返回 null。 */
    public String resolveField(String owner, String name) {
        String current = owner;
        Set<String> visited = new HashSet<>();
        while (current != null && visited.add(current)) {
            ClassInfo cls = classInfo(current);
            if (cls == null) {
                return null; // 类不可解析：无法证明存在，保守由调用方处理
            }
            if (cls.field(name) != null) {
                return current;
            }
            current = cls.superName();
        }
        return null;
    }

    /**
     * 接口实现类（传递，非接口类），超上限返回 null 表示放弃枚举。带缓存。
     */
    public List<String> implementers(String interfaceName, int cap) {
        if (implementersCache.containsKey(interfaceName)) {
            return implementersCache.get(interfaceName);
        }
        List<String> result = new ArrayList<>();
        Deque<String> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(interfaceName);
        while (!queue.isEmpty()) {
            String cur = queue.poll();
            if (!visited.add(cur)) {
                continue;
            }
            // 快照遍历：classInfo 懒加载可能向 directSubtypes 追加（单线程 CME）
            for (String sub : new ArrayList<>(loadedSubtypes(cur))) {
                ClassInfo ci = classInfo(sub);
                if (ci == null) {
                    continue;
                }
                if (ci.isInterface()) {
                    queue.add(sub);
                } else {
                    result.add(sub);
                    if (result.size() > cap) {
                        implementersCache.put(interfaceName, null);
                        return null;
                    }
                }
            }
        }
        List<String> cached = List.copyOf(result);
        implementersCache.put(interfaceName, cached);
        return cached;
    }
}
