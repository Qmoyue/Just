package io.just.sast.model;

import java.util.ArrayList;
import java.util.List;

/** JVM 描述符工具。 */
public final class Descriptor {

    private Descriptor() {}

    /** 方法描述符的参数个数（不含 this）。 */
    public static int paramCount(String methodDescriptor) {
        int open = methodDescriptor.indexOf('(');
        int close = methodDescriptor.indexOf(')', open);
        String args = methodDescriptor.substring(open + 1, close);
        if (args.isEmpty()) {
            return 0;
        }
        int count = 0;
        int i = 0;
        while (i < args.length()) {
            count++;
            i = next(args, i);
        }
        return count;
    }

    /** 每个参数（含 this，若非静态）占用的槽位数。 */
    public static List<Integer> argSlots(String methodDescriptor, boolean isStatic) {
        int open = methodDescriptor.indexOf('(');
        int close = methodDescriptor.indexOf(')', open);
        String args = methodDescriptor.substring(open + 1, close);
        List<Integer> slots = new ArrayList<>();
        if (!isStatic) {
            slots.add(1);
        }
        int i = 0;
        while (i < args.length()) {
            int start = i;
            i = next(args, i);
            String type = args.substring(start, i);
            slots.add(type.equals("J") || type.equals("D") ? 2 : 1);
        }
        return slots;
    }

    /** 参数局部槽 → 参数序数（0 基，不含 this）；实例方法 slot 0（this/receiver）返回 -1；非参数槽（wide 次槽等）返回 -2。 */
    public static int paramOrdinal(String methodDescriptor, boolean isStatic, int slot) {
        List<Integer> slots = argSlots(methodDescriptor, isStatic);
        int cur = 0;
        for (int i = 0; i < slots.size(); i++) {
            if (cur == slot) {
                return isStatic ? i : i - 1;
            }
            cur += slots.get(i);
        }
        return -2;
    }

    /** 第 ordinal 个参数（0 基，不含 this）的类型子串（如 "Ljava/lang/String;"、"I"）；越界返回 null。 */
    public static String paramType(String methodDescriptor, int ordinal) {
        int open = methodDescriptor.indexOf('(');
        int close = methodDescriptor.indexOf(')', open);
        String args = methodDescriptor.substring(open + 1, close);
        int i = 0;
        for (int n = 0; i < args.length(); n++) {
            int start = i;
            i = next(args, i);
            if (n == ordinal) {
                return args.substring(start, i);
            }
        }
        return null;
    }

    /** 返回类型：方法描述符 ')' 之后的部分。 */
    public static String returnType(String methodDescriptor) {
        int close = methodDescriptor.indexOf(')');
        return close >= 0 ? methodDescriptor.substring(close + 1) : "Ljava/lang/Object;";
    }

    private static int next(String args, int i) {
        char c = args.charAt(i);
        if (c == '[') {
            int j = i;
            while (args.charAt(j) == '[') {
                j++;
            }
            return args.charAt(j) == 'L' ? args.indexOf(';', j) + 1 : j + 1;
        }
        if (c == 'L') {
            return args.indexOf(';', i) + 1;
        }
        return i + 1;
    }
}
