# Just

轻量字节码 SAST：挖掘 Java 原生反序列化（ObjectInputStream）gadget 利用链。

## 架构

```text
JAR → ASM 前端（fat jar 嵌套解析 + JDK 运行库）→ 字节码事实模型 → CPG（内存图 + CFG + 调用图）
  → 黑板（Blackboard = CPG + 分析产物；知识源经事件协作，插件式扩展）
      KS1 模式匹配引擎：YAML 规则圈定 sink 起点（命令执行/动态类加载/JNDI/反射调用）
                       与 magic entry 终点（readObject/hashCode/equals/toString/.../InvocationHandler.invoke）
      KS2 反向污点引擎：从 sink 参数反向回溯（参数位置对齐、字段敏感、数组元素、
                       调用点敏感、反射/代理/lambda），触及 entry 即产出候选链
  → 链提取 + 置信度 → CSV（findings/edges/sinks）
```

## 使用

```bash
mvn package          # 产出 target/just-sast.jar
java -jar target/just-sast.jar scan --jar target.jar --stats
```

| 参数 | 说明 |
|---|---|
| `--jar <jar\|dir>` | 目标 JAR 或 class 目录（必填，支持 Spring Boot fat jar） |
| `--deps <a,b,...>` | 附加依赖（逗号分隔） |
| `--output <dir>` | CSV 输出目录（默认 `just-out`） |
| `--rules <file>` | 自定义规则 YAML（默认内置） |
| `--max-depth <n>` | 反向回溯深度上限（默认 20） |
| `--stats` | 扫描统计与逐规则过滤率 |

输出：
- `findings.csv`：候选 gadget 链（entry → sink 路径、置信度、变体计数）
- `edges.csv`：链每跳明细（调用/字段流转证据）
- `sinks.csv`：每个 sink 的分析裁决（KS2 对 KS1 标记的过滤记录）

本地测试（benchmark 与开发记录不入仓库）：

```bash
mvn test
```
