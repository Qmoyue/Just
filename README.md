# Just

轻量字节码 SAST：挖掘 Java 原生反序列化（ObjectInputStream）gadget 利用链。
简单易用：一条命令深度扫描（默认含 JDK 运行库全量分析），CSV 输出。

## 架构

```text
JAR → ASM 前端（fat jar 嵌套解析 + JDK 运行库）
  → 字节码事实模型 → CPG（内存图 + 惰性 CFG/def-use + CHA 调用图）
  → 黑板（知识源交叉并行、插件式扩展，ServiceLoader 注册）
      KS1 模式匹配：YAML 规则圈定 sink 起点与 magic entry 终点
      KS2 反向污点：从 sink 反向回答"该值是否攻击者可控"
         （OIS 源 / 对象图传递 / 字段敏感 / 数组元素 / 可控 receiver）
  → 链提取 + 置信度排序（高可用链置顶）→ CSV（findings/edges/sinks）
```

## 使用

```bash
mvn package
java -jar target/just-sast.jar scan --jar target.jar
```

| 参数 | 说明 |
|---|---|
| `--jar <jar\|dir>` | 目标 JAR 或 class 目录（必填，支持 Spring Boot fat jar） |
| `--deps <a,b,...>` | 附加依赖（逗号分隔） |
| `--output <dir>` | CSV 输出目录（默认 `just-out`） |
| `--rules <file>` | 自定义规则 YAML（默认内置） |
| `--fast` | 快速模式：不加载 JDK 运行库全量（链可能不完整） |
| `--stats` | 扫描统计与逐规则过滤率 |

输出：
- `findings.csv`：候选 gadget 链（按置信度降序，含路径与变体计数）
- `edges.csv`：链每跳明细（调用/字段流转证据）
- `sinks.csv`：每个 sink 的 KS2 裁决（对 KS1 标记的校准记录）

## 开发

规范见 `AGENTS.md`；架构 `docs/architecture.md`；需求 `docs/requirements.md`。
新增知识源：实现 `io.just.sast.blackboard.KnowledgeSource` → 写入
`META-INF/services/io.just.sast.blackboard.KnowledgeSource` → 回归测试。
