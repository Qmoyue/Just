# Just

轻量字节码 SAST：挖掘 Java 反序列化 gadget 利用链。
覆盖原生 OIS + Kryo/SnakeYAML/XStream/Hessian/Fastjson/Gson/Jackson 等替代框架。
一条命令深度扫描，CSV 输出，`--jdk-home` 支持目标 JDK 精确匹配。

## 快速开始

```bash
mvn package -DskipTests
java -jar target/just-sast-0.1.0.jar scan --jar app.jar --stats
```

## 架构

```
JAR/WAR → ASM 前端（fat jar/WAR 嵌套 + JDK[--jdk-home 可选指定版本]）
  → CPG（传递子类型分发 + 惰性 CFG + CHA 调用图）
  → 黑板三阶段调度（10 个知识源）
      ANALYSIS:     反向污点 | 前向对象污点 | OIS 回调 | 规则驱动框架桥接
      COMPOSITION:  对象图入口扩散 | 语义链组装
      CALIBRATION:  链校验 | 链剪枝 | SafeConfig | 已知模式识别
  → 置信度排序 → CSV 三表
```

## 参数

| 参数 | 说明 |
|---|---|
| `--jar <jar\|war\|dir>` | 目标（必填，支持 fat jar / WAR / class 目录） |
| `--deps <a,b,...>` | 附加依赖（逗号分隔） |
| `--jdk-home <dir>` | 目标 JDK/JRE 主目录（精确匹配 rt.jar / jrt-fs） |
| `--output <dir>` | CSV 输出（默认 `just-out`） |
| `--rules <file>` | 自定义规则 YAML |
| `--fast` | 快速模式（不加载 JDK 全量） |
| `--stats` | 扫描统计与逐规则过滤率 |

## 知识源（10 个引擎）

| KS | 包 | 阶段 | 职责 |
|---|---|---|---|
| BackwardTaint | `backward` | ANALYSIS | 反向污点：sink→可控性回溯（双向剪枝+接口反向分发） |
| ForwardTaint | `engine` | ANALYSIS | 前向对象污点（粗扫+精扫，GadgetInspector 式） |
| OisCallback | `ois` | ANALYSIS | OIS 机制回调（resolveClass/resolveProxyClass 重写建模） |
| FrameworkBridge | `framework` | ANALYSIS | 规则驱动框架桥接（Kryo/SnakeYAML/jackson 等→反射 sink） |
| ObjectGraph | `objectgraph` | COMPOSITION | 对象图入口扩散（字段类型回调重根） |
| ChainComposer | `compose` | COMPOSITION | 语义链组装（INVOKE/TRIGGER/TEMPLATE 桥接多级链） |
| ChainValidator | `calibrate` | CALIBRATION | 链校验：PASM 可行性 + 类型流 + 序列化可行性 |
| ChainPruner | `calibrate` | CALIBRATION | 链剪枝：触发上下文 + 机制去重（入口家族） |
| SafeConfig | `calibrate` | CALIBRATION | 安全配置抑制（XStream 白名单/Kryo 注册要求等→不产链） |
| GadgetPattern | `calibrate` | CALIBRATION | 已知 gadget 模式识别（CC1-7/Spring/Rome/CB/Jdk7u21） |

## 规则系统（4 种类型，改 YAML 零代码）

| kind | 用途 | 数量 | 来源 |
|---|---|---|---|
| `sink` | 危险调用点（RCE/JNDI/SQLI/SSRF/File/模板注入） | 35+ | 自有 + tabby/GI/CodeQL |
| `magic-entry` | OIS 反序列化入口方法 | 12 | 自有 |
| `source` | 替代反序列化框架入口 | 24 | CodeQL 16 框架 + 自有 |
| `model` | 声明式污点透传（tabby actions） | 10 | tabby |

## 输出

- **findings.csv**：候选链（按置信度降序，含路径/变体计数/证据）
- **edges.csv**：链每跳明细（调用/字段流转/桥接证据）
- **sinks.csv**：每个 sink 的裁决

## 从开源项目学习

| 来源 | 移植内容 |
|---|---|
| GadgetInspector | 传递子类型分发修复、前向对象污点两段式 |
| FLASH (USENIX'25) | 包前缀剪枝（DDCA 管线特化）、触发上下文 |
| JDD (IEEE S&P) | 语义链组装（bottom-up 组装思想）、已知模式识别 |
| tabby | model 规则（actions 声明式摘要）、--jdk-home |
| CodeQL | 16 框架 source 清单、SafeConfig 抑制 |
| marshalsec | 已知 gadget 模式分类 |

## 开发

规范 `AGENTS.md`；架构 `docs/architecture.md`；需求 `docs/requirements.md`。
新增知识源：实现 `KnowledgeSource`（声明 phase/interests）→ ServiceLoader 注册 → CLI 回归。
