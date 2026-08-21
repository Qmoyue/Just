# AGENTS.md

本项目开发规范（面向在此仓库工作的 AI 编程代理）。

## 项目

Just：轻量字节码 SAST，挖掘 Java 反序列化 gadget 利用链。
覆盖原生 ObjectInputStream + Kryo/SnakeYAML/XStream/Hessian/Fastjson/Gson/Jackson 等替代框架。
交付形态：**单个 CLI JAR**，无 GUI/Web/IDE 插件。CSV 三表输出，默认输出 `just-out`。

## 架构基线

```
JAR/WAR → ASM 前端（fat jar/WAR 嵌套 + JDK[--jdk-home 可选版本]）
  → CPG（传递子类型分发 + 惰性 CFG，构建后冻结）
  → 黑板三阶段调度（10 个知识源）
      ANALYSIS:     backward + engine + ois + framework
      COMPOSITION:  objectgraph + compose
      CALIBRATION:  calibrate×4（Validator/Pruner/SafeConfig/GadgetPattern）
  → 置信度 → CSV 三表
```

设计文档：`docs/architecture.md`（架构）、`docs/requirements.md`（需求）。

## 工程命令

```bash
mvn package -DskipTests                # 构建 target/just-sast-0.1.0.jar
java -jar target/just-sast-0.1.0.jar scan --jar x.jar
```

**不做 mvn test**：回归验收走手动 CLI 扫描逐语料校准。
CLI 极简：`--jar`（必填）+ `--deps/--output/--rules/--fast/--stats/--jdk-home`。

环境：JDK 17（release 17）、Maven 单模块。运行时依赖仅 ASM + picocli + SnakeYAML。

## 知识源

10 个内置引擎，按职责分包（不做 ksN 编号命名）：

| 包 | 类 | 阶段 |
|---|---|---|
| `backward` | BackwardTaintAnalysis | ANALYSIS |
| `engine` | ForwardTaintKnowledgeSource + ForwardEngine | ANALYSIS |
| `ois` | DeserializationCallbackKnowledgeSource | ANALYSIS |
| `framework` | FrameworkBridgeKnowledgeSource | ANALYSIS |
| `objectgraph` | ObjectGraphEntryKnowledgeSource | COMPOSITION |
| `compose` | ChainComposerKnowledgeSource | COMPOSITION |
| `calibrate` | ChainValidator/ChainPruner/SafeConfig/GadgetPattern | CALIBRATION |

## 开发规范

1. **低耦合高内聚**：ASM 仅在 frontend；知识源互不直接调用（只经黑板）；分层单向。
2. **知识源可扩展**：实现 `KnowledgeSource`（声明 phase/interests）+ ServiceLoader 注册（单轨）。ANALYSIS 阶段自足（用 RuleEngine 匹配，不读其他 KS 产物）。
3. **规则做数据，引擎做语义**：框架清单/sink/source/model 全在 YAML；引擎零硬编码框架数据；新增攻击面改规则文件即可。
4. **禁止 benchmark 过拟合**：生产代码不得特判 benchmark 类名/路径；优化必须是通用语义修复。
5. **代码风格**（ai-slop-taste）：直接、类型封闭（record/sealed）、少状态少抽象。
6. **反 slop**：不用"控制平面/网关"等名词；日志走 stderr。
7. **回归纪律**：新增/修改功能后手动 CLI 扫描 benchmark，检查 findings.csv 锚点链。

## 仓库约定

- `benchmark/` 与 `docs/development.md` **仅存本地，不得提交**。
- 规则文件：`src/main/resources/rules/default-rules.yaml`（4 种类型：sink/magic-entry/source/model）。
- 每条链携带 rule_id，假链可归因到规则。
