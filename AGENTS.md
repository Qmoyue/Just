# AGENTS.md

本项目开发规范（面向在此仓库工作的 AI 编程代理）。

## 项目

Just：轻量字节码 SAST，挖掘 Java 原生反序列化（ObjectInputStream）gadget 利用链。
交付形态：**单个 CLI JAR**，无 GUI/Web/IDE 插件。CSV 输出（findings/edges/sinks），默认输出 `just-out`。

## 架构基线

```
JAR/WAR → ASM 前端（fat jar 嵌套解析 + JDK 运行库）
  → model（自研字节码事实，不依赖 ASM）
  → CPG（内存图：METHOD/CALL 节点 + 调用边；CFG 惰性计算，构建后冻结）
  → 黑板架构（串行两阶段：ANALYSIS → CALIBRATION）：
      KS1 模式匹配（YAML 规则，sink 起点与 magic entry 终点，owner 层次匹配）
      KS2 反向污点（参数序数对齐、字段敏感、数组元素、上下文不敏感）
      KS4/KS5 前向对象污点（粗扫/接口代理反射精扫）
      KS3 链可行性校验（CALIBRATION 阶段）
      → 链提取 + 置信度 → CSV 三表
```

设计文档：`docs/architecture.md`（架构）、`docs/requirements.md`（需求基线）。

## 工程命令

```bash
mvn package -DskipTests                # 构建 target/just-sast-<ver>.jar
java -jar target/just-sast-0.1.0.jar scan --jar x.jar
```

**不做 mvn test**：回归验收走手动 CLI 扫描逐语料校准（`java -jar ... scan --jar benchmark/xxx.jar`，检查 findings.csv 中锚点链）。
CLI 极简：仅 `--jar`（必填）+ `--deps/--output/--rules/--fast/--stats`。深度分析默认开启（含 JDK 运行库）。

环境：JDK 17（release 17）、Maven 单模块。运行时依赖仅 ASM + picocli + SnakeYAML。

## 开发规范

1. **低耦合高内聚**：`org.objectweb.asm.*` 只允许出现在 `frontend` 包；知识源之间零直接调用（只经黑板通信）；分层单向依赖。
2. **知识源可扩展**：新引擎实现 `KnowledgeSource` 接口（声明 phase/interests）+ ServiceLoader 注册（单轨，META-INF/services）即可，不得修改既有引擎。内置 KS 在 `io.just.sast.knowledge.ks1..ks11` 包（ks10 触发上下文、ks11 机制去重均在 CALIBRATION）；共用引擎库：过程内 origin 分析在 `io.just.sast.analysis.taint`（黑板构造分发），前向污点引擎在 `io.just.sast.knowledge.engine`；KS 包之间禁止互相 import。ANALYSIS 阶段 KS 必须自足（只读图/层次/规则等静态输入，不读其他 KS 产物）；控制器串行三阶段调度（ANALYSIS → COMPOSITION → CALIBRATION），CALIBRATION 内顺序 KS3→KS8→KS9→KS10→KS11，KS 无需线程安全。
3. **回归纪律**：不走 mvn test；新增/修改功能后用 `java -jar target/just-sast-*.jar scan --jar benchmark/xxx.jar --output just-out` 手动扫描，检查 findings.csv 中锚点链在位、负例不出。
4. **禁止 benchmark 过拟合**：生产代码不得出现任何针对 benchmark 类名/路径的特判；优化必须是通用语义修复；不得伪造准确率。
5. **反 slop 词汇**：不用"控制平面/网关/运行时"等名词；日志走 stderr，与 CSV 输出分离。

## 仓库约定

- `benchmark/`（五个回归 jar + javamix wp）与 `docs/development.md`（开发记录）**仅存本地，不得提交**。
- 规则文件：`src/main/resources/rules/default-rules.yaml`（sink/magic-entry 声明式规则，支持 `~` 锚定正则）。
- 规则默认 owner+name+descriptor 结构匹配；每条链携带 rule_id，假链需可归因到规则。
