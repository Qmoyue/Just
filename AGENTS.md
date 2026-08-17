# AGENTS.md

本项目开发规范（面向在此仓库工作的 AI 编程代理）。

## 项目

Just：轻量字节码 SAST，挖掘 Java 原生反序列化（ObjectInputStream）gadget 利用链。
交付形态：**单个 CLI JAR**，无 GUI/Web/IDE 插件。CSV 输出（findings/edges/sinks），默认输出 `just-out`。

## 架构基线

```
JAR → ASM 前端（fat jar 嵌套解析 + JDK 运行库）
  → model（自研字节码事实，不依赖 ASM）
  → CPG（内存图：METHOD/CALL 节点 + 调用边；CFG/def-use 惰性计算）
  → 黑板架构：KS1 模式匹配（YAML 规则，圈定 sink 起点与 magic entry 终点）
              KS2 反向污点（参数位置对齐、字段敏感、数组元素、调用点敏感）
              → 链提取 + 置信度 → CSV
```

设计文档：`docs/architecture.md`（架构）、`docs/requirements.md`（需求基线）。

## 工程命令

```bash
mvn package                 # 构建 target/just-sast.jar
mvn test                    # 全部测试（含 benchmark 三 jar 真实回归）
java -jar target/just-sast.jar scan --jar x.jar --stats
```

环境：JDK 17（release 17）、Maven 单模块。运行时依赖仅 ASM + picocli + SnakeYAML。

## 开发规范

1. **低耦合高内聚**：`org.objectweb.asm.*` 只允许出现在 `frontend` 包；知识源之间零直接调用（只经黑板通信）；分层单向依赖。
2. **知识源可扩展**：新引擎实现 `KnowledgeSource` 接口注册即可，不得修改既有引擎。
3. **测试纪律**（test-doctor）：每条测试保护一个用户可见契约（检出链/负例不报/CSV 格式/损坏类隔离），不测实现细节。
4. **禁止 benchmark 过拟合**：生产代码不得出现任何针对 benchmark 类名/路径的特判；优化必须是通用语义修复；不得伪造准确率。
5. **代码风格**（ai-slop-taste）：直接、类型封闭（record/sealed）、少状态少抽象；不写死结构、不写未使用的代码。
6. **反 slop 词汇**：不用"控制平面/网关/运行时"等名词；日志走 stderr，与 CSV 输出分离。

## 仓库约定

- `benchmark/`（demo.jar、demo2.jar、Unictf.jar）与 `docs/development.md`（开发记录）**仅存本地，不得提交**。
- 规则文件：`src/main/resources/rules/default-rules.yaml`（sink/magic-entry 声明式规则，支持 `~` 锚定正则）。
- 规则默认 owner+name+descriptor 结构匹配；每条链携带 rule_id，假链需可归因到规则。
