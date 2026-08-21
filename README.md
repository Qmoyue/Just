# Just

轻量字节码 SAST：挖掘 Java 原生反序列化（ObjectInputStream）gadget 利用链。
简单易用：一条命令深度扫描（默认含 JDK 运行库全量分析），CSV 输出。

## 架构

```text
JAR/WAR → ASM 前端（fat jar 嵌套解析 + JDK 运行库[可选指定目标版本]）
  → 字节码事实模型 → CPG（内存图 + 惰性 CFG/def-use + CHA 调用图）
  → 黑板（串行三阶段调度，插件式扩展，ServiceLoader 注册）
      ANALYSIS:     KS1 模式匹配 | KS2 反向污点 | KS4/5 前向对象污点
                    KS6 OIS 回调 | KS12 序列化框架桥接
      COMPOSITION:  KS7 对象图入口扩散
      CALIBRATION:  KS3 可行性 | KS8 类型流 | KS9 序列化可行性
                    KS10 触发上下文 | KS11 机制去重
  → 链提取 + 置信度排序（高可用链置顶）→ CSV（findings/edges/sinks）
```

## 使用

```bash
mvn package -DskipTests
java -jar target/just-sast-0.1.0.jar scan --jar target.jar
```

### 基本扫描

```bash
# 默认：用运行时 JDK 的核心库做深度分析
java -jar target/just-sast-0.1.0.jar scan --jar app.jar

# Spring Boot fat jar（自动递归解析 BOOT-INF/lib 嵌套 jar）
java -jar target/just-sast-0.1.0.jar scan --jar app.jar --stats

# WAR（自动解析 WEB-INF/classes + WEB-INF/lib）
java -jar target/just-sast-0.1.0.jar scan --jar app.war
```

### 指定目标 JDK 版本（推荐）

当目标 jar 编译版本与运行时 JDK 不一致时（如 Java 8 目标跑在 JDK 17 上），
用 `--jdk-home` 指定目标 JDK 路径，工具将使用该版本的核心库替代运行时 JDK：

```bash
# Java 8 目标：指定 JDK 8 主目录（读 jre/lib/rt.jar + 辅助 jar）
java -jar target/just-sast-0.1.0.jar scan --jar app.jar \
  --jdk-home /path/to/jdk8

# Java 7 目标：指定 JDK 7 主目录
java -jar target/just-sast-0.1.0.jar scan --jar app.jar \
  --jdk-home /path/to/jdk7

# 也可直接传 JRE 目录（读 lib/rt.jar）
java -jar target/just-sast-0.1.0.jar scan --jar app.jar \
  --jdk-home /path/to/jre8

# Java 9+ 目标（走 jrt-fs 挂载外部模块系统）
java -jar target/just-sast-0.1.0.jar scan --jar app.jar \
  --jdk-home /path/to/jdk11
```

> 不指定 `--jdk-home` 时，默认用运行时 JVM 的 JDK 核心库。工具会自动检测
> 目标 jar 的 class 文件版本（major version），报告并在版本不匹配时打 WARN。

### 全部参数

| 参数 | 说明 |
|---|---|
| `--jar <jar\|war\|dir>` | 目标 JAR/WAR 或 class 目录（必填） |
| `--deps <a,b,...>` | 附加依赖（逗号分隔） |
| `--jdk-home <dir>` | 目标 JDK/JRE 主目录（不指定则用运行时 JDK） |
| `--output <dir>` | CSV 输出目录（默认 `just-out`） |
| `--rules <file>` | 自定义规则 YAML（默认内置） |
| `--fast` | 快速模式：不加载 JDK 运行库全量（链可能不完整） |
| `--stats` | 扫描统计与逐规则过滤率 |

### 输出

- `findings.csv`：候选 gadget 链（按置信度降序，含路径与变体计数）
- `edges.csv`：链每跳明细（调用/字段流转证据）
- `sinks.csv`：每个 sink 的 KS2 裁决（对 KS1 标记的校准记录）

## 知识源

| KS | 阶段 | 职责 |
|---|---|---|
| KS1 | ANALYSIS | 模式匹配：YAML 规则圈定 sink 与 magic entry（含 owner 层次命中） |
| KS2 | ANALYSIS | 反向污点：从 sink 反向回答"该值是否攻击者可控"（双向剪枝 + 接口反向分发） |
| KS3 | CALIBRATION | 链可行性校验（字段声明/方法可解析） |
| KS4 | ANALYSIS | 前向对象污点粗扫（GadgetInspector 式） |
| KS5 | ANALYSIS | 前向精扫（接口展开/代理串联/反射解析） |
| KS6 | ANALYSIS | 反序列化回调（自定义 OIS 的 resolveClass/resolveProxyClass 重写） |
| KS7 | COMPOSITION | 对象图入口扩散（字段类型回调重根产新链） |
| KS8 | CALIBRATION | 类型流校准（逐跳值类型相容性） |
| KS9 | CALIBRATION | 序列化可行性（字段类型无可序列化子类闭包则拒） |
| KS10 | CALIBRATION | 触发上下文（hashCode/toString 等入口须有反序列化可达触发者） |
| KS11 | CALIBRATION | 机制去重（同机制尾按入口家族留代表，防笛卡尔积噪音） |
| KS12 | ANALYSIS | 序列化框架桥接（toString/readObject → jackson/gson/fastjson → getter 反射） |

## 开发

规范见 `AGENTS.md`；架构 `docs/architecture.md`；需求 `docs/requirements.md`。
新增知识源：实现 `io.just.sast.blackboard.KnowledgeSource`（声明 phase/interests）→ 写入
`META-INF/services/io.just.sast.blackboard.KnowledgeSource` → 手动 CLI 回归。
