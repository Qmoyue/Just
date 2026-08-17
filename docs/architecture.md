# Just — 架构设计

## 1. 项目目标与约束

- 轻量 Java SAST：对**闭源 JAR**做 **Java 原生反序列化（ObjectInputStream）gadget 链挖掘**。
- 交付：**单个可运行 JAR**（shade 打包），CLI 使用，CSV 导出，默认输出目录 `just-out`。
- 运行时依赖仅三类：ASM（asm/asm-tree/asm-analysis）、picocli、SnakeYAML。
- 启动快：无 DI、无服务、无重型初始化。
- 低耦合高内聚：黑板架构，引擎只通过共享图通信；ASM 隔离在 frontend 层。
- JDK 17 编译运行（release 17），单 Maven 模块。

**核心流程：**

```text
JAR → ASM 前端解析 → CPG 构建 → 黑板架构链路发现 → CSV 报告
```

## 2. 总体架构（黑板架构）

```text
┌─────────────────────────────────────────────────────────────────────┐
│  cli         参数解析、命令编排、退出码、日志(stderr)                   │
├─────────────────────────────────────────────────────────────────────┤
│  config      ScanConfig、YAML 规则加载（SnakeYAML）                    │
├─────────────────────────────────────────────────────────────────────┤
│  ╔══════════════ 黑板（Blackboard）= CPG 图 + 分析产物 ══════════════╗  │
│  ║ 节点/边 + TAINT 反向边 + SINK/MAGIC_ENTRY 标记 + 事件 + 质量记录    ║  │
│  ╚═════════════════════════════════════════════════════════════════╝  │
├─────────────────────────────────────────────────────────────────────┤
│  知识源（插件式，互不直接调用，仅读写黑板）                               │
│  ┌─────────────────────────┐  ┌──────────────────────────────────┐   │
│  │ KS1 模式匹配引擎          │  │ KS2 反向污点引擎                  │   │
│  │ · 标记 SINK 起点          │  │ · 从 SINK 参数反向传播            │   │
│  │ · 标记 MAGIC_ENTRY 终点   │  │ · 反 def-use/字段/调用图          │   │
│  │ · Serializable 过滤       │  │ · 参数位置对齐校验                │   │
│  │ （高召回预筛）             │  │ · 写 TAINT 反向边（精度闸门）     │   │
│  └─────────────────────────┘  └──────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│  控制器：worklist 调度、事件分发、链达成判定                            │
├─────────────────────────────────────────────────────────────────────┤
│  chain       链提取、路径翻转（entry→sink）、置信度评分                 │
├─────────────────────────────────────────────────────────────────────┤
│  report      CSV（findings.csv/edges.csv）、控制台摘要                 │
└─────────────────────────────────────────────────────────────────────┘
```

**依赖方向（单向）：**

```text
cli → config → frontend → model
cli → cpg → model
cli → analysis.{hierarchy,callgraph,pattern,taint} → {model, cpg}
cli → blackboard → {analysis, cpg}
cli → chain → {cpg}
cli → report → {chain, cpg}
```

**耦合规则：**
- 仅 `frontend` 层允许 `import org.objectweb.asm.*`。
- 知识源之间零直接调用；新增引擎不触碰既有引擎。
- 分析层不感知 CLI、不写文件；异常与质量信号经黑板事件向上抛。

## 3. 知识源插件化

```java
public interface KnowledgeSource {
    /** 唯一标识，如 "pattern" / "backward-taint" */
    String id();
    /** 声明关心的事件类型（SINK_MARKED / TAINT_EXTENDED / EDGE_ADDED ...） */
    Set<EventType> interests();
    /** 一次性初始化（读取配置、编译规则） */
    void init(Blackboard blackboard);
    /** 响应黑板事件执行；只读写黑板，不直接调用其他知识源 */
    void run(Blackboard blackboard, Event event);
}
```

- 控制器持有 `KnowledgeSourceRegistry`：加载内置 KS1/KS2，后续新引擎（如 v0.2 正向探索、PASM 验证器）实现同一接口注册即可，零侵入。
- 事件流：KS1 标记 SINK → 控制器调度 KS2 反向分析 → KS2 写 TAINT 边 → 控制器判定链达成 → 链提取器消费。
- v0.1 以内置注册表形式实现；接口即为扩展点。

## 4. 核心数据模型

### 4.1 字节码事实（model 层，ASM 解析产物）

```java
record ClassInfo(String internalName, String superName, List<String> interfaces,
                 int access, List<MethodInfo> methods, List<FieldInfo> fields,
                 List<StringConstant> constants) {}

record MethodInfo(String owner, String name, String descriptor, int access,
                  List<InsnFact> instructions, List<TryCatchFact> tryCatch,
                  boolean hasLineNumbers) {}

record FieldInfo(String owner, String name, String descriptor, int access) {}

record InsnFact(int offset, int opcode, List<Object> operands) {}
// operands：MethodInsn → (owner, name, desc)；LdcInsn → 常量值
```

### 4.2 CPG 节点

| 节点 | 关键属性 |
|---|---|
| `CLASS` | internalName, superName, interfaces, access |
| `METHOD` | owner, name, descriptor, access |
| `FIELD` | owner, name, descriptor, access |
| `PARAM` / `LOCAL` | index |
| `INS` | offset, opcode, operands |
| `CALL` | owner, name, descriptor, invokeKind |
| `CONST` | value, type |
| `SINK` | sinkKind, category, taintedPositions, ruleId |
| `MAGIC_ENTRY` | magicKind, ruleId |
| `UNKNOWN_EDGE` | reason |

### 4.3 CPG 边

| 边 | from → to | 用途 |
|---|---|---|
| `CONTAINS` | METHOD → INS | 结构边 |
| `ARG` | CALL → INS, index | 调用参数 |
| `CFG` | INS → INS, {SEQ/TRUE/FALSE/JUMP/RETURN/EXCEPTION} | 控制流 |
| `EXTENDS` / `IMPLEMENTS` | CLASS → CLASS | 类层次 |
| `INVOKES` | CALL → METHOD | 静态/特殊调用 |
| `DISPATCHES` | CALL → METHOD | 虚调用 CHA 候选（多边） |
| `REFLECTIVE` / `PROXY` / `LAMBDA` | CALL → METHOD | 反射/代理/lambda 边 |
| `FIELD_REF` | INS → FIELD, {read/write} | 字段读写 |
| `TAINT` | 被需求者 → 需求者（**反向**），{load/store/call/field/reflective/proxy/lambda} | KS2 产物 |

> TAINT 边内部为反向（"sink 值 ← 谁产生它"），报告时翻转为 entry → sink 人读顺序。

### 4.4 反向索引

| 索引 | 内容 |
|---|---|
| `ReverseCallIndex` | callee → 所有调用点（含 CHA 候选） |
| `ReverseDefUseIndex` | 变量/栈槽 ← 最近生产者指令 |
| `FieldWriterIndex` | (class, field) → PUTFIELD 指令集合 |
| `NodePropertyIndex` | 类型/属性 → 节点（KS1 匹配用） |

## 5. 分析流水线

### 5.1 构建期（一次性）

```text
FRONTEND   目标 JAR/目录 + 依赖 JAR → ASM 解析 → ClassInfo 集合（含诊断）
HIERARCHY  类层次 + JDK 懒加载 → EXTENDS/IMPLEMENTS → Serializable 判定表
CPG_BUILD  CONTAINS/ARG/CFG/FIELD_REF 边 + 四个反向索引
CALLGRAPH  CHA + 反射/代理/lambda 特殊边
```

### 5.2 分析期（黑板循环：KS1/KS2 交叉并行）

```text
SCAN_START 事件广播：KS1 与 KS2 同时触发，互不等待对方的输出。

KS1（模式匹配，高召回预筛）：
  独立枚举：按 YAML 规则遍历 CALL/METHOD 节点 → 标记 SINK / MAGIC_ENTRY → 写黑板
KS2（反向污点，精度闸门）：
  独立枚举：同样从黑板读规则，自行圈定 sink 候选（不读 KS1 的标记）
  → 对每个候选反向回答"该值是否攻击者可控"（controlled 语义：
    OIS 读无条件可控 / magic entry 对象图可控 / 可控对象字段可控 /
    可控值写入字段可控 / 数组元素 / 可控 receiver 返回值）
  → 写 TAINT 路径边 + 候选链 + 每 sink 裁决（SinkOutcome）

校准关系（非流水线依赖）：黑板合并视图 sinkRecords() = KS1 标记 + KS2 裁决；
KS2 的裁决附着于 KS1 的标记之上，过滤率即纠错效果的量化（sinks.csv + 控制台逐规则统计）。
新增知识源实现 KnowledgeSource 接口 + ServiceLoader 注册即可加入循环，零侵入。
```

### 5.3 报告期

```text
链整理（TAINT 反向路径翻转为 entry→sink）→ 去重 → 置信度 → CSV + 控制台摘要
```

## 6. 关键算法

### 6.1 类层次与 JDK 懒加载

- 全量解析目标 + 依赖；JDK 类按需从 jmods/运行镜像提取单 class 并缓存。
- Serializable/Externalizable 传递闭包判定，结果缓存。
- JDK 类参与调用图与反向搜索（真实链必经 HashMap/PriorityQueue 等）。

### 6.2 CFG（指令级）

顺序边 / 条件边（IF*）/ 跳转边（GOTO、TABLESWITCH、LOOKUPSWITCH）/ 返回边 / 异常边（TryCatch）。反向遍历 = 边取逆。

### 6.3 调用图（CHA 起步）

- `INVOKESTATIC/INVOKESPECIAL` 定目标；`INVOKEVIRTUAL/INVOKEINTERFACE` CHA 在声明类型及子类找实现。
- 反射：`Method.invoke` 等 Method 对象来源可解析时加 `REFLECTIVE` 边，否则 UNKNOWN 标记。
- 代理：`Proxy.newProxyInstance` 的 handler 可解析时，接口调用 → `invoke`。
- Lambda：`invokedynamic` bootstrap 参数解析 `implMethod` → 目标方法。

### 6.4 反向污点引擎（KS2，精度闸门）

**问题形式：** sink 调用点第 i 个参数（或 receiver）需要污点 → 求哪些程序点能使其可控 → 直至触及 MAGIC_ENTRY。

**抽象位置：** `LocalVar(class.method, slot) | InstanceField(class, field) | Constant | Unknown`

**反向需求：** `TaintRequirement(location, taintKind)`

**传播规则（需求回溯方向）：**

| 字节码事实 | 规则 |
|---|---|
| STORE（栈→槽） | 槽需要污点 → 回溯栈顶生产者 |
| LOAD（槽→栈） | 栈需要污点 → 槽需要污点 → 最近 STORE（反 def-use） |
| PUTFIELD this.f=v | this.f 需要污点 → 回溯 v；发生在 MAGIC_ENTRY 方法内 → 链达成 |
| GETFIELD x=this.f | x 需要污点 → this.f 需要污点 → FieldWriterIndex 回溯写入点 |
| 静态调用 | 形参需要污点 → 所有调用点对应实参；返回值需要污点 → 方法内 RETURN |
| CHA 多目标 | 分发所有候选目标，记录 dispatchKind |
| REFLECTIVE | 被反射方法形参 → Method 对象来源/方法名常量 |
| PROXY | invoke 的 args → 接口调用点实参 |
| LAMBDA | lambda 形参 → 捕获变量 |
| 常量 | 回溯终止 |

**参数位置对齐（强制约束）：** 跨方法回溯必须严格映射形参↔实参、receiver↔this、返回值↔调用结果；未对齐即终止分支。防"纸上路径"假链。

**终止与防爆：** 回溯深度上限（默认 20）；同一 (method, location) 去环；每 sink 候选链数量上限；需求集合并保证收敛。

### 6.5 链达成、提取与置信度

```text
链达成：TAINT 回溯触及 MAGIC_ENTRY 的 this 实例字段 / 参数 / invoke 的 args

Chain := Entry(magic entry) → hop1 → ... → Sink(call)
ChainHop := {fromMethod, toMethod, edgeKind, field?, reason}
```

- 去重键：entry + sink + 有序中间方法集合。
- 置信度按**路径证据**（非 sink 匹配方式）打分：静态全解析 > CHA 虚分发 > 反射/代理/lambda > 含 UNKNOWN 跳。

### 6.6 黑板调度协议

```text
事件：SINK_MARKED / TAINT_EXTENDED / EDGE_ADDED / CHAIN_FOUND / QUALITY_NOTE
控制器：FIFO + 优先级队列；幂等消费；只做调度不做评分决策
```

## 7. 规则系统（YAML）与防误报约束

- 规则 = 声明式模型：`sink`（起点）、`magic-entry`（终点）。
- **防误报约束**：sink/magic-entry 默认要求 **owner + name + descriptor 结构匹配**；正则仅作可选增强且须**锚定**（同族 API，如 `~"lookup|list|bind"`），不鼓励裸匹配方法名。
- 每条链携带出发 sink 的 `rule_id` → 假链可归因到具体规则，改 YAML 即可修复，引擎不动。
- 分工原则：KS1 高召回（漏真 sink 无法补救），KS2 高精度（噪声由严格判定消化），置信度按路径证据定级。

```yaml
rules:
  - id: JUST-SINK-COMMAND-EXEC
    kind: sink
    category: COMMAND_EXEC
    severity: HIGH
    match:
      call: { owner: "java/lang/Runtime", name: "exec" }
      tainted: [{arg: 0}]

  - id: JUST-SINK-CLASSLOAD
    kind: sink
    category: CODE_EXEC
    match:
      call: { owner: "java/lang/Class", name: "forName" }
      tainted: [{arg: 0}]

  - id: JUST-SINK-JNDI
    kind: sink
    category: JNDI
    match:
      call: { owner: "javax/naming/Context", name: ~"lookup|list|bind" }
      tainted: [{arg: 0}]

  - id: JUST-SINK-TEMPLATESIMPL
    kind: sink
    category: CODE_EXEC
    match:
      call: { owner: "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl",
              name: ~"getOutputProperties|newTransformer" }
      tainted: [{receiver: true}]

  - id: JUST-ENTRY-READOBJECT
    kind: magic-entry
    match:
      method: { name: "readObject", descriptor: "(Ljava/io/ObjectInputStream;)V" }
      class: { implements: "java/io/Serializable" }

  - id: JUST-ENTRY-HASHCODE
    kind: magic-entry
    match:
      method: { name: "hashCode", descriptor: "()I" }
      class: { serializable: true }

  - id: JUST-ENTRY-PROXY-INVOKE
    kind: magic-entry
    match:
      method: { name: "invoke",
                descriptor: "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;" }
      class: { implements: "java/lang/reflect/InvocationHandler" }
```

## 8. CSV 报告

### findings.csv（一条链一行，entry → sink 顺序）

```text
chain_id, rule_id, category, severity, confidence, quality,
entry_class, entry_method, entry_kind,
sink_class, sink_method, sink_kind,
chain_length, unresolved_hops, path, evidence
```

- `quality`：`COMPLETE / PARTIAL(unresolved=n)`
- `path`：`Foo.readObject -> Bar.toString -> Runtime.exec`
- `evidence`：分号分隔关键证据（Serializable 继承、字段流转点、常量）

### edges.csv（链每跳明细）

```text
chain_id, step, from_class, from_method, to_class, to_method, edge_kind, field, reason
```

- `edge_kind ∈ {DIRECT_CALL, VIRTUAL_DISPATCH, REFLECTIVE, PROXY, LAMBDA, FIELD_FLOW}`

### 格式约定

RFC 4180 转义；UTF-8 with BOM（Excel 中文不乱码）；统计与日志走 stderr，不污染 CSV。

## 9. 非功能目标

| 项 | 目标 |
|---|---|
| 启动 | JVM 启动后 < 1s 进入扫描 |
| 依赖 | 运行时依赖 ≤ 3；shade 单 JAR |
| 内存 | < 1 万类规模 4GB 堆内完成；字符串驻留、JDK 懒加载 |
| 容错 | 单类损坏/解析失败不中断，计入诊断 |
| 可测性 | 每阶段纯逻辑单测；ASM 动态生成 fixture 字节码；commons-collections 3.2.1（test）集成 |

## 10. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M1 骨架 | Maven、shade、CLI、ASM 解析层、model | 扫 JAR 输出类/方法统计；损坏 class 隔离 |
| M2 CPG | 图、CFG、类层次、JDK 懒加载、反向索引 | CFG/Serializable 闭包单测通过 |
| M3 调用图+KS1 | CHA、反射/代理/lambda、YAML 规则、SINK/ENTRY 标记 | 合成 JAR 中 sink/entry 全部准确标记 |
| M4 KS2+黑板 | 反向污点、参数对齐、字段敏感、控制器 | 合成链检出；参数错位假链不报 |
| M5 链+CSV | 路径翻转、置信度、CSV 导出 | 输出符合第 8 节规范 |
| M6 验证 | 真实库集成、性能、README | commons-collections 检出已知链候选 |

## 11. 风险与应对

| 风险 | 应对 |
|---|---|
| 反向搜索组合爆炸 | 深度/数量上限、去环、worklist 合并 |
| 假链（参数错位） | 参数对齐强制约束 |
| CHA 虚调用噪音 | 置信度降级、unresolved 标记、后续 RTA |
| 反射/代理/lambda 漏报 | 覆盖常见模式；UNKNOWN 标记而非判 clean |
| 正则规则过宽 → 假 sink | owner+name+desc 结构匹配 + 锚定正则 + ruleId 归因 |
| 混淆 JAR | 类层次/字段/调用事实仍可用；诊断透明 |

## 12. 关键设计决策摘要

| 决策 | 理由 |
|---|---|
| 字节码唯一前端，反编译不进主链路 | 反编译产物不可靠、混淆下失效；字节码信息更精确 |
| 自研内存图，不用图数据库 | Neo4j 5.x 无嵌入模式；分析负载不适合事务库；Joern 亦弃用 Neo4j |
| 数据依赖边惰性计算 | 全量 PDG 体积爆炸；污点按需计算，TAINT 边留证据 |
| 最小依赖 + CSV 输出 | 轻量启动；CSV 便于下游处理与复核 |
| 黑板架构 + sink 驱动反向搜索 | sink 远少于 magic entry，反向天然剪枝；引擎插件化解耦 |
| KS1 高召回 / KS2 高精度 | 漏报不可补救，误报可被严格判定与置信度消化 |

## 13. 知识源扩展路线（调研自同类引擎）

| 候选知识源 | 借鉴 | 作用 | 计划 |
|---|---|---|---|
| **KS3 链可行性验证 PASM-lite（已实现）** | Gadget Inspector 的 PASM（Partial Assembly，类型约束装配） | 沿链逐跳验证运行时类型约束：字段声明类型、调用 owner 兼容性、虚分发目标可达性、sink 参数兼容；不满足即拒绝（REJECT 校准），剔"纸上链" | v0.1 ✓ |
| **KS4 前向对象污点引擎（已实现）** | Gadget Inspector 前向两段式（方法摘要 + 事实不动点） | 从 magic entry/OIS 正向传播"反序列化对象"污点，不逐调用点枚举；补齐反向引擎在接口扇出处的命中能力 | v0.1 ✓ |
| KS5 分配点敏感（轻量指针分析） | tabby（Soot points-to） | 区分同字段不同实例，消除字段碰撞假链 | v0.2 |
| KS6 反射/代理/lambda 按需解析 | CodeQL models-as-data | 反向遇反射/代理/indy 时向黑板提需求，解析后重新投递（EDGE_ADDED 反馈环） | v0.2 |

**KS3 PASM 校验规则（保守，只拒绝可证明不可能的链）：**

```text
沿链（entry→sink）维护当前值的可能运行时类型集：
1. FIELD_FLOW(f)：类型集 ← 各可能 owner 类型的 f 字段声明类型（字段类型 Object 等宽类型视为任意）
2. DIRECT_CALL/VIRTUAL_DISPATCH(A.m→B.n)：接收者类型集须有子类型于 A，且 resolveMethod 结果为 B；
   否则拒绝（类型不兼容/分发不可达）；之后类型集 ← m 的返回类型
3. LAMBDA：跳过（未知通过）
4. 终局：sink 参数类型须兼容当前类型集，否则拒绝
```

拒绝理由写入黑板校准（chainCalibrations），报告层过滤被拒绝的链。

**置信度评分规范（证据化，逐条可复核）：**

```text
score = Σ(逐跳证据) + entry 权重 + 严重度加成 - unresolved × 2
逐跳：DIRECT_CALL +1；FIELD_FLOW +1（含字段名证据）；VIRTUAL_DISPATCH 0；LAMBDA 0
entry：readObject/readResolve/readObjectNoData/readExternal/hashCode/proxyInvoke +2；
       equals/compareTo/compare/toString/finalize +1；deserialization（OIS 源）+1
严重度：HIGH +1
分桶：score ≥ 5 → HIGH；≥ 3 → MEDIUM；否则 LOW
```

findings.csv 按 confidence_score 降序输出（高证据链置顶）；分类 = entry_kind + sink category。

## 13. 知识源扩展路线（调研自同类引擎）

| 候选知识源 | 借鉴 | 作用 | 计划 |
|---|---|---|---|
| KS3 链可行性验证（PASM-lite） | Gadget Inspector 的 PASM（Partial Assembly，类型约束模拟） | 校验链上每跳的运行时类型约束（字段声明类型、方法参数类型、if 条件），剔除"纸上链" | v0.2 |

KS3 接口草图：

```java
/** 链可行性验证：消费 CHAIN_FOUND，按类型约束过滤并写 CALIBRATED 事件。 */
public interface KnowledgeSource {
    String id();
    Set<EventType> interests();
    void init(Blackboard bb);
    void onEvent(Blackboard bb, Event event);
}
```

插件约定（新增知识源三步）：实现接口 → 写入
`META-INF/services/io.just.sast.blackboard.KnowledgeSource` → 回归测试。
内置 KS 位于 `io.just.sast.knowledge.ks1`（模式匹配）、`io.just.sast.knowledge.ks2`（反向污点）、
`io.just.sast.knowledge.ks3`（PASM 链可行性验证）、`io.just.sast.knowledge.ks4`（前向对象污点）。
