# Just — 架构设计

## 1. 项目目标与约束

- 轻量 Java SAST：对**闭源 JAR/WAR** 做 **Java 原生反序列化（ObjectInputStream）gadget 链挖掘**。
- 交付：**单个可运行 JAR**（shade 打包），CLI 使用，CSV 导出（findings/edges/sinks），默认输出目录 `just-out`。
- 运行时依赖仅三类：ASM（asm + asm-tree）、picocli、SnakeYAML。
- 启动快：无 DI、无服务、无重型初始化。
- 低耦合高内聚：黑板架构，知识源只通过黑板通信；ASM 隔离在 frontend 层。
- JDK 17 编译运行（release 17），单 Maven 模块。
- **普适优化红线**：生产代码不得出现针对特定 benchmark 类名/路径的特判；一切优化必须是通用语义修复。

**核心流程：**

```text
JAR/WAR → ASM 前端解析 → 类层次/CPG/调用图（构建期，一次完成并冻结）
        → 黑板两阶段分析（ANALYSIS → CALIBRATION，串行）→ CSV 报告
```

## 2. 总体架构（黑板架构）

```text
┌─────────────────────────────────────────────────────────────────────┐
│  cli         参数解析、管线编排、退出码、日志(stderr)                    │
├─────────────────────────────────────────────────────────────────────┤
│  config      规则模型与 YAML 加载（SnakeYAML）、规则匹配引擎             │
├─────────────────────────────────────────────────────────────────────┤
│  ╔══════════════ 黑板（Blackboard）= CPG + 分析产物 ═════════════════╗ │
│  ║ 图：METHOD/CALL 节点 + INVOKES/DISPATCHES/LAMBDA 调用边（冻结只读） ║ │
│  ║ 产物：sink/entry 标记、sink 裁决、链、链校准、质量注释               ║ │
│  ║ 共享设施：过程内 origin 分析缓存（ForwardOrigins，全 KS 复用）       ║ │
│  ╚═════════════════════════════════════════════════════════════════╝ │
├─────────────────────────────────────────────────────────────────────┤
│  知识源（插件式，互不直接调用，仅读写黑板）                              │
│  KS1 模式匹配（高召回预筛）   KS2 反向污点（精度闸门）                   │
│  KS4 前向对象污点（粗扫）     KS5 前向对象污点（接口/代理/反射精扫）      │
│  KS6 反序列化回调（OIS 类解析回调建模）                                 │
│  KS7 对象图入口扩散（COMPOSITION 阶段：字段类型回调重根产新链）           │
│  KS3 可行性 / KS8 类型流 / KS9 序列化 / KS10 触发 / KS11 去重（CALIBRATION）│
├─────────────────────────────────────────────────────────────────────┤
│  控制器：串行三阶段调度（ANALYSIS → COMPOSITION → CALIBRATION）          │
├─────────────────────────────────────────────────────────────────────┤
│  chain       置信度评分                                              │
│  report      CSV 三表 + 控制台摘要（stderr）                           │
└─────────────────────────────────────────────────────────────────────┘
```

**依赖方向（单向）：**

```text
cli → {config, frontend, cpg, analysis, blackboard, chain, report}
blackboard → {analysis.taint, analysis.hierarchy, cpg, config}
knowledge.ks1..ksN → {blackboard, config, analysis.taint, model, cpg}
knowledge.engine（前向污点引擎库，KS4/KS5 共用）→ {blackboard, config, analysis.taint, model, cpg}
frontend → model（实现 model 层的 JdkClassSource SPI，供类层次懒加载 JDK 类）
```

**耦合规则：**

- 仅 `frontend` 层允许 `import org.objectweb.asm.*`。
- 知识源之间零直接调用、零跨 ks 包 import；共用引擎代码放 `analysis.taint` 共享层。
- 分析层不感知 CLI、不写文件。
- 单线程契约：控制器串行调度，知识源与其内部缓存无需线程安全。

## 3. 知识源插件化

```java
public interface KnowledgeSource {
    /** 唯一标识，如 "pattern" / "backward-taint"。 */
    String id();
    /** 声明关心的事件类型。 */
    Set<EventType> interests();
    /** 执行阶段：ANALYSIS（产出分析）/ CALIBRATION（校准他者产物），默认 ANALYSIS。 */
    default Phase phase() { return Phase.ANALYSIS; }
    /** 一次性初始化（规则编译、索引准备）。异常由控制器隔离，不中断其他 KS。 */
    void init(Blackboard blackboard);
    /** 响应黑板事件；只读写黑板，不直接调用其他知识源。 */
    void onEvent(Blackboard blackboard, Event event);
}
```

**知识源契约（扩展点即以下四条）：**

1. **输入只读**：`graph()/hierarchy()/rules()/fieldWriters()/origins()` 是静态输入（构建期冻结或只增缓存）。
2. **ANALYSIS 阶段自足**：需要 sink/magic-entry 判定时用 `RuleEngine` 按规则自行匹配（含 owner 层次解析），**不读其他 KS 的标记产物**——KS 之间无运行顺序依赖。
3. **输出只写自己的产物**：`markSink/markMagicEntry`（KS1）、`recordOutcome/addChain`（裁决引擎）、`calibrateChain`（校准引擎）。
4. `id` 唯一；声明 `interests()` 与 `phase()`。

**注册（单轨 ServiceLoader）**：内置 KS 与第三方插件统一经
`META-INF/services/io.just.sast.blackboard.KnowledgeSource` 注册，无硬编码列表；
重复 id 丢弃并告警。内置顺序即文件行序（ks1 → ks2 → ks4 → ks5 → ks3）。

## 4. 核心数据模型

### 4.1 字节码事实（model 层，ASM 解析产物，不依赖 ASM）

```java
record ClassInfo(String internalName, String superName, List<String> interfaces,
                 int access, List<MethodInfo> methods, List<FieldInfo> fields) {}
record MethodInfo(String owner, String name, String descriptor, int access,
                  List<InsnFact> instructions, List<TryCatchFact> tryCatch,
                  boolean hasLineNumbers) {}
record FieldInfo(String owner, String name, String descriptor, int access) {}
record InsnFact(int offset, Op op, List<Object> operands) {}
// operands：调用 → (owner, name, desc)；LDC → 常量值；字段 → FieldRef；等
// Op 为封闭枚举：加载/存储/算术/调用/跳转/switch/异常/栈操作等
```

### 4.2 CPG：两类节点 + 调用边（构建期物化，随后冻结）

| 节点 | 关键属性 |
|---|---|
| `METHOD` | owner, name, descriptor, access |
| `CALL` | owner, name, descriptor, invokeKind, 所在方法与 offset |

| 边 | from → to | 用途 |
|---|---|---|
| `INVOKES` | CALL → METHOD | 静态/特殊调用（含 super 与构造器） |
| `DISPATCHES` | CALL → METHOD | 虚/接口调用 CHA 候选（一点多边，有上限） |
| `LAMBDA` | CALL → METHOD | invokedynamic 引导方法解析目标 |

反射与动态代理**不建图边**（不可静态枚举），由 KS5 前向引擎按需展开（见 6.5）；
不可解析的外部调用以节点属性标记（external），参与置信度惩罚。

### 4.3 惰性 CFG

CPG 不物化控制流。`Cfg.compute(method)` 按需产出指令级边：
`{SEQ, FALSE, JUMP, EXCEPTION}`；异常边对 try 范围内每个 offset 连向 handler，
是 origin 分析实现"进 handler 清栈压异常对象"的依据（见 6.2）。

### 4.4 索引

| 索引 | 内容 |
|---|---|
| `FieldWriterIndex` | (class, field) → PUTFIELD 指令集合（KS2 字段写入者回溯） |
| `Graph` 内部 | METHOD 按 (owner,name,desc) 索引、节点类型索引 |
| `Blackboard.origins()` | 共享 ForwardOrigins 缓存：method → 过程内 origin 分析结果，KS2/KS4/KS5 复用同一份 |

## 5. 分析流水线

### 5.1 构建期（一次性，完成后图冻结）

```text
FRONTEND   目标 JAR/WAR + 依赖 JAR（fat jar BOOT-INF 递归）→ ASM 解析 → ClassInfo 集合
           深度模式（默认）额外全量解析 JDK 运行库模块（java.base/naming/rmi/management/scripting/sql）
           单类损坏/解析失败不中断，计入诊断；--fast 跳过 JDK 全量，保留懒加载
HIERARCHY  类层次 + JDK 懒加载（jrtfs）→ Serializable/Externalizable 闭包
CPG_BUILD  METHOD/CALL 节点 + 调用边 + FieldWriterIndex → Graph.freeze()
CALLGRAPH  CHA 虚调用解析（DISPATCHES 多边）+ LAMBDA 解析
```

### 5.2 分析期（串行三阶段）

```text
SCAN_START 事件 → ANALYSIS 阶段：KS1、KS2、KS4、KS5、KS6 依次执行（顺序无关紧要，各自独立）

  KS1（模式匹配，高召回）：按 YAML 规则遍历 CALL/METHOD → 标记 SINK/MAGIC_ENTRY（供报告层）
  KS2（反向污点，精度闸门）：自行匹配 sink 规则 → 反向回溯"该位置是否攻击者可控"
      → 产链 + 每 sink 裁决（SinkOutcome）；双向剪枝（入口下游集）跳过可证明无链分支
  KS4（前向对象污点，粗扫）：magic entry/OIS 读为种子 → 对象污点事实不动点 → 命中 sink 产链
  KS5（前向精扫）：同引擎精化选项——接口实现展开、Proxy handler 串联、Method.invoke 常量解析
  KS6（反序列化回调）：OIS 机制类解析回调建模——自定义 resolveClass/resolveProxyClass 重写
      内由回调参数驱动的 sink 产链（见 6.6）

SCAN_ANALYZED 事件 → COMPOSITION 阶段：KS7 消费全部完整链，按对象图回调语义重根
  产新链（类 E 的字段可容纳 F 实例 → F 的回调入口链重根到 E 入口，见 6.7）

SCAN_COMPLETE 事件 → CALIBRATION 阶段（顺序：KS3 → KS8 → KS9 → KS10 → KS11）：
  KS3 链可行性（字段声明/方法可解析）；KS8 类型流（逐跳值类型相容，来源须 final 精确）；
  KS9 序列化可行性（序列化声明类的字段类型无可序列化子类闭包则不可能）；
  KS10 触发上下文（非机制调用的入口类别须有下游集内触发者）；
  KS11 机制去重（同机制尾只留 3 条代表）；均只拒绝可证明不可能/纯重复者
```

两阶段即黑板调度的全部协议：ANALYSIS 产物 → CALIBRATION 校准 → 报告。
不存在反馈重调度；CHAIN_FOUND 事件保留给未来插件消费。

### 5.3 报告期

```text
链整理（entry→sink 顺序）→ KS3 拒绝链过滤 → 去重折叠（entry,sink,category）
→ 置信度评分 → CSV 三表 + 控制台摘要
```

## 6. 关键算法

### 6.1 类层次与 JDK 懒加载

- 全量解析目标 + 依赖；JDK 类按需从运行镜像（jrtfs）提取单 class 并缓存。
- Serializable/Externalizable 传递闭包判定，结果缓存。
- JDK 类参与调用图与污点分析（真实链必经 HashMap/PriorityQueue 等）。
- 懒加载向层次追加新子类型时，子类型/方法解析/接口实现三类缓存失效重建。

### 6.2 过程内 origin 分析（ForwardOrigins，共享缓存）

每个方法做一次符号栈模拟，产出"每个 offset 前的栈/局部变量来源集合
（ValueOrigin: Param/Insn/CallResult/FieldRead/Constant/Unknown）"，KS2/KS4/KS5 共享。

**栈语义（对齐 JVM 规范，此为精度根基）：**

- 栈条目 `(origins, cat2)`：long/double 为 category-2 单条目；
  `POP2` 顶部 cat-2 弹 1 否则弹 2；`DUP2/DUP2_X1/DUP2_X2` 按 cat-2 单值语义复制/插入。
- `TABLESWITCH/LOOKUPSWITCH` 弹出 key。
- **异常边**：沿 `EXCEPTION` 边进入 handler 时清空栈、压入单个异常对象（Unknown），
  locals 保留——handler 内 astore 不会误取 try 点业务值。
- `LSTORE/DSTORE` 同时清除占用槽与次槽的来源。
- 合并点栈高不一致时保守截断到公共高度并记质量诊断（解释器漂移的报警器）。

**参数语义（跨方法对齐的唯一口径）：**

- `ValueOrigin.Param(slot)` 的 slot 是**被调方法的局部变量槽**（receiver=0，wide 参数占 2 槽）。
- 消费端（KS2 回溯实参、KS4/KS5 passthrough）经 `Descriptor.paramOrdinal(desc, isStatic, slot)`
  转换为**参数序数**（receiver → -1），再按序数定位调用点栈上的实参：
  arg i 深度 = `paramCount - 1 - i`，receiver 深度 = `paramCount`。
  静态方法无 receiver；cat-2 实参与 cat-1 一样各占一个栈条目，序数即正确。

### 6.3 调用图（CHA 起步）

- `INVOKESTATIC/INVOKESPECIAL` 定目标；`INVOKEVIRTUAL/INVOKEINTERFACE` CHA
  在声明类型的子类闭包中找实现（DISPATCHES 多边，每调用点有候选上限）。
- Lambda：`invokedynamic` bootstrap 参数解析 implMethod → LAMBDA 边。
- 反射/代理不建边：KS5 精扫在污点命中此类调用时按需展开（见 6.5）。

### 6.4 反向污点（KS2，精度闸门）

**问题形式**：sink 调用点第 i 个参数（或 receiver）需要污点 → 反向回溯谁使其可控 → 直至触及 magic entry。
**上下文敏感性**：上下文不敏感（所有调用点合并），靠预算、去环与 KS3 校准控制噪声。
**调用点收集**：方法自身入边为空时（接口实现数超 CHA 枚举上限、分发边未物化的实现类），
并入祖先类型（传递接口/父类链）上同名同描述符方法的调用点（上限独立控制）——与前向引擎的
接口反向分发同款语义，打通 `JsonSerializer.serialize → BeanSerializer.serialize` 这类接口枢纽。

| controlled 语义 | 规则 |
|---|---|
| OIS 读（readObject/readUnshared/readFields） | 无条件可控（反序列化数据源） |
| magic entry 的 this | 可控（反序列化构造的对象图根） |
| proxy 入口（InvocationHandler.invoke）的 args | 可控（当 handler 类可序列化） |
| 可控对象的方法返回值 | 可控（receiver 语义，GadgetInspector 式对象污点） |
| 可控实参 → passthrough 返回值 | 可控（保守） |
| 可控值写入的字段 / 数组元素 | 可控（FieldWriterIndex / arrayElements 回溯） |
| 常量 | 不可控，终止 |

**终止与防爆**：回溯深度上限（20）；同一方法内去环；全局步数预算；
死胡同记忆化（预算尾部截断不入缓存，防假阴污染）；每 sink 候选链上限。

### 6.5 前向对象污点（KS4 粗扫 / KS5 精扫，共用引擎，选项区分）

GadgetInspector 式两段：先算方法摘要（origin 分析），再以对象污点事实做不动点。

```text
事实：thisTainted(类) / paramTainted(方法,槽) / fieldTainted(类,字段) / returnTainted(方法)
种子：magic entry 的 this；OIS 读所在类
传播：receiver 可控 → 返回值可控；可控值 PUTFIELD → 字段污点；可控 RETURN → 返回污点；
      类级 this 污点向子类型传播（保守）；字段读回退到声明类 this 污点（保守）
静态方法：首参不吃类级 this 污点（无 receiver）
KS5 精化选项：
  1. 接口展开：污点命中接口调用且边未物化实现时按上限展开实现类
  2. 代理串联：receiver 为 Proxy.newProxyInstance 结果时，污点传给 handler 类
  3. 反射解析：Method.invoke 的 Method 对象来自 getMethod/getDeclaredMethod 常量名时解析目标
  4. 可达剪枝：仅 magic entry/OIS 可达子图内传播（粗扫亦默认开启）
```

以上保守近似（passthrough、类级污点、子类型传播）是有意的召回取舍，
由 KS3 校准与置信度分桶消化假阳。

### 6.6 反序列化回调（KS6 ois-callback，ANALYSIS）

领域语义建模（与"OIS 读结果无条件可控"、proxyInvoke 入口同族的威胁模型假设）：
**readObject/readUnshared 执行期间，OIS 机制会以攻击者可控的参数同步回调流对象的类解析方法**
——自定义 ObjectInputStream 子类重写的 `resolveClass(ObjectStreamClass)` /
`resolveProxyClass(Class[])`（流数据里的类描述符由攻击者决定）。

```text
1. 发现重写类：loadedSubtypes(java/io/ObjectInputStream) 中 resolveMethod 指向子类自身者
2. 确证污点：重写方法内规则命中的 sink（forName/loadClass/defineClass 等），其污点位置来源
   须由回调参数（desc，slot 1）直接或经一层调用（如 desc.getName()）派生——常量参数不报
3. 机制路径：调用图上从 java/io/ObjectInputStream.readObject 到重写方法的有界 BFS（机制跳全部真实存在）
4. 链组装：入口取 OIS 宿主方法的最近 magic-entry 祖先（有界上溯；无则记 deserialization 源）
   → 宿主调用 readObject 跳 → 机制路径跳 → sink；受宿主数与总链数上限约束
```

该知识源补足前向/反向引擎在"机制内部数据流"（流字节 → 类描述符 → resolveClass）上的盲区：
值污点模型无法表达"机制以流内容为参数回调"，正如代理需要 proxyInvoke 建模一样。

### 6.7 对象图入口扩散（KS7 object-graph，COMPOSITION）

反序列化机制按**对象图**递归触发字段类型的反序列化回调：类 E 的非 transient 字段
声明类型 T，攻击者可在其中放置任意可序列化的 T 子类型 F 实例 → F 的回调入口方法
在 E 反序列化期间被机制调用。这是默认反序列化填充字段的语义——不经任何显式调用边，
前向/反向引擎均不可见，本源补足。

```text
1. 容器索引：Serializable 类的非 transient/static 引用字段，按声明类型 T 索引
2. 可重根链：入口类别为机制直接调用者——readObject/readObjectNoData/readExternal；
   validateObject 仅当该类 readObject 体内有 OIS.registerValidation 调用（机制语义核验）
3. 重根：F 的入口链 → 去入口自跳 → 字段跳（E 的入口 --[field]--> F 入口，reason=object-graph）
   → E 的入口跳；要求 E 自身有回调入口方法、防环、总跳数/每链/总数上限
4. 声明类型取 F 的祖先闭包（父类链+传递接口）——祖先类型的容器字段均可容纳 F
```

产出为**新的 entry→sink 覆盖**（E 无直接链时此前不可见），KS3/KS8/KS9 照常校准。

### 6.8 类型流校准（KS8 typeflow，CALIBRATION）

逐跳值类型相容性校验（借鉴 FLASH/JDD 的精确化思路，保守实现——只拒可证明不兼容）：

```text
对带槽位信息的调用跳：形参类型 P = paramType(desc, ordinal(slot))
值来源类型 T（沿链向入口方向取上一跳）：
  - FIELD_FLOW(f) 跳 → 字段声明类型
  - 调用跳 → 其形参类型（参数链逐级传递）
  - ENTRY 跳 → 入口类名
T 与 P 双方可解析且 T 不是 P 的子类型（isSubtypeOf）→ 拒绝（reason=typeflow）
任一方不可解析 / Object 形参 / 无槽位信息 → 保守通过
```

典型收割：CHA 宽分发把 String 字段流进 Comparator/Transformer 形参的"纸上链"。

### 6.8b 序列化可行性校准（KS9 serialize-feasibility，CALIBRATION）

借鉴 JDD 可利用性验证的静态可判定子集（Java 序列化规范：写端要生成载荷，
非 transient 字段的运行时值类型必须可序列化）：

```text
链上 FIELD_FLOW 涉及字段（非 transient）的声明类型 T：
T 可解析 && T 自身与已加载子类型闭包中均无 Serializable → 链物理不可能，拒绝
（如 Runtime 型字段：无任何可序列化子类）
Object 型字段天然通行（存在大量可序列化子类型）；transient 字段不拒
（自定义 readObject 可显式赋值，仍可由流数据驱动）
```

### 6.9 触发上下文校准（KS10 trigger-context，CALIBRATION）

hashCode/equals/compareTo/compare/toString 五类入口**不被 OIS 机制自动调用**（区别于
readObject 族与 proxyInvoke）——链要成立，必须有**反序列化可达的调用者**触发入口方法
（如 HashMap.readObject → hash(key) → key.hashCode、TreeMap.readObject → compare、
BadAttributeValueExpException.readObject → val.toString）。KS4/KS5 的前向链未验证
触发存在性；KS10 补足：

```text
入口类别 ∈ {hashCode, equals, compareTo, compare, toString} 的链：
入口方法在"入口/OIS 宿主下游集"（含字段中介边，与 KS2 剪枝集同构）内无任何调用者
→ 该链不可能在反序列化过程中触发，拒绝（reason=no-trigger）
其余入口类别（readObject 族/proxyInvoke/deserialization 等机制调用者）不校验
```

### 6.10 链校验（KS3 PASM-lite，CALIBRATION）

保守校验，只拒绝**可证明不可能**的链（逐跳独立，不做全局类型游走）：

```text
1. FIELD_FLOW(f)：字段 f 声明于 fromOwner 或其父类（父类链全部可解析时才允许拒绝，否则保守通过）
2. 调用跳：目标方法在 toOwner 上可解析（类可解析时才允许拒绝）
3. LAMBDA / 无描述符 / 类不可解析：保守通过
```

拒绝理由写入黑板校准表，报告层过滤。

### 6.7 链提取与置信度

```text
Chain := Entry(magic entry) → hop1 → ... → Sink(call)
去重键：entry + sink + 有序中间方法；报告层再按 (entry, sink, category) 折叠变体

score = Σ(逐跳证据) + entry 权重 + 严重度加成 - unresolved × 2
逐跳：DIRECT_CALL +1；FIELD_FLOW +1；VIRTUAL_DISPATCH/LAMBDA/ENTRY 0
entry：readObject/readResolve/readObjectNoData/readExternal/hashCode/proxyInvoke/deserialization 强 +2；
       equals/compareTo/compare/toString/finalize +1
严重度：HIGH +1
分桶：score ≥ 5 → HIGH；≥ 3 → MEDIUM；否则 LOW
```

findings.csv 按 confidence_score 降序、链长、变体数排序输出。

### 6.11 序列化框架桥接（KS12 serialize-bridge，ANALYSIS）

领域建模（与 OIS 回调建模同族）：当 magic-entry 方法调用序列化框架的"对象→字符串"入口
（jackson/gson/fastjson/XStream 等），序列化管线以**反射调用 getter/setter**（Method.invoke）
来获取/写入字段——被序列化对象上的**任何 getter** 都成为攻击面（getter 内可执行任意逻辑，
如 TemplatesImpl.getOutputProperties 加载字节码）。

```text
1. 框架入口识别（内置声明式清单，可经 YAML 扩展）：
   jackson:   ObjectMapper/ObjectWriter.writeValueAsString/AsBytes/Value
   fastjson1/2: JSON.toJSONString/toJSONBytes/writeJSONString, JSONObject/JSONArray.toString/toJSONString
   gson:      Gson.toJson
   XStream:   XStream.toXML
   snakeyaml: Yaml.dump
   ...
2. 桥接条件：
   a) magic-entry 方法（toString/readObject/hashCode/equals/proxyInvoke 等）体内调用框架入口
   b) 框架管线终点存在 Method.invoke sink（BeanPropertyWriter.serializeAsField 等）
   c) sink 的 receiver/arg0 来源可追溯到被序列化对象（框架入口的 arg0）
3. 产链：entry → ... → 框架入口调用跳（reason=serialize-bridge）→ 管线关键跳 → Method.invoke sink
   管线路径取调用图 BFS（只取调用边，不用污点传播——管线本身是框架内部，污点经过它不衰减）
```

典型收获：jackson `BaseJsonNode.toString → InternalNodeMapper → ObjectWriter.writeValueAsString
→ BeanPropertyWriter.serializeAsField → Method.invoke`（n1cat 完整链的内层缺失段）。

### 6.12 JDK 版本感知（前端 + CLI）

当前工具用运行时 JVM 的 jrt 文件系统（JDK 17）作为 JDK 运行库——若目标 jar 编译目标为
Java 8（major 52），而运行时为 JDK 17，可能出现：
- 假阳：JDK 8 无而 17 有的方法被当作可达
- 假阴：JDK 8 有而 17 已移除/签名变更的方法被判定不可解析

```text
前端改进：ClassFileReader 解析时提取 class 文件 major version（前 8 字节偏移 6-7），
LoadResult 汇总 targetMajorVersion（取最大值）。
CLI 日志：报告目标 JDK 版本与运行时 JDK 版本，差异时打 WARN。
```

### 6.13 机制去重校准（KS11 mechanism-dedup，CALIBRATION）

同一"机制尾"（sink + 类别 + 去首跳的路径签名）的多入口链只保留 K=3 条代表
（未解析少 → 链短 → 证据分高择优），其余以 mechanism-duplicate 拒绝。
动机：KS6/KS7 的"任意入口 × 同一机制"笛卡尔积对人工审阅是纯噪音——
分析者需要每行一个不同机制，而非同一机制的数百个入口变体。

### 6.14 黑板调度协议

```text
事件：SCAN_START / SCAN_ANALYZED / SCAN_COMPLETE / CHAIN_FOUND（addChain 时发布，当前无内置订阅者，留作扩展点）
控制器：FIFO 串行分发；ANALYSIS → COMPOSITION → CALIBRATION 三阶段依次推进，
        前一阶段全部完成后才发布下一阶段事件；init/onEvent 异常按 KS 隔离（含 Error），不中断全扫
CALIBRATION 内顺序：KS3（可行性）→ KS8（类型流）→ KS9（序列化可行性）→ KS10（触发上下文）
        → KS11（机制去重）——先精化后去重，保证保留的是每组最优代表
```

## 7. 规则系统（YAML）

规则 = 声明式模型：`sink`（链终点危险调用）、`magic-entry`（链起点反序列化触发方法）。
**规则清单以 `src/main/resources/rules/default-rules.yaml` 为唯一事实源，本文档不复制清单。**

```yaml
rules:
  - id: JUST-SINK-JNDI-LOOKUP
    kind: sink
    category: JNDI
    severity: HIGH
    match:
      call: { owner: "javax/naming/Context", name: ~"lookup|list|bind", descriptor: "(Ljava/lang/String;)Ljava/lang/Object;" }
      tainted: [{arg: 0}]

  - id: JUST-ENTRY-READOBJECT
    kind: magic-entry
    match:
      method: { name: "readObject", descriptor: "(Ljava/io/ObjectInputStream;)V" }
      implements: "java/io/Serializable"
```

**匹配语义（结构匹配优先，防误报）：**

- `owner/name/descriptor` 支持字面量与 `~` 前缀的**锚定正则**（构造期强制 `^(?:...)$`）。
- **sink owner 层次匹配**：调用点 owner 为规则 owner 的子类型或实现类时同样命中
  （`InitialContext().lookup(...)` 命中 `javax/naming/Context` 规则；子类 loader 的
  `defineClass` 命中 `java/lang/ClassLoader` 规则）。
- magic-entry 的 `implements` 同样按类层次闭包校验。
- `tainted` 声明需要污点的位置：`{arg: n}`（0 基）或 `{receiver: true}`。
- 每条链携带出发 sink 的 `rule_id` → 假链可归因到具体规则，改 YAML 即可修复，引擎不动。

**分工原则**：KS1 高召回（漏真 sink 无法补救），KS2/KS4/KS5 严格判定消化噪声，
置信度按路径证据定级。

## 8. CSV 报告

三表（RFC 4180 转义；UTF-8 with BOM；CRLF；统计与日志走 stderr）：

- **findings.csv**：一条链一行（entry → sink 顺序），含 rule_id/category/severity/
  confidence(HIGH/MEDIUM/LOW)/confidence_score/variant_count/entry/sink/path/evidence 等列，
  按置信度降序。**列清单以 `CsvReporter` 表头为唯一事实源。**
- **edges.csv**：链每跳明细（chain_id, step, from/to 类与方法, edge_kind, field, reason）；
  edge_kind ∈ {DIRECT_CALL, VIRTUAL_DISPATCH, LAMBDA, FIELD_FLOW, ENTRY}。
- **sinks.csv**：每个 sink 的裁决（KS2 verdict、产链数、步数、unresolved 等）。

KS3 拒绝的链不出现在 findings.csv，其拒绝理由与计数在控制台摘要可见。

## 9. 非功能目标

| 项 | 目标 |
|---|---|
| 启动 | JVM 启动后 < 1s 进入扫描 |
| 依赖 | 运行时依赖 ≤ 3；shade 单 JAR |
| 内存 | < 1 万类规模 4GB 堆内完成；origin 分析全 KS 共享单份缓存；死胡同缓存按代清理 |
| 容错 | 单类损坏/解析失败不中断，计入诊断；单 KS 异常隔离 |
| 可测性 | 每阶段纯逻辑单测；ASM 动态生成 fixture 字节码（合成正例/负例）；本地 benchmark jar 回归（不入库） |

## 10. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| M1 骨架 | Maven、shade、CLI、ASM 解析层、model | 扫 JAR 输出类/方法统计；损坏 class 隔离 |
| M2 CPG | 图、惰性 CFG、类层次、JDK 懒加载、字段索引 | CFG/Serializable 闭包单测通过 |
| M3 调用图+KS1 | CHA、LAMBDA、YAML 规则（含 owner 层次匹配）、标记 | 合成 JAR 中 sink/entry 全部准确标记 |
| M4 KS2+黑板 | 反向污点、参数对齐、串行两阶段控制器 | 合成链检出；参数错位假链不报；校准阶段拒绝链不报 |
| M5 链+CSV | 链提取、置信度、CSV 三表 | 输出符合第 8 节规范 |
| M6 回归 | 本地 benchmark（demo 系、javamix、n1cat） | 已知链检出、已知负例不报、耗时在档 |

## 11. 风险与应对

| 风险 | 应对 |
|---|---|
| 自研 origin 解释器语义漂移 | 合并点栈高诊断报警；switch/异常边/cat-2 合成回归矩阵（正例+负例） |
| 反向搜索组合爆炸 | 深度/步数/数量上限、去环、死胡同记忆化、可达剪枝 |
| 假链（参数错位） | paramOrdinal 统一对齐口径；KS3 校准；置信度惩罚 |
| CHA 虚调用噪音 | DISPATCHES 候选上限、unresolved 惩罚、置信度降级 |
| 保守近似假阳（passthrough/类级污点） | KS3 只砍可证伪链，剩余按证据分桶交人工分诊 |
| 正则规则过宽 → 假 sink | owner+name+desc 结构匹配 + 锚定正则 + rule_id 归因 |
| 混淆 JAR | 类层次/字段/调用事实仍可用；诊断透明 |

## 12. 关键设计决策摘要

| 决策 | 理由 |
|---|---|
| 字节码唯一前端，反编译不进主链路 | 反编译产物不可靠、混淆下失效；字节码信息更精确 |
| 自研轻量 origin 解释器（非 Soot） | 轻量+快；代价是 JVM 栈语义合规自担，用合成矩阵+栈高诊断兜底 |
| 自研内存图，不用图数据库 | 分析负载不适合事务库；Joern/Neo4j 过重 |
| 串行两阶段（ANALYSIS → CALIBRATION），不做并行 | 准确性与可调试性优先；KS 无顺序依赖后并行只是 Controller 小改，留待有实测收益再议 |
| origin 分析共享单份缓存 | 消除三引擎重复计算与三倍内存；共享是普适优化非特判 |
| 黑板架构 + sink 驱动反向 + entry 驱动前向 | 双向互补召回；引擎插件化解耦 |
| 规则清单/CSV 列表只在代码与 YAML 中维护，文档指向事实源 | 杜绝文档快照漂移（此前 13≠17、16≠18 列的教训） |

## 13. 知识源扩展路线

| 知识源 | 借鉴 | 状态 |
|---|---|---|
| KS1 模式匹配 | tabby 规则驱动 | v0.1 ✓ |
| KS2 反向污点 | 参数对齐 + 字段敏感 + 双向剪枝 | v0.1 ✓ |
| KS3 链可行性校验（PASM-lite） | GadgetInspector PASM | v0.1 ✓（CALIBRATION 阶段） |
| KS4 前向对象污点（粗扫） | GadgetInspector 两段式 | v0.1 ✓ |
| KS5 接口/代理/反射精扫 | tabby 对象图、GI 补全 | v0.1 ✓ |
| KS6 反序列化回调（ois-callback） | OIS 机制类解析回调建模（marshalsec/GI 领域知识） | v0.2 ✓ |
| KS7 对象图入口扩散（object-graph） | 反序列化对象图回调语义（GI 对象图 + 机制触发面）：字段类型回调重根产新链 | v0.2 ✓（COMPOSITION 阶段） |
| KS8 类型流校准（typeflow） | FLASH/JDD 精确化：逐跳值类型相容性，只拒可证明不兼容 | v0.2 ✓（CALIBRATION 阶段） |
| KS9 序列化可行性校准（serialize-feasibility） | JDD 可利用性验证的静态子集：字段类型无可序列化子类闭包则链不可能 | v0.2 ✓（CALIBRATION 阶段） |
| KS10 触发上下文校准（trigger-context） | GI topLevel 语义：hashCode/equals/compareTo/compare/toString 须有反序列化可达触发者 | v0.2 ✓（CALIBRATION 阶段） |
| KS11 机制去重校准（mechanism-dedup） | 人工审阅友好：同机制尾只留 K 条代表，消解入口×机制笛卡尔积噪音 | v0.2 ✓（CALIBRATION 阶段） |
| KS12 序列化框架桥接（serialize-bridge） | n1cat/GI 领域：toString/readObject 调用 jackson/gson/fastjson 序列化时，getter 反射成为攻击面 | v0.2 ✓（ANALYSIS 阶段） |

新增知识源三步：实现 `KnowledgeSource`（声明 phase 与 interests）→
写入 `META-INF/services/io.just.sast.blackboard.KnowledgeSource` → 补契约测试与 benchmark 回归。
内置 KS 位于 `io.just.sast.knowledge.ks1..ks9`；共享引擎库：过程内 origin 分析在 `io.just.sast.analysis.taint`（黑板构造分发），前向污点引擎在 `io.just.sast.knowledge.engine`。
