# Just — 架构设计

## 1. 项目目标

轻量字节码 SAST：对闭源 JAR/WAR 挖掘 Java 反序列化 gadget 利用链。
覆盖原生 ObjectInputStream + Kryo/SnakeYAML/XStream/Hessian/Fastjson/Gson/Jackson 等替代框架。

- 交付：单个 CLI JAR（shade），CSV 三表输出，`--jdk-home` 支持目标 JDK 精确匹配
- 运行时依赖：ASM（asm + asm-tree）、picocli、SnakeYAML
- JDK 17（release 17），单 Maven 模块
- **普适优化红线**：生产代码不得针对特定 benchmark 特判

## 2. 总体架构

```text
JAR/WAR → ASM 前端（fat jar/WAR 嵌套 + JDK[--jdk-home 可选版本]）
  → CPG（传递子类型分发 + 惰性 CFG + CHA 调用图，构建后冻结）
  → 黑板三阶段调度（10 个知识源）
      ANALYSIS:     反向污点 | 前向对象污点 | OIS 回调 | 规则驱动框架桥接
      COMPOSITION:  对象图入口扩散 | 语义链组装
      CALIBRATION:  链校验 | 链剪枝 | SafeConfig | 已知模式识别
  → 置信度排序 → CSV 三表
```

## 3. 知识源（10 个引擎）

| KS | 包 | 阶段 | 职责 |
|---|---|---|---|
| BackwardTaint | `backward` | ANALYSIS | 反向污点：从 sink 回答"是否攻击者可控" |
| ForwardTaint | `engine` | ANALYSIS | 前向对象污点（粗扫+精扫，GadgetInspector 式两段） |
| OisCallback | `ois` | ANALYSIS | OIS resolveClass/resolveProxyClass 回调建模 |
| FrameworkBridge | `framework` | ANALYSIS | 规则驱动框架桥接（从 YAML 读框架清单，零硬编码） |
| ObjectGraph | `objectgraph` | COMPOSITION | 对象图入口扩散（字段类型回调重根产新链） |
| ChainComposer | `compose` | COMPOSITION | 语义链组装（INVOKE/TRIGGER/TEMPLATE 桥接多级链） |
| ChainValidator | `calibrate` | CALIBRATION | 链校验：PASM 可行性 + 类型流 + 序列化可行性 |
| ChainPruner | `calibrate` | CALIBRATION | 链剪枝：触发上下文 + 机制去重（入口家族） |
| SafeConfig | `calibrate` | CALIBRATION | 安全配置抑制（XStream 白名单/Kryo 注册等） |
| GadgetPattern | `calibrate` | CALIBRATION | 已知 gadget 模式识别（CC1-7/Spring/Rome/CB1） |

### 接口

```java
public interface KnowledgeSource {
    String id();
    Set<EventType> interests();
    default Phase phase() { return Phase.ANALYSIS; }
    void init(Blackboard blackboard);
    void onEvent(Blackboard blackboard, Event event);
}
```

### 契约

1. 输入只读：graph()/hierarchy()/rules()/originSupport() 是静态输入
2. ANALYSIS 阶段自足：用 RuleEngine 按规则匹配，不读其他 KS 产物
3. 输出只写自己的产物
4. COMPOSITION 阶段可消费完整链（其他 KS 的产物）
5. CALIBRATION 阶段校准/拒绝链

### 注册

ServiceLoader 单轨（META-INF/services），无硬编码列表。

## 4. 核心数据模型

### CPG（两类节点 + 调用边，构建后冻结）

| 节点 | 属性 |
|---|---|
| METHOD | owner, name, descriptor, access |
| CALL | owner, name, descriptor, invokeKind, offset |

| 边 | 用途 |
|---|---|
| INVOKES | 静态/特殊调用（SPECIAL 边用 resolveMethod 后的真实声明类） |
| DISPATCHES | 虚/接口调用 CHA 候选（**传递子类型闭包**，深继承链覆写方法同样获得边） |
| LAMBDA | invokedynamic → 实现方法 |

### 共享分析层（analysis.taint）

- **ForwardOrigins**：过程内符号栈模拟（cat-2 建模/异常边清栈/switch 弹 key），全 KS 共享缓存
- **OriginSupport**：调用点索引 + 方法解析缓存 + 跨方法实参定位（paramOrdinal 统一口径）

## 5. 规则系统（4 种类型，改 YAML 零代码）

| kind | 用途 | 数量 | 来源 |
|---|---|---|---|
| `sink` | 危险调用点 | 35+ | 自有 + tabby/GI/CodeQL（RCE/JNDI/SQLI/SSRF/File/模板注入） |
| `magic-entry` | OIS 反序列化入口 | 12 | 自有 |
| `source` | 替代反序列化框架入口 | 24 | CodeQL 16 框架 + 自有 |
| `model` | 声明式污点透传 | 10 | tabby actions 模式（Map.put/get 等） |

### 规则示例

```yaml
# sink
- id: JUST-SINK-JNDI-LOOKUP
  kind: sink
  category: JNDI
  severity: HIGH
  match:
    call: { owner: "javax/naming/Context", name: ~"lookup|list|bind" }
  tainted: [{arg: 0}]

# source（替代反序列化框架）
- id: JUST-SOURCE-KRYO
  kind: source
  bridge: deserialize
  match:
    call: { owner: "com/esotericsoftware/kryo/Kryo", name: ~"readClassAndObject|readObject" }

# model（声明式污点透传）
- id: MODEL-MAP-PUT
  kind: model
  match:
    call: { owner: "java/util/Map", name: "put" }
  actions: { this: [arg1] }   # value 污染整个 Map
```

## 6. 关键算法

### 6.1 反向污点（BackwardTaint，ANALYSIS）

从 sink 参数反向回溯可控性，直至触及 magic entry。

| controlled 语义 | 规则 |
|---|---|
| OIS 读 | 无条件可控 |
| magic entry 的 this | 可控 |
| proxy 入口的 args | 可控（handler 类可序列化时） |
| 可控 receiver 的返回值 | 可控 |
| 可控实参 → passthrough 返回值 | 可控（保守） |

- **双向剪枝**：入口/OIS 宿主下游集（含字段中介边）之外的调用者可证明无链，跳过
- **接口反向分发**：方法入边为空时并入祖先类型上同名方法的调用点
- **终止**：深度 20 / 全局步数 / 死胡同记忆化 / 每 sink 链数上限

### 6.2 前向对象污点（ForwardTaint，ANALYSIS）

GadgetInspector 式两段：方法摘要 + 对象污点事实不动点。

- 种子：magic entry 的 this / OIS 读所在类
- 传播：receiver 可控→返回值可控 / PUTFIELD→字段污点 / 子类型传播
- 精化（同引擎两轮）：接口展开 / Proxy 串联 / Method.invoke 常量解析 / 可达剪枝

### 6.3 OIS 回调（OisCallback，ANALYSIS）

readObject 期间 OIS 以攻击者可控参数回调 resolveClass/resolveProxyClass 重写。
管线 BFS 从 OIS.readObject 到重写方法（机制跳真实存在）。

### 6.4 框架桥接（FrameworkBridge，ANALYSIS）

从 YAML source 规则读框架清单，包前缀剪枝 BFS 从框架入口到反射 sink。
支持 serialize 方向（toString→getter 反射）和 deserialize 方向（load→构造器/setter 反射）。

### 6.5 对象图入口扩散（ObjectGraph，COMPOSITION）

类 E 的非 transient 字段声明类型 T → 攻击者可放置 T 的可序列化子类型 F 实例
→ F 的回调入口在 E 反序列化期间被调用 → F 的入口链重根到 E。

### 6.6 语义链组装（ChainComposer，COMPOSITION）

三种语义桥接将不同引擎产出的完整链组装成多级攻击路径：

| 桥接 | 条件 | 语义 |
|---|---|---|
| INVOKE | 前段 sink = Method.invoke，后段 entry 是公共方法 | Method.invoke 可调任意公共方法 |
| TRIGGER | 前段路径含 HashMap/HashSet/Hashtable/TreeMap，后段 entry 是 hashCode/toString | 反序列化容器调 key.hashCode/toString |
| TEMPLATE | 前段路径含 TemplatesImpl，后段 entry 是 getOutputProperties/newTransformer | 模板 getter 加载字节码 |

### 6.7 链校验（ChainValidator，CALIBRATION）

三层保守校验——只拒绝可证明不可能的链：

1. **PASM 可行性**：字段声明存在 / 方法可解析
2. **类型流**：来源类型（final 精确）与形参类型非子类型关系 → 拒
3. **序列化可行性**：字段声明类型无可序列化子类闭包 → 物理不可能

### 6.8 链剪枝（ChainPruner，CALIBRATION）

1. **触发上下文**：hashCode/equals/toString 等入口须有反序列化可达触发者
2. **机制去重**：同机制尾按入口家族（类路径前两段）留 ≤5 条代表

### 6.9 SafeConfig（CALIBRATION）

同一方法体内先安全配置（XStream.addPermission / Kryo.setRegistrationRequired /
Jackson.deactivateDefaultTyping）再调用反序列化入口 → 该入口链全部抑制。

### 6.10 已知模式识别（GadgetPattern，CALIBRATION）

链路径同时包含已知 gadget 家族关键类组合时标注模式名并加分：
CC1-7 / Spring1 / Rome / CB1 / Jdk7u21 / SignedObject 二次反序列化。

## 7. 调用图基础设施

- **传递子类型分发**：虚调用按传递子类型闭包枚举（深继承链覆写方法获得边）
- **SPECIAL 边解析**：用 resolveMethod 后的真实声明类（消灭幽灵节点）
- **DISPATCH_CAP = 200**：超限截断（Object 的 7009 子类型正确截断）
- **图冻结**：构建后 freeze()，分析期只读

## 8. 前端与 JDK 版本

- fat jar（BOOT-INF）+ WAR（WEB-INF）嵌套 jar 递归解析
- 单类损坏不中断，计入诊断
- class 文件 major version 提取 → 目标 JDK 版本报告
- `--jdk-home`：Java 8 读 rt.jar + 辅助 jar，Java 9+ 走 jrt-fs

## 9. CSV 输出

- **findings.csv**：链汇总（置信度降序，含 variant_count / path / evidence）
- **edges.csv**：链每跳明细（from/to/kind/field/reason）
- **sinks.csv**：每个 sink 的裁决

## 10. 从开源项目学习

| 来源 | 移植内容 |
|---|---|
| GadgetInspector | 传递子类型分发修复、前向对象污点两段式、passthrough 语义 |
| FLASH (USENIX'25) | 包前缀剪枝（DDCA 管线特化）、触发上下文校准 |
| JDD (IEEE S&P) | 语义链组装（bottom-up）、已知模式识别 |
| tabby | model 规则（actions 声明式摘要）、--jdk-home |
| CodeQL | 16 框架 source 清单、SafeConfig 抑制 |
| marshalsec | 已知 gadget 模式分类 |
