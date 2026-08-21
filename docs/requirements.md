# Just — 需求文档

## 1. 概述

Just 是轻量 Java SAST 工具：对闭源 JAR/WAR 做 Java 原生反序列化（ObjectInputStream）gadget 链挖掘。
交付形态：**单个可运行 CLI JAR**（shade），无 GUI/Web/IDE 插件。结果 CSV 导出，默认输出目录 `just-out`。

核心流程：`JAR/WAR → ASM 解析 → 类层次/CPG/调用图 → 黑板两阶段分析（ANALYSIS → CALIBRATION，串行）→ CSV 报告`

## 2. 功能需求

| 编号 | 需求 | 说明 |
|---|---|---|
| FR1 | 输入解析 | 目标 JAR/WAR/class 目录 + 可选依赖 JAR；支持 Spring Boot fat jar（BOOT-INF/classes + BOOT-INF/lib 嵌套 jar 递归解析）；**深度分析默认开启**（JDK 运行库 java.base/naming/rmi/management/scripting/sql 全量纳入），`--fast` 跳过全量仅保留懒加载；单类损坏/解析失败不中断全扫，计入诊断；单条目体积上限防 zip 炸弹 |
| FR2 | 字节码事实模型 | ASM 解析为自研 model（ClassInfo/MethodInfo/FieldInfo/InsnFact/Op），model 不依赖 ASM |
| FR3 | CPG 构建 | METHOD/CALL 两类节点；INVOKES/DISPATCHES/LAMBDA 调用边（CHA 多边，候选有上限）；指令级 CFG 惰性计算（SEQ/FALSE/JUMP/EXCEPTION，含异常边）；构建完成后图冻结（分析期禁写） |
| FR4 | 类层次 | 含 JDK 类懒加载（jrtfs）；Serializable/Externalizable 传递闭包判定；懒加载追加子类型时相关缓存失效；接口实现查询带独立上限缓存 |
| FR5 | 调用图 | CHA 虚调用解析；lambda（invokedynamic bootstrap）边；反射/代理不建边、由前向精扫按需展开；不可解析调用标记 external 参与置信度惩罚 |
| FR6 | KS1 模式匹配 | YAML 规则：sink 起点（命令执行/类加载/JNDI/反射/脚本/表达式引擎等类别）+ magic-entry 终点（readObject/readResolve/readObjectNoData/hashCode/equals/compareTo/compare/toString/finalize/readExternal/proxyInvoke 等）。**清单以 default-rules.yaml 为唯一事实源**，语义对齐 ysoserial/GadgetInspector/CodeQL/tabby 公开规则；owner+name+descriptor 结构匹配，`~` 锚定正则可选；**sink owner 支持子类型/实现类层次命中**；每条链携带 rule_id 可归因 |
| FR7 | 黑板与控制器 | 知识源插件接口（KnowledgeSource + ServiceLoader 单轨注册，无硬编码列表）；**串行两阶段调度**：ANALYSIS（KS1/KS2/KS4/KS5，各自独立、互不依赖对方产物，自行用 RuleEngine 匹配 sink/entry）→ CALIBRATION（KS3 校准全部链）；KS 异常按源隔离不中断全扫；KS 之间零直接调用、零跨 ks 包 import |
| FR8 | KS2 反向污点 | 从 sink 参数/receiver 反向回溯：OIS 读/入口 this/proxy args/receiver 返回值/passthrough/字段写入者/数组元素；**跨方法形参↔实参按参数序数严格对齐**（paramOrdinal 统一口径，区分静态/实例、wide 参数槽）；上下文不敏感；**双向剪枝**（入口/OIS 宿主下游集之外的调用者可证明无链，跳过）；深度/步数/链数预算与去环；死胡同记忆化（预算尾部截断不入缓存） |
| FR8b | KS6 反序列化回调 | OIS 机制回调建模：自定义 ObjectInputStream 子类重写的 resolveClass/resolveProxyClass 在 readObject 期间以攻击者可控参数被回调；重写方法内由回调参数派生的规则 sink（经 origin 确证，常量不报）产链；机制路径取调用图真实 BFS；入口取 OIS 宿主的最近 magic-entry 祖先 |
| FR8c | KS7 对象图入口扩散 | 类 E 的非 transient 字段可容纳可序列化子类型 F 实例 → F 的机制回调入口（readObject/readObjectNoData/readExternal；validateObject 需 readObject 内 registerValidation 核验）在 E 反序列化期间被调用；F 的入口链重根到 E 产出新 entry→sink 覆盖；防环与上限约束；COMPOSITION 阶段 |
| FR8d | KS8 类型流校准 | 逐跳值类型相容性：带形参序数的调用跳，值来源类型（上一跳形参/字段声明类型/入口类）与形参类型双可解析且非子类型关系 → 拒绝；Object/数组/原语/不可解析保守通过 |
| FR8e | KS9 序列化可行性校准 | FIELD_FLOW 涉及字段（声明类自身可序列化——攻击者对象图代理）的声明类型与已加载子类型闭包中均无 Serializable → 链物理不可能（写端无法构造载荷）→ 拒绝；Object 型字段天然通行；类型/Serializable 标记/祖先链不可解析保守通过 |
| FR8f | KS10 触发上下文校准 | hashCode/equals/compareTo/compare/toString 类入口不被 OIS 机制自动调用：入口方法在入口/OIS 宿主下游集（含字段中介）内无任何调用者 → 链无法在反序列化中触发 → 拒绝（no-trigger）；机制调用的入口类别不校验 |
| FR8g | KS11 机制去重校准 | 同机制尾（sink+类别+去首跳路径签名）的多入口链只保留 3 条代表（未解析少→链短→证据高择优），其余拒绝（mechanism-duplicate）；CALIBRATION 内顺序 KS3→KS8→KS9→KS10→KS11 |
| FR8h | 产链降噪 | KS6 流来源剪除（宿主内联 new ObjectInputStream → 重写回调物理不可能）；KS7 万能容器类型（Object/Serializable/Cloneable/Comparable/Externalizable 字段）重根排除 |
| FR9 | 链达成 | 回溯触及 magic-entry 的 this/参数/proxy args，或前向对象污点命中 sink → 链成立 |
| FR10 | 链提取 | entry→sink 人读顺序；去重（entry+sink+有序方法集合）；报告层按 (entry,sink,category) 折叠变体计数；置信度按路径证据分级（DIRECT_CALL/FIELD_FLOW 计证据，VIRTUAL_DISPATCH/LAMBDA 不计，unresolved 惩罚） |
| FR11 | CSV 报告 | findings.csv（链汇总+变体计数+置信度分）+ edges.csv（每跳明细）+ sinks.csv（每 sink 的 KS2 裁决）；RFC 4180；UTF-8 BOM；CRLF；统计与日志走 stderr；KS3 拒绝链过滤出 findings |
| FR12 | CLI | `scan` 子命令：`--jar`（必填）、`--deps`、`--output`（默认 just-out）、`--rules`、`--fast`、`--stats`；退出码 0 成功/2 用法错误（含无子命令）/3 内部错误 |

## 3. 非功能需求

| 编号 | 需求 |
|---|---|
| NFR1 | 运行时依赖仅 3 类：ASM、picocli、SnakeYAML |
| NFR2 | 启动快：JVM 启动后 <1s 进入扫描，无 DI/服务 |
| NFR3 | 低耦合高内聚：ASM 仅出现在 frontend 层；知识源互不直接调用；共用引擎在共享层（analysis.taint）；分层单向依赖 |
| NFR4 | 知识源可扩展：新引擎实现 KnowledgeSource 接口（声明 phase/interests）+ ServiceLoader 注册即可；ANALYSIS 阶段 KS 不得依赖其他 KS 产物 |
| NFR5 | 内存可控：<1 万类规模 4GB 堆内完成；origin 分析全 KS 共享单份；死胡同缓存按代清理；JDK 源实例单份 |
| NFR6 | 测试：单元测试 + ASM 动态生成 fixture（合成正例/负例）+ 本地 benchmark jar 真实回归（benchmark/ 不入库，缺失时测试跳过而非失败） |
| NFR7 | **普适性红线**：生产代码不得针对特定 benchmark 类名/路径特判；一切优化必须是通用语义修复；不得伪造准确率 |

## 4. 验收标准

| 里程碑 | 验收 |
|---|---|
| M1 骨架 | 扫任意 JAR 输出类/方法统计；损坏 class 隔离（诊断计数） |
| M2 CPG | CFG 边与 Serializable 闭包单测通过 |
| M3 调用图+KS1 | 合成 JAR 中 sink 与 magic-entry 全部准确标记（含 owner 子类型命中） |
| M4 KS2+黑板 | 合成链检出；参数错位假链不报；静态方法参数/wide 参数链检出；CALIBRATION 拒绝链不出现在 findings |
| M5 链+CSV | 输出格式符合 architecture.md 第 8 节；链路径可人工复核 |
| M6 回归 | **本地 benchmark 全量回归（主要验收标准）**：demo/demo2 检出已知链、Unictf/java-quote 检出已知链、Dog.equals 等已知负例不报、javamix 扫描收敛且已知 WP 链组件可复核、n1cat WAR 检出已知链；与基线对比无合理链丢失、无误报回归；耗时留档 |

## 5. 范围外

payload 生成、非原生序列化（Hessian/Fastjson/XStream 等 marshaller）的入口建模、源码分析、
指针分析、SARIF/HTML、图数据库、GUI/Web/IDE 插件、反编译展示、并行调度（保留为后续实测收益驱动选项）。
