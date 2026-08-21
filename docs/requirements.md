# Just — 需求文档

## 1. 概述

Just 是轻量 Java SAST 工具：对闭源 JAR/WAR 做反序列化 gadget 链挖掘。
覆盖原生 ObjectInputStream + Kryo/SnakeYAML/XStream/Hessian/Fastjson/Gson/Jackson 等替代框架。

交付形态：单个 CLI JAR（shade），CSV 三表输出，`--jdk-home` 支持目标 JDK 精确匹配。

## 2. 功能需求

| 编号 | 需求 | 说明 |
|---|---|---|
| FR1 | 输入解析 | JAR/WAR/class 目录 + `--deps`；fat jar（BOOT-INF）与 WAR（WEB-INF）嵌套 jar 递归解析；单类损坏不中断 |
| FR2 | 字节码事实 | ASM 解析为自研 model（ClassInfo/InsnFact/Op），model 不依赖 ASM |
| FR3 | CPG | METHOD/CALL 两类节点；INVOKES/DISPATCHES/LAMBDA 边（**传递子类型闭包**分发）；SPECIAL 边用 resolveMethod 后真实声明类；构建后冻结 |
| FR4 | 类层次 | Serializable/Externalizable 传递闭包；JDK 懒加载（jrtfs / --jdk-home rt.jar）；懒加载后缓存失效 |
| FR5 | 调用图 | CHA 虚调用（传递子类型）；lambda 解析；反射/代理不建边、由前向精扫按需展开 |
| FR6 | 反向污点 | sink 参数反向回溯；OIS 读/入口 this/proxy args/receiver 返回值/passthrough/字段写入者/数组元素；paramOrdinal 统一槽→序数；双向剪枝；接口反向分发 |
| FR7 | 前向对象污点 | magic entry/OIS 种子 → 对象污点事实不动点；粗扫+精扫（接口展开/代理串联/反射解析/可达剪枝） |
| FR8 | OIS 回调 | 自定义 resolveClass/resolveProxyClass 重写建模：回调参数驱动的 sink 产链；机制路径 BFS；流来源剪除 |
| FR9 | 框架桥接 | YAML source 规则驱动（零硬编码）：serialize 方向（toString→getter 反射）+ deserialize 方向（load→构造器/setter 反射） |
| FR10 | 对象图扩散 | 类 E 非 transient 字段可容纳 F → F 的回调入口链重根到 E |
| FR11 | 语义链组装 | INVOKE/TRIGGER/TEMPLATE 三种语义桥接组装多级链 |
| FR12 | 链校验 | PASM 可行性 + 类型流（final 来源精确）+ 序列化可行性（字段类型闭包） |
| FR13 | 链剪枝 | 触发上下文（hashCode/toString 须有可达触发者）+ 机制去重（同机制尾按入口家族留代表） |
| FR14 | SafeConfig | 同方法内安全配置（XStream 白名单/Kryo 注册等）→ 入口链抑制 |
| FR15 | 已知模式 | CC1-7/Spring1/Rome/CB1/Jdk7u21/SignedObject 等模式识别与加分 |
| FR16 | 规则系统 | 4 种类型（sink/magic-entry/source/model），改 YAML 零代码；owner 层次命中；`~` 锚定正则 |
| FR17 | CSV 输出 | findings.csv（置信度降序+变体计数）+ edges.csv（每跳明细）+ sinks.csv（裁决）；RFC 4180；UTF-8 BOM |
| FR18 | CLI | `--jar`（必填）/ `--deps` / `--output` / `--rules` / `--fast` / `--stats` / `--jdk-home`；退出码 0/2/3 |
| FR19 | JDK 版本 | class 文件 major version 提取；目标与运行时 JDK 差异 WARN；--jdk-home 读 rt.jar 或 jrt-fs |
| FR20 | 容器透传 | model 规则声明式污点透传（Map.put/get、List.add/get、String.valueOf 等） |

## 3. 非功能需求

| 编号 | 需求 |
|---|---|
| NFR1 | 运行时依赖仅 3 类：ASM、picocli、SnakeYAML |
| NFR2 | 启动快：JVM 启动后 <1s 进入扫描 |
| NFR3 | ASM 仅在 frontend 层；知识源互不直接调用；分层单向依赖 |
| NFR4 | 知识源可扩展：实现 KnowledgeSource + ServiceLoader 注册即可 |
| NFR5 | 内存可控：4GB 堆内完成 <1 万类扫描 |
| NFR6 | **普适性红线**：不得针对 benchmark 特判；优化必须是通用语义修复 |
| NFR7 | 回归验收：手动 CLI 扫描逐语料校准锚点链 |

## 4. 验收标准

| 里程碑 | 验收 |
|---|---|
| 构建期 | CPG 传递子类型分发 + SPECIAL 边解析正确；WAR/fat jar 全量解析 |
| 反向污点 | 已知链检出（demo Dog.hashCode→invoke / Unictf toString→invoke / quote BeanMap CC 链） |
| 前向污点 | magic entry 种子传播 + 精化选项生效 |
| 框架桥接 | Kryo/SnakeYAML/jackson 入口桥接到反射 sink |
| 链组装 | 多级链可组装（babychain Kryo→Rome→TemplatesImpl） |
| 校准 | 假链不报；SafeConfig 抑制生效；已知模式标注 |
| 全量回归 | 8 语料（demo×2/Unictf/quote/babychain/babyjava/n1cat/javamix）锚点全过 |
