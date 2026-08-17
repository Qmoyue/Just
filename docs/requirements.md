# Just — 需求文档

## 1. 概述

Just 是轻量 Java SAST 工具：对闭源 JAR 做 Java 原生反序列化（ObjectInputStream）gadget 链挖掘。
交付形态：**单个可运行 CLI JAR**（shade），无 GUI/Web/IDE 插件。结果 CSV 导出，默认输出目录 `just-out`。

核心流程：`JAR → ASM 解析 → CPG 构建 → 黑板架构链路发现（sink 驱动反向搜索）→ CSV 报告`

## 2. 功能需求

| 编号 | 需求 | 说明 |
|---|---|---|
| FR1 | 输入解析 | 目标 JAR/class 目录 + 可选依赖 JAR；**支持 Spring Boot fat jar**（BOOT-INF/classes + BOOT-INF/lib 嵌套 jar 递归解析）；单类损坏/解析失败不中断全扫，计入诊断 |
| FR2 | 字节码事实模型 | ASM 解析为自研 model（ClassInfo/MethodInfo/FieldInfo/InsnFact 等），model 不依赖 ASM |
| FR3 | CPG 构建 | 节点（CLASS/METHOD/FIELD/INS/CALL/CONST）与边（CONTAINS/ARG/CFG/EXTENDS/IMPLEMENTS/INVOKES/DISPATCHES/REFLECTIVE/PROXY/LAMBDA/FIELD_REF/TAINT）；指令级 CFG（含异常边）；反向遍历能力 |
| FR4 | 类层次 | 含 JDK 类懒加载（jrtfs）；Serializable/Externalizable 传递闭包判定 |
| FR5 | 调用图 | CHA 虚调用解析；反射/动态代理/lambda 特殊边；不可解析标记 UNKNOWN 质量 |
| FR6 | KS1 模式匹配 | YAML 规则：sink 起点（命令执行/动态类加载/JNDI/**反射调用 Method.invoke** 四类首发）+ magic-entry 终点（readObject/readResolve/readObjectNoData/hashCode/equals/compareTo/toString/finalize/InvocationHandler.invoke）；owner+name+descriptor 结构匹配，正则可选且锚定 |
| FR7 | 黑板与控制器 | 知识源插件接口（KnowledgeSource）；事件驱动调度；KS 交错执行；反馈重调度（KS2 遇阻→需求事件→解析补边→受影响 sink 重新入队）；不动点终止 |
| FR8 | KS2 反向污点 | 从 sink 参数/receiver 反向回溯：反 def-use、字段写入者回溯、跨方法形参↔实参对齐（强制）、CHA 分发、反射/代理/lambda 反向边；深度上限与去环；路径记录 |
| FR9 | 链达成 | TAINT 回溯触及 magic-entry 的 this 字段 / OIS.read* 调用结果 / proxy-invoke 参数 → 链成立 |
| FR10 | 链提取 | 内部反向 TAINT 路径翻转为 entry→sink 人读顺序；去重（entry+sink+有序方法集合）；置信度按路径证据分级 |
| FR11 | CSV 报告 | findings.csv（链汇总，含 variant_count 变体计数）+ edges.csv（每跳明细）+ sinks.csv（每个 sink 的 KS2 裁决）；RFC 4180；UTF-8 BOM；统计与日志走 stderr |
| FR12 | CLI | `scan` 子命令：`--jar`（必填）、`--deps`、`--output`（默认 just-out）、`--rules`、`--max-depth`（默认 20）、`--stats`；退出码 0 成功/2 用法错误/3 内部错误 |

## 3. 非功能需求

| 编号 | 需求 |
|---|---|
| NFR1 | 运行时依赖仅 3 类：ASM、picocli、SnakeYAML |
| NFR2 | 启动快：JVM 启动后 <1s 进入扫描，无 DI/服务 |
| NFR3 | 低耦合高内聚：ASM 仅出现在 frontend 层；知识源互不直接调用；分层单向依赖 |
| NFR4 | 知识源可扩展：新引擎实现 KnowledgeSource 接口注册即可 |
| NFR5 | 内存可控：<1 万类规模 4GB 堆内完成；字符串驻留；JDK 懒加载 |
| NFR6 | 测试：单元测试 + ASM 动态生成 fixture + benchmark/demo.jar 真实回归 |

## 4. 验收标准

| 里程碑 | 验收 |
|---|---|
| M1 骨架 | 扫任意 JAR 输出类/方法统计；损坏 class 隔离 |
| M2 CPG | CFG 边与 Serializable 闭包单测通过 |
| M3 调用图+KS1 | 合成 JAR 中三类 sink 与 magic-entry 全部准确标记 |
| M4 KS2+黑板 | 合成链检出；参数错位假链不报；反馈重调度生效 |
| M5 链+CSV | 输出格式符合规范；链路径可人工复核 |
| M6 回归 | **扫描 benchmark/demo/ 三个 jar：demo/demo2 检出 hashCode → wagTail → Method.invoke 链、Unictf 检出 toString → Method.invoke 链；Dog.equals 负例不报**；commons-collections 3.2.1 检出已知链候选 |

## 5. 范围外（v0.1）

payload 生成、PASM 类型约束验证、非原生序列化（Hessian/Fastjson 等）、源码分析、指针分析、
SARIF/HTML、图数据库、GUI/Web/IDE 插件、反编译展示。
