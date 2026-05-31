# 系统架构

本节描述 ProvidAPT 的整体架构设计与核心实现原理。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [overview.md](overview.md) | 系统全景图（v2.2）：分层架构、数据流、核心组件交互 |
| [architecture-v1.md](architecture-v1.md) | v1 版本技术架构（生产就绪基线） |
| [provenance-model.md](provenance-model.md) | W3C PROV 兼容溯源数据模型与图存储结构 |
| [taint-scoring.md](taint-scoring.md) | 污点传播模型：标记规则、传播策略、评分公式 |

## 核心分层

```text
用户界面层 → 分析引擎层 → 存储层 → 内核 eBPF 层
```

各层通过 gRPC + Protobuf 通信，数据以有向无环图（DAG）形式组织和查询。
