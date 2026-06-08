# 系统架构

本节说明 ProvidAPT 的整体架构、数据流与核心设计原则。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [overview.md](overview.md) | 系统总览与主要组件 |
| [architecture-v1.md](architecture-v1.md) | v1 架构基线 |
| [provenance-model.md](provenance-model.md) | W3C PROV 兼容数据模型 |
| [taint-scoring.md](taint-scoring.md) | 污点传播与评分模型 |

## 核心分层

```text
用户界面层 -> 分析引擎层 -> 存储层 -> 内核 eBPF 层
```

各层通过 gRPC 与 Protobuf 通信，数据以有向无环图形式组织与分析。
