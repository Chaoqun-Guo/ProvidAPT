# 开发者文档

本节面向希望扩展、集成、测试或发布 ProvidAPT 的开发者与维护者。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC / HTTP API 定义、请求响应结构与错误码 |
| [data-schema.md](data-schema.md) | Protobuf 数据模型、事件类型与关系结构 |
| [testing.md](testing.md) | 单元测试、集成测试与性能测试说明 |
| [upgrade-guide.md](upgrade-guide.md) | 当前发布线升级、预检、回滚说明 |
| [release-readiness.md](release-readiness.md) | 发布前最终检查清单 |
| [release-notes-v1.2.2.md](release-notes-v1.2.2.md) | `v1.2.2` 发布说明 |
| [changelog.md](changelog.md) | 工程侧变更记录 |

## 快速开发

```bash
make build-ebpf
make build-userspace
make test-core
```
