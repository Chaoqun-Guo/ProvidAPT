# 开发者文档

本节面向希望扩展、集成或发布 ProvidAPT 的开发者与维护者。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC API 定义、请求/响应格式与错误码 |
| [data-schema.md](data-schema.md) | Protobuf 数据模型、事件类型与关系结构 |
| [changelog.md](changelog.md) | 版本变更记录 |
| [upgrade-guide.md](upgrade-guide.md) | 升级、预检、回滚与兼容性说明 |
| [testing.md](testing.md) | 单元测试、集成测试与性能测试说明 |
| [release-readiness.md](release-readiness.md) | 发版前最终检查清单 |
| [release-notes-draft.md](release-notes-draft.md) | 即将发布版本的 release notes 草稿 |

## 快速开发

```bash
# 编译全部 eBPF 程序
make v1-ebpf

# 编译全部 Go 二进制
make v1-userspace

# 运行测试
make v1-test
```

## 扩展指引

新增一个 eBPF Hook 的基本步骤：

1. 在 `cmd/bpf/probes/` 下编写 eBPF C 程序
2. 在 `cmd/bpf/headers/events.h` 中定义新的事件类型
3. 在 `internal/engine/collector/` 中注册事件处理逻辑
4. 在 Protobuf schema 中补充新的事件消息
