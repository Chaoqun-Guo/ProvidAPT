# 开发者文档

本节面向希望扩展或集成 ProvidAPT 的开发者。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [api-reference.md](api-reference.md) | gRPC API 定义：服务接口、请求/响应格式、错误码 |
| [data-schema.md](data-schema.md) | Protobuf 模式规范：事件类型、节点属性、边关系 |
| [changelog.md](changelog.md) | 版本变更日志 |
| [upgrade-guide.md](upgrade-guide.md) | 版本升级注意事项、模式迁移、API 兼容性说明 |
| [testing.md](testing.md) | 测试指南：单元测试、集成测试、性能压测 |

## 快速开发

```bash
# 编译所有 eBPF 程序
make v1-ebpf

# 编译所有 Go 二进制
make v1-userspace

# 运行单元测试
make v1-test
```

## 扩展指南

添加新 eBPF Hook 点的基本步骤：

1. 在 `cmd/bpf/probes/` 下编写 eBPF C 程序
2. 在 `cmd/bpf/headers/events.h` 中定义新事件类型
3. 在用户态 `internal/engine/collector/` 中注册事件处理函数
4. 在 Protobuf schema 中添加新事件消息
