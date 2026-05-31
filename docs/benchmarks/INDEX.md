# 性能基准

本节提供 ProvidAPT 在不同环境下的性能测试数据与分析。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [benchmark-report.md](benchmark-report.md) | 多内核版本性能压测报告（事件吞吐、CPU/内存开销） |

## 关键指标摘要

| 指标 | 典型值 | 备注 |
| --- | --- | --- |
| 事件吞吐 | 50K - 150K ops/s | 取决于 BPF Ring Buffer 大小与内核版本 |
| 平均延迟 | < 5 µs（eBPF） | eBPF 到用户态传递延迟 |
| CPU 开销 | 1-3% | 单核 2.4GHz，100K ops/s 场景 |
| 内存开销 | ~200 MB | 含 LRU 缓存 + Pebble 存储引擎 |

## 测试方法

所有压测基于 `test/benchmark/` 目录下的自动化测试框架，支持自定义事件速率与负载模式。
