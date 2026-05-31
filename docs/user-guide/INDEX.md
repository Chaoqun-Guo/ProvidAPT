# 用户指南

本节为 ProvidAPT 的日常操作提供详细说明，涵盖 CLI、查询语法、规则编写与可视化。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` 命令全集：参数、子命令、使用示例 |
| [provql.md](provql.md) | ProvQL 查询语法：图遍历、时序过滤、聚合操作 |
| [detection-rules.md](detection-rules.md) | Sigma 规则编写指南：规则结构、字段映射、自定义聚合 |
| [operations.md](operations.md) | 日常运维：日志管理、健康检查、故障恢复 |
| [visual-guide.md](visual-guide.md) | 可视化界面操作：仪表盘、溯源图浏览、事件搜索 |
| [manual.md](manual.md) | 用户手册（英文版）[中文版](manual.zh.md) |
| [manual.zh.md](manual.zh.md) | 用户手册（中文完整版） |

## 典型操作流程

```bash
# 查询最近告警
providaptctl alert list --since 1h

# 溯源一个进程
providaptctl provenance trace --pid 1234

# 查看系统健康状态
providaptctl status
```
