# 用户指南

本节提供 ProvidAPT 的日常使用说明，覆盖 CLI、查询、规则、运维与可视化。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [cli.md](cli.md) | `providaptctl` 及相关命令说明 |
| [provql.md](provql.md) | ProvQL 查询语法与示例 |
| [detection-rules.md](detection-rules.md) | 检测规则编写说明 |
| [operations.md](operations.md) | 运维、健康检查与故障处理 |
| [visual-guide.md](visual-guide.md) | 可视化界面与图谱浏览说明 |
| [manual.md](manual.md) | 英文完整版手册 |
| [manual.zh.md](manual.zh.md) | 中文完整版手册 |

## 常见操作

```bash
# 查看最近告警
providaptctl alert list --since 1h

# 回溯单个进程
providaptctl provenance trace --pid 1234

# 查看系统健康状态
providaptctl status
```
