# 合规与安全

本节说明 ProvidAPT 在安全、隐私、审计与数据处理方面的设计原则。

## 文档列表

| 文档 | 说明 |
| --- | --- |
| [security-privacy.md](security-privacy.md) | 脱敏、隐私与安全设计说明 |

## 设计原则

- 数据最小化：只采集溯源与检测所需字段
- 可配置脱敏：支持对路径、地址、令牌等敏感字段做规则化处理
- 防篡改审计：审计记录支持完整性校验与长期留痕
- 访问控制：管理面支持认证、RBAC 与审计跟踪

## 相关配置

安全与审计策略主要通过 `/etc/providapt/providapt.toml` 配置，部署细节可参考 `docs/getting-started/deployment.md`。
