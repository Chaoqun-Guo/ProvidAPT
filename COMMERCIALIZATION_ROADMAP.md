# ProvidAPT 商业化路线图

> 状态：执行计划（v1）
> 更新时间：2026-06-07
> 目标：将当前技术底座推进为可销售、可交付、可运营、可规模部署的商业产品

---

## 1. 总体目标

商业产品状态不等于“功能很多”，而是同时满足：

- 可安装：客户能稳定部署、升级、回滚
- 可验证：构建、加载、运行、策略、告警有自动化验证闭环
- 可运营：健康、遥测、审计、支持包、诊断链路完整
- 可管理：多主机、策略、资产、告警、权限统一管理
- 可交付：文档、打包、许可证、版本策略、支持流程可落地

---

## 2. 工作分层

### P0：必须完成

这些项不补齐，产品仍偏“工程样机”：

1. Linux 真实运行验证闭环
2. e2e 端到端验证闭环
3. 遥测数据上报链路打通
4. gRPC 管理面测试补齐
5. 安装 / 升级 / 回滚能力标准化
6. 支持包、诊断、审计链路收口

### P1：强烈建议尽快完成

这些项决定能否稳定卖给企业客户：

1. 集中式控制面（资产、策略、告警）
2. 基础 RBAC / 多角色权限
3. 策略版本化、审批、灰度发布
4. 告警抑制、去重、升级、工单流转
5. Dashboard / Web 控制台增强
6. Fleet / Agent 分组与标签管理

---

## 3. 三阶段目标

### 阶段 1：可卖（Sellable）

目标：完成最小商业交付闭环

#### 范围

- P0 全部完成
- P1 中的基础控制面、RBAC、告警工作流最小集
- 单机 + 小规模多主机部署闭环
- 安装、升级、回滚、支持包、诊断流程固化

#### 验收标准

- Linux eBPF loader 有自动 CI + 手动 smoke 双验证
- 守护进程、策略、API、告警、审计具备回归测试
- 提供标准安装包、版本升级路径和失败回滚说明
- 提供基础 Web 管理入口：资产列表、告警列表、健康状态
- 至少支持三种角色：管理员、分析员、审计员
- 提供支持包导出与标准排障文档

#### 代码落点

- `internal/engine/loader/`
- `test/integration/`
- `pkg/telemetry/`
- `internal/policy/mgmt/`
- `pkg/api/`
- `pkg/audit/`
- `pkg/diagnose/`
- `pkg/supportbundle/`

---

### 阶段 2：可规模部署（Scalable）

目标：从“能卖”推进到“能大规模稳定部署”

#### 范围

- Agent Fleet 管理
- 主机分组、标签、策略批量下发
- 遥测聚合与集中健康看板
- Dashboard → Web 控制台增强
- 告警聚合、抑制、升级、关联分析
- 对接外部系统：Webhook / Slack / 工单

#### 验收标准

- 支持 100+ Agent 管理模型
- 支持按主机组发布策略和回滚
- 支持集中查看 Agent 健康、版本、最近遥测、最近告警
- 支持告警去重、静默、升级
- 支持标准通知 / 工单集成

#### 代码落点

- `internal/policy/mgmt/`
- `pkg/api/`
- `cmd/collector/`
- `internal/stitcher/`
- `pkg/notify/`
- `pkg/client/`
- `pkg/metrics/`
- `pkg/telemetry/`

---

### 阶段 3：高价值企业版（Enterprise）

目标：形成高客单价能力与长期续费价值

#### 范围

- 多租户
- 策略审批流
- 案件调查工作台
- 合规与管理报表
- 威胁内容订阅 / 规则包更新
- 许可证 / 授权管理
- 更强的自动响应编排

#### 验收标准

- 支持租户隔离、数据隔离、权限隔离
- 支持规则版本审计与审批链
- 支持案件时间线、攻击链视图、证据包导出
- 支持周报 / 月报 / ATT&CK coverage / 合规摘要
- 支持授权文件、版本控制、功能开关

#### 代码落点

- `pkg/plugin/`
- `pkg/api/`
- `internal/policy/incident/`
- `internal/policy/respond/`
- `internal/policy/response/`
- `internal/engine/backtrace/`
- `internal/engine/viz/`

---

## 4. 执行顺序（推荐）

### Wave 1：验证与交付基础

1. Loader Linux 自动验证稳定化
2. e2e 端到端验证脚本与 CI 化
3. `pkg/telemetry/` 真正接入 daemon / API / 上报端
4. `internal/policy/mgmt/` 测试补齐
5. 安装 / 升级 / 回滚文档与脚本统一

### Wave 2：控制面最小闭环

1. Web 控制台最小 MVP
2. 资产列表 / Agent 状态
3. 告警列表 / 检索 / 抑制
4. 基础 RBAC
5. 支持包 / 诊断中心

### Wave 3：规模化与企业增强

1. Fleet 管理
2. 策略中心
3. 多租户
4. 案件工作台
5. 规则订阅 / 授权管理

---

## 5. P0 明细与验收

### P0-1 Loader / e2e 验证闭环

#### 目标

- 从“可以运行”提升到“运行可验证”

#### 需要完成

- `loader_smoke` 从手动 job 逐步推进到定时或标签触发
- 增加 e2e 全链路 smoke：daemon → collector → pipeline → graph → alert
- 产物与日志作为 CI artifact 上传

#### 验收

- 新版本提交后可自动或手动产出 Linux 运行验证结果
- 失败时可获取完整日志、支持包、环境探测结果

---

### P0-2 遥测链路打通

#### 目标

- 让产品具备运营视角，而不只是本地运行

#### 需要完成

- 定义 telemetry schema
- 接入 daemon runtime 指标、版本、健康、错误摘要
- 接入 API / CLI 查看最近上报状态
- 提供开关、匿名化、重试、限速机制

#### 验收

- 可查看 Agent 最近一次上报时间、状态、失败原因
- 可关闭遥测并保留本地功能

---

### P0-3 Mgmt 管理面测试

#### 目标

- 管理接口可回归、可发布

#### 需要完成

- gRPC Query / UpdatePolicy / Check / WatchAlerts 测试
- 鉴权 / TLS / 错误路径 / 并发路径覆盖

#### 验收

- `internal/policy/mgmt/` 有基础单测 + 集成测试

---

### P0-4 安装 / 升级 / 回滚

#### 目标

- 客户能安全上生产

#### 需要完成

- 统一安装入口
- 版本升级脚本
- 失败自动回滚说明
- 兼容矩阵文档

#### 验收

- 至少覆盖 tar / deb / rpm / container 四条主路径

---

## 6. P1 明细与验收

### P1-1 Web 控制台 MVP

#### 功能

- 登录入口
- 资产概览
- Agent 健康
- 告警列表
- 基础搜索

### P1-2 RBAC

#### 角色

- Admin
- Analyst
- Auditor

### P1-3 策略中心

#### 功能

- 查看当前策略
- 编辑草稿
- 发布版本
- 回滚历史版本

#### 当前进展

- ✅ `internal/policy/mgmt/` 已增加策略中心快照、版本历史、发布/回滚骨架
- ✅ `pkg/api/` 已提供 `GET/POST /api/v1/control/policies`
- ✅ `pkg/api/dashboard.html` 已新增策略中心总览卡片与最近策略动作时间线
- ✅ 策略动作已补 `actor / role` 注入与动作审计时间线
- ✅ RBAC 已限制仅 `Admin` 可执行发布/回滚，`Analyst/Auditor` 保持只读

### P1-4 告警工作流

#### 功能

- 去重
- 静默
- 升级
- 分派
- 工单 / Webhook

#### 当前进展

- ✅ `pkg/alertflow/` 已提供告警去重、静默、分派、关闭/重开最小状态机
- ✅ `cmd/agent/daemon/` 已在通知前接入 workflow gating，重复告警不会直接重复外发
- ✅ `pkg/api/` 已提供 `GET/POST /api/v1/control/alerts`
- ✅ `pkg/api/dashboard.html` 已新增 Alert Workflow 概览卡片、最近工作流告警列表与动作时间线
- ✅ 告警工作流动作已补 `actor / role / note` 注入与动作审计时间线
- ✅ `pkg/notify/` 已增加 webhook / email / slack 统一 delivery 审计、失败重试与 dead-letter 跟踪
- ✅ `pkg/api/` 已提供 `GET /api/v1/control/deliveries`
- ✅ `pkg/api/dashboard.html` 已新增 Delivery Health 概览与 dead-letter 最近列表
- ✅ 已补 dead-letter 单条 / 批量 replay 动作与 `POST /api/v1/control/deliveries`
- ✅ 已新增 `pkg/ticketing/`，提供 Jira / generic webhook / ServiceNow 工单创建骨架
- ✅ 同一 dead-letter 已支持基础 ticket 链接幂等，避免重复升单
- ✅ Delivery Health 控制台已补 replay / create-ticket 动作入口与 ticket 链接展示
- ✅ Delivery Health 控制台已补 `create_ticket_all` 批量升单入口，支持已升单 dead-letter 跳过统计
- ✅ Delivery Health 已补最近操作审计时间线，记录 replay / ticket 动作与批量结果
- ✅ Jira / ServiceNow / webhook 工单已支持评论回写，把 replay / escalate 结果同步到外部工单
- ✅ 交付动作审计与工单评论已补 `actor / role / note` 上下文，并支持 `api.auth_identities` 身份映射，便于审计与复盘
- 🔜 下一步补投递失败长期留痕、更多工单系统适配（如 飞书）与更完整的工单审计

### P1-5 Fleet 管理

#### 功能

- Agent 注册
- 分组 / 标签
- 批量操作
- 版本可见性

#### 当前进展

- ✅ `pkg/api/` 已提供 `GET/POST /api/v1/control/fleet`，支持按 `group / tag` 查询与元数据更新
- ✅ Fleet 元数据更新已接入 `actor / role / note` 注入，与现有控制面审计模型保持一致
- ✅ `cmd/agent/daemon/` 已补最近 Fleet 操作审计时间线，记录分组 / 标签变更的操作者、目标节点与备注
- ✅ `pkg/api/dashboard.html` 已新增 Recent Fleet Actions 视图，支持在控制台直接回看最近资产分组操作
- 🔜 下一步补批量 Fleet 操作、主机版本态势与更完整的资产筛选/排序能力

### P1-6 支持包 / 诊断中心

#### 当前进展

- ✅ `pkg/supportbundle/` 已支持 `CaptureTo`，手动导出 support bundle 时可返回实际导出路径
- ✅ `pkg/api/` 已提供 `GET/POST /api/v1/control/support`，支持查看最近 support bundle 状态并触发手动导出
- ✅ Support bundle 导出动作已接入 `actor / role / note` 注入与统一控制面审计时间线
- ✅ `pkg/supportbundle/` 已补脱敏 zip 归档，当前会对常见文本文件中的邮箱、IP、password/token/api key 等字段做基础遮盖
- ✅ `pkg/api/` 已提供 `GET /api/v1/control/support/download`，并通过现有鉴权链路限制下载访问
- ✅ `cmd/agent/daemon/` 已把导出结果、最近操作者、最近原因、归档路径与下载入口回显到控制面状态
- ✅ `pkg/api/dashboard.html` 已新增 Support Bundle 面板、导出入口与最新归档下载入口
- ✅ 支持包脱敏已改为稳定伪名化，同一敏感值会映射到一致的 `<redacted-*-hash>` 标记，便于排障比对
- ✅ 归档已补基础生命周期管理：自动保留最近若干份 support bundle 并清理更旧目录/zip
- ✅ 最新 support bundle 下载动作会进入统一控制面审计时间线
- ✅ Support bundle 导出/下载动作已补长期 `pkg/audit/` 管理审计落盘
- ✅ 归档保留数量与脱敏开关已支持配置化覆盖
- ✅ `GET /api/v1/control/audit` 已可查询持久化支持包管理审计，控制台可直接查看最近支持包长期留痕
- 🔜 下一步补更细粒度的字段级脱敏规则、下载审计查询视图，以及按租户/主机组的支持包访问边界

---

## 7. 30 / 90 / 180 天里程碑

### 30 天

- P0-1 Loader / e2e 验证闭环
- P0-2 Telemetry 最小上报
- P0-3 Mgmt 测试补齐
- Web 控制台信息架构与接口草案

### 90 天

- 阶段 1（可卖）完成
- 基础 RBAC、告警工作流、支持包、升级流程完成
- 形成首个客户 PoC 交付包

### 180 天

- 阶段 2（可规模部署）完成
- 启动阶段 3 的多租户、案件工作台、规则订阅

---

## 8. 当前建议的下一开发批次

按性价比排序：

1. `pkg/telemetry/` 接入 daemon / API / tests  ✅
2. `internal/policy/mgmt/` 测试补齐  ✅（基础路径）
3. `pkg/api/` 增加 Web 控制台 MVP 骨架  ✅（控制面总览 MVP）
4. 基础 RBAC（Admin / Analyst / Auditor） ✅（API Key 角色绑定 + 控制面授权）
5. 策略中心 MVP ✅（策略快照 + 版本发布/回滚骨架 + 控制台展示）
6. 告警工作流 MVP ✅（去重 + 静默 + 分派 + 交付可靠性 / dead-letter 可视化 / 单条与批量 replay）
7. `test/integration/` 增加 e2e smoke + artifact
8. CI 增加 loader/e2e 运行态产物上传

---

## 9. 定义完成（Definition of Done）

某一商业化条目只有同时满足以下条件，才算完成：

- 代码实现完成
- 至少一条自动化验证路径完成
- 对应文档完成
- CLI / API / UI 至少一条可用入口完成
- 失败模式可诊断
- 版本升级和回滚影响已评估

---

## 10. 风险提醒

以下事项决定交付速度：

- 是否接受“先单租户后多租户”
- 是否接受“先最小 RBAC 后 SSO”
- 是否接受“先手动审批流后自动审批流”
- 是否接受“先 Agent 管理后策略中心”

若全部一次做满，周期会明显拉长。建议严格按阶段推进。

---

## 11. ���ֲ������

- ? �Ѳ� `GET/POST /api/v1/control/license`����������֤�ļ������ԡ���С���޸�ʱ�����˹�У������
- ? �Ѳ� `GET/POST /api/v1/control/upgrade`��������������������ƻ���ע����
- ? License / Upgrade �ѽ��� `actor / role / note` ע�롢ͳһ���������ʱ�����볤�� `pkg/audit/` �������
- ? `pkg/api/dashboard.html` ������ `License & Upgrade` ��壬֧�ֲ鿴״̬��ִ�й�������
- ? �Ѳ�����֤Ԫ����������֧�ִ� YAML/JSON ����֤�ļ����� `customer / edition / issued_at / expires_at / signature`�������㵽��״̬��ʣ������
- ? �Ѳ� HMAC-SHA256 ����֤ǩ��У���� `PROVIDAPT_LICENSE_SIGNING_KEY` �������
- ? �Ѳ�������У��������֧�� `PROVIDAPT_UPGRADE_PACKAGE_PATH`��`PROVIDAPT_UPGRADE_EXPECTED_SHA256`��`PROVIDAPT_UPGRADE_ROLLBACK_PLAN`
- ? Dashboard �� `License & Upgrade` ����ֿ�չʾǩ��У�顢����״̬��������ժҪ��ع��ƻ�
- ? �Ѳ�����֤����������ڣ�֧�� `license.revoked_ids` �� `license.grace_period_days`������������� revoked / expired / grace-period ״̬
- ? �Ѳ�����ǩ��У�飺֧�� `PROVIDAPT_UPGRADE_SIGNATURE_PATH` �� `PROVIDAPT_UPGRADE_SIGNING_KEY`
- ? ������ `scripts/upgrade/rollback-example.sh`����Ϊ���������ع�ִ��������عǼ�
- ? �Ѳ�Զ�˵����б�ͬ���뻺����ˣ�֧�� `license.revocation_url` + `license.revocation_cache`
- ? �Ѳ���Կ��ǩ����������֤����������֧�� `Ed25519` ��Կ��ǩ�������� HMAC ����·��
- ? �Ѳ��������� / Ԥ����·��֧�� `upgrade.download_url`�������� `download` / `preflight` ��������У����ع��ƻ�����
- ? ������ `docs/DOCUMENTATION_AUDIT.md`���Ը��ĵ��� `docs/` Ŀ¼�����������ڵĹ���
- ? �Ѳ�����Դǩ��У����״̬���ԣ�������ɼ� `revocation_verified`
- ? �Ѳ����� `download` / `preflight` �������Լ�����Դ / �ع��ƻ� / preflight ready ����

- 2026-06-08: Release documentation entry points cleaned and release-doc consistency check refreshed for product release handoff.

- 2026-06-08: Chinese documentation index pages normalized to clean UTF-8, reducing release review friction for GA packaging.

- 2026-06-08: Release notes draft and curated changelog summaries prepared for final GA/RC packaging.

- 2026-06-08: Release and CI workflows upgraded for Node 24 action compatibility to unblock GitHub-hosted releases.

- 2026-06-08: Release pipeline cache configuration hardened for setup-go@v6 to avoid dependency-file auto-detection failures on GitHub-hosted runners.

- 2026-06-09: Lint workflow aligned with Node 24 and golangci-lint v2 by moving to golangci-lint-action@v7.
