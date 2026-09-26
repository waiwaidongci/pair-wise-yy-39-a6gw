# 大坝巡检、缺陷与应急管理

安排巡检，记录渗流、位移、裂缝等缺陷并跟踪修复、复检和应急预案。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8316
```

默认端口为`8316`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `GET /api/seal-cases`、`GET /api/seal-cases/{id}`
- `POST /api/seal-cases`，提交`reason`和`evidence_summary`
- `POST /api/seal-cases/{id}/confirm`，提交`scope_note`
- `POST /api/seal-cases/{id}/resolve`，提交`resolution_note`

允许角色：inspector, dam_engineer, emergency_manager, viewer。异常值比控制阈值越高，缺陷优先级越高；应急处置缺陷必须完成复检并记录证据后才能关闭。

## 审计封存

- 夜巡或值班员发现审计链断链后，通过`POST /api/seal-cases`建未结清处置单，系统自动定位断点事件，记录发现人、原因和证据摘要，并冻结断点之后相关缺陷的后续写入（补录、流转）。
- 另一名应急经理（不得为发现人）通过`POST /api/seal-cases/{id}/confirm`确认影响范围；原事件始终只读，不做改写。
- 处置完成后通过`POST /api/seal-cases/{id}/resolve`结清并记录恢复说明，冻结解除；建单、确认、结清均写入审计链。
- 结清视为处置了该断点及之前的全部异常；同一断点结清后不能重复建单。
- `GET /api/seal-cases`查看冻结项与处置进度，演示页同步展示。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
