# 大坝巡检、缺陷与应急管理

安排巡检，记录渗流、位移、裂缝等缺陷并跟踪修复、复检和应急预案。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限、关闭不变量和封存处置规则。
- `src/repository.py`：SQLite建表、事务、版本控制、审计链和处置单存储。
- `src/service.py`：权限检查、用例编排、并发控制、写入冻结门禁和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页，展示冻结项和处置进度。
- `tests/`：完整流程、规则、失败和封存测试。

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
- `GET /api/audit/verify`，返回断点位置和恢复后链段状态
- `GET /api/seals` / `POST /api/seals`，上报断链并生成未结束处置单
- `GET /api/seals/{id}`
- `POST /api/seals/{id}/confirm`，另一名应急经理确认影响范围
- `POST /api/seals/{id}/resolve`，结清处置单并恢复写入

允许角色：inspector, dam_engineer, emergency_manager, viewer。异常值比控制阈值越高，缺陷优先级越高；应急处置缺陷必须完成复检并记录证据后才能关闭。

## 审计封存

审计链断链时，值班角色可上报封存：系统定位断点并生成未结束处置单，记录断点、发现人、原因和证据摘要，同时冻结缺陷建单与流转。另一名应急经理确认影响范围后，原事件保留为只读；处置单结清才恢复写入，并向审计链追加一条恢复说明。已结清断点不可重复封存。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
