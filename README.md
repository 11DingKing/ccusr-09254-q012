# 实训学时合规与冻结服务

该服务汇聚学员签到、导师确认和请假修正事件，按培养方案与时区重放学时状态，并保存可追溯的学期冻结快照。项目还提供导师分配、证明材料、豁免复核、规则版本、名额、通知和数据留存等领域模块，供后续业务扩展时复用统一的状态与审计约束。

## 运行方式

默认数据保存在项目目录的 SQLite 文件中。安装依赖后执行 `uvicorn app.main:app --host 127.0.0.1 --port 8000`，健康检查地址为 `/health`，业务接口位于 `/api`。

## 测试

```bash
python3 -m pytest -q
```

## 编译检查

```bash
python3 -m compileall -q app tests
```

测试覆盖事件幂等导入、跨时区与跨日学时合并、实习确认、负向修正、冻结快照和差异查询；运行过程中不需要单独的数据库或网络服务。

## 多方责任链

联合实训活动可由学院（`college`）、企业（`enterprise`）与第三方（`third_party`）共同负责。争议数据更正必须匹配**事件发生时刻**生效的责任链，相关接口均位于 `/api/activities/{activity_id}` 下：

| 接口 | 说明 |
| --- | --- |
| `PUT /roles/{role}` | 配置责任角色与责任人；责任转移只追加新区间并关闭旧区间，不追溯改变旧授权 |
| `PUT /fields/{field}/scope` | 配置字段授权角色范围；多角色字段为共有字段，更正时必须会签 |
| `POST /delegations` | 配置区间内责任委托；形成循环授权（含自环、经失效区间）时拒绝 |
| `GET /chain` | 查询活动完整责任链（角色段、字段范围、委托） |
| `GET /authorize` | 按 `at` 时刻责任链判定某操作人能否更正某字段 |
| `POST /corrections` | 提交争议更正（锚定 `event_occurred_at`）；`is_emergency=true` 时紧急先行生效并记录补审期限 |
| `POST /corrections/{id}/countersign` | 共有字段会签/紧急补审；超期补审返回 409 并自动失效 |
| `POST /expire-overdue` | 清扫超过补审期限仍未补签的紧急更正 |
| `GET /corrections`、`GET /corrections/{id}` | 更正单与会签进度查询 |
| `GET /audit` | 责任链审计查询，支持按实体过滤，并校验链式指纹是否被篡改 |

规则要点：

* 有效区间为半开区间 `[valid_from, valid_until)`，跨日按 UTC 边界生效；
* 委托可传递授权（A 委托 B、B 委托 C 则 C 可履职），但任何会成环的委托都被拒绝；
* 责任转移采用条件更新实现乐观锁，并发转移只有一方成功，失败返回 409；
* 紧急更正必须在 `review_seconds`（默认 24 小时）内补齐其余责任方会签，超期自动置为 `expired`。
