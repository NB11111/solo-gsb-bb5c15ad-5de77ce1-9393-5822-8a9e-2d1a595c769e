# 网络前缀策略分析 API（Network Prefix Policy Analyzer）

基于 **Python 3.12 + FastAPI + SQLite** 的服务：提交一组带 **优先级、动作、来源标签** 的
IPv4/IPv6 CIDR 规则，服务端按 **最长前缀匹配（LPM）+ 同前缀优先级裁决** 计算每条规则的
**实际覆盖范围**，识别：

- **完全遮蔽（fully shadowed）**：规则的整个 CIDR 被更长前缀全部拿走，实际不转发任何地址；
- **部分重叠（partial overlap）**：部分范围被更长前缀覆盖（给出碎片 CIDR 列表）；
- **动作冲突（action conflict）**：重叠且动作不同（permit vs deny），并给出**可复现的最小冲突对**
  及其精确的 `override_range`；
- **优先级反转（priority inversion）**：长前缀仅凭前缀长度（而非更高优先级数字）覆盖短前缀
  且改变动作时给出提示。

分析结果是**确定性**的：相同输入得到相同 `ruleset_hash` 与版本 `id`。支持保存分析版本、
按条件查询规则/发现、导出 JSON。

---

## 一条命令启动（Docker Compose）

```bash
docker compose up --build -d
```

- 服务监听端口：**8080**（宿主机与容器内一致）
- API 根地址：<http://localhost:8080/>
- 交互式文档（Swagger UI）：<http://localhost:8080/docs>
- 健康检查：<http://localhost:8080/health>

SQLite 数据文件保存在命名卷 `prefix_data`（容器内 `/data/prefix_policy.db`），容器重启后
已保存的分析版本不丢失。停止：`docker compose down`（加 `-v` 同时删除数据卷）。

### 不用 Docker，直接本地运行

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

数据库默认落在 `/data/prefix_policy.db`；该目录不可写时自动回退到系统临时目录
`$TMPDIR/prefix_policy.db`。可用环境变量 `PREFIX_DB_PATH` 显式指定：

```bash
PREFIX_DB_PATH=./data/policy.db uvicorn app.main:app --host 0.0.0.0 --port 8080
```

运行测试：

```bash
python -m pytest -q
```

---

## 规则与裁决语义

| 字段 | 说明 |
| --- | --- |
| `cidr` | IPv4/IPv6 CIDR，如 `10.0.0.0/8`、`2001:db8::/32`；**主机位必须为 0**（`10.0.0.5/24` 会被拒绝） |
| `action` | `permit`（别名 `allow`/`accept`/`pass`）或 `deny`（别名 `block`/`drop`/`reject`），大小写不敏感 |
| `priority` | 整数，**数值越小优先级越高**，默认 `100`。仅用于裁决**完全相同 CIDR** 的规则 |
| `source_tag` | 来源标签（自由文本），默认 `default`，如 `hq` / `edge-fw` / `terraform` |
| `rule_id` | 可选唯一 ID；不填则自动生成 `r1, r2, ...` |

转发模型采用经典最长前缀匹配：

1. **更长前缀永远胜出**——即使它的 `priority` 数字更"低"（数值更大）。此时若动作也发生变化，
   该边会被标记 `priority_inversion: true`。
2. **同一 CIDR 的多条规则**归并为一个 trie 节点：优先级最高（数字最小，再按提交顺序）者为
   **winner**，其余为 **duplicate**，实际覆盖为 0（`role: "duplicate"`, `status: "shadowed"`）。
3. 规则 R 的**实际覆盖** = `cidr(R)` − 其所有 winner 子节点 CIDR 的并集，以 CIDR 碎片列表
   `effective_cidrs` 返回：
   - 碎片为空 → `status: "shadowed"`（完全遮蔽）
   - 有碎片且存在子节点 → `status: "partial"`（部分重叠）
   - 无子节点 → `status: "active"`

### 最小冲突对（minimal_conflict_pairs）

对每个**实际转发至少一个地址**的节点 N（`effective_cidrs` 非空），沿祖先链向上查找：
**跳过动作与 N 相同的祖先**，与第一个动作不同的祖先配对。该对的 `override_range` 精确等于
N 的实际覆盖碎片。

跳过同动作祖先保证了结果**最小且无遗漏**——例如 `permit /8 → deny /16 → deny /17 ×2`，
/16 被两个 deny 的 /17 完全遮蔽时，内部没有冲突，但两个 /17 会"穿过"同动作的 /16 与 /8
配对，而死规则 /16 自身不产生对。输出按规则 ID 排序，完全可复现。

---

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/analyze` | 分析规则集（默认保存；`save:false` 只算不存） |
| GET | `/api/analyses` | 列出已保存版本（`limit`/`offset` 分页） |
| GET | `/api/analyses/diff` | 两个已保存版本的**语义差异**（查询参数 `base`、`target`） |
| GET | `/api/analyses/{id}` | 取某个版本的完整分析结果 |
| GET | `/api/analyses/{id}/rules` | 查询规则：`status=active/partial/shadowed`、`action=permit/deny`、`ip=4/6` |
| GET | `/api/analyses/{id}/findings` | 查询发现：`severity=conflict/warning/info`、`behavioral_only=true` |
| GET | `/api/analyses/{id}/export.json` | 以附件形式导出完整结果 JSON |
| GET | `/health` | 健康检查 |

### 示例：提交分析

```bash
curl -s -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "dc-2026-09",
    "rules": [
      {"cidr": "10.0.0.0/8",   "action": "permit", "priority": 100, "source_tag": "hq"},
      {"cidr": "10.10.0.0/16", "action": "deny",   "priority": 500, "source_tag": "dc1"},
      {"cidr": "10.10.1.0/24", "action": "permit", "priority": 900, "source_tag": "lab"},
      {"cidr": "2001:db8::/32", "action": "deny",  "source_tag": "v6"}
    ]
  }'
```

响应（节选）：

```json
{
  "id": "an_e38b58f57faf2325",
  "ruleset_hash": "e38b58f5...",
  "persisted": true,
  "summary": {
    "rule_count": 4, "distinct_cidrs": 4,
    "active_rules": 2, "partial_rules": 2, "shadowed_rules": 0,
    "behavioral_conflicts": 2, "priority_inversions": 2
  },
  "rules": [
    {
      "rule_id": "r1", "cidr": "10.0.0.0/8", "action": "permit",
      "priority": 100, "source_tag": "hq",
      "role": "winner", "status": "partial",
      "covered": 16711680, "total_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/13", "10.8.0.0/15", "..."],
      "covered_by": ["r2"], "has_conflict": true
    }
  ],
  "findings": [
    {
      "type": "cover", "severity": "conflict",
      "rule_id": "r2", "other_rule_id": "r1",
      "cidr": "10.10.0.0/16", "parent_cidr": "10.0.0.0/8",
      "child_action": "deny", "parent_action": "permit",
      "action_conflict": true, "behavioral": true,
      "priority_inversion": true,
      "reason": "rule 'r2' (deny) overrides 'r1' (permit) on 10.10.0.0/16 via longer prefix"
    }
  ],
  "minimal_conflict_pairs": [
    {
      "kind": "cover", "rule_id": "r2", "other_rule_id": "r1",
      "action": "deny", "other_action": "permit", "winner_rule_id": "r2",
      "cidr": "10.10.0.0/16",
      "override_range": ["10.10.0.0/24", "10.10.2.0/23", "..."],
      "reason": "longest-prefix match: 'r2' (deny) wins over 'r1' (permit) on this range"
    }
  ]
}
```

### 查询与导出

```bash
# 只看部分重叠的规则
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/rules?status=partial"

# 只看真正改变转发行为的冲突发现
curl -s "http://localhost:8080/api/analyses/an_e38b58f57faf2325/findings?behavioral_only=true"

# 导出 JSON 文件
curl -sOJ "http://localhost:8080/api/analyses/an_e38b58f57faf2325/export.json"
```

### 版本语义差异

`GET /api/analyses/diff?base={id}&target={id}` 比较两个**已保存版本**中每个 IPv4/IPv6
地址的**最终生效动作**：最长前缀命中的 winner 规则动作为 `permit`/`deny`，没有任何规则
命中记为 `none`。只有至少被一个版本覆盖的地址参与比较（两版本都无规则匹配的地址忽略）。

结果返回动作发生变化的地址段——以覆盖该段的**最小 CIDR 集合**表示，并给出每种变化类型
（有序动作对，共 6 种：`none_to_permit`、`none_to_deny`、`permit_to_none`、`deny_to_none`、
`permit_to_deny`、`deny_to_permit`）的变化范围数与地址数。**仅当相邻两段的变化类型完全
相同时才合并**；被不同类型或"无变化"区间隔开的范围各自独立。IPv4 与 IPv6 独立比较，
IPv6 的超大地址计数（如 2^96）以 JSON 数字返回。

```bash
curl -s "http://localhost:8080/api/analyses/diff?base=an_aaaa...&target=an_bbbb..."
```

```json
{
  "base_id": "an_aaaa...",
  "target_id": "an_bbbb...",
  "total_changed_addresses": 256,
  "total_cidr_count": 2,
  "total_change_range_count": 2,
  "by_change_type": {
    "permit_to_deny":  {"change_range_count": 1, "changed_addresses": 128},
    "permit_to_none":  {"change_range_count": 1, "changed_addresses": 128}
  },
  "ipv4": {"change_range_count": 2, "changed_addresses": 256, "cidr_count": 2, "by_type": {}},
  "ipv6": {"change_range_count": 0, "changed_addresses": 0, "cidr_count": 0, "by_type": {}},
  "changes": [
    {"ip_version": 4, "change_type": "permit_to_deny",
     "base_action": "permit", "target_action": "deny",
     "cidrs": ["10.0.0.0/25"], "address_count": 128},
    {"ip_version": 4, "change_type": "permit_to_none",
     "base_action": "permit", "target_action": "none",
     "cidrs": ["10.0.0.128/25"], "address_count": 128}
  ]
}
```

差异是**有方向**的（`base → target`）；交换两个参数得到反向变化。ID 必须形如
`an_` + 16 个十六进制字符：格式非法或两个 ID 相同 → `400`；任一版本不存在 → `404`。

### 错误处理

- 非法 CIDR（语法错误、主机位非零、rule_id 重复等）→ `400`，形如
  `{"error": "invalid_ruleset", "detail": "rule #1: invalid CIDR '10.0.0.5/24' (...)"}`
- 字段类型/取值错误（未知 action、空规则列表、多余字段等）→ `422`（Pydantic 校验错误）
- 版本不存在 → `404`
- 语义差异的版本 ID 格式非法或两个 ID 相同 → `400`；差异端点引用的版本不存在 → `404`

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py     # 核心引擎：CIDR 解析、trie、覆盖与最小冲突对（纯函数，可独立使用）
│   ├── schemas.py      # Pydantic v2 请求/响应模型
│   ├── db.py           # SQLite 持久层（analyses / rules / findings 三表）
│   └── main.py         # FastAPI 路由
├── tests/test_api.py   # 端到端测试（pytest + TestClient）
├── requirements.txt
├── Dockerfile          # 非 root 运行、内置 HEALTHCHECK、暴露 8080
├── docker-compose.yml  # 单命令启动 + 命名卷持久化
└── README.md
```

### SQLite 表结构

- `analyses(id, name, ruleset_hash, analyzer_version, created_at, rule_count, result_json)`
  —— 不可变版本，完整结果 JSON 冗余保存，便于导出；
- `rules(analysis_id, rule_index, rule_id, cidr, ip_version, action, priority, source_tag,
  role, status, covered, has_conflict)` —— 支持 SQL 过滤；
- `findings(analysis_id, seq, kind, severity, rule_id, other_rule_id, behavioral, payload_json)`
  —— 支持按严重级别/是否影响行为过滤。

`covered` 以十进制文本存储，以容纳超出 64 位整数范围的 IPv6 地址计数（如 /32 的 2^96）。

### 确定性 / 幂等

版本 ID = `an_` + `sha256(规范化输入)` 的前 16 个十六进制字符。规范化输入包含
`rule_id / cidr / action / priority / source_tag`，与提交顺序无关地以规范 JSON
（排序键、无空白）序列化。重复提交同一规则集返回**同一个版本 ID**，数据库中只存一份。

### 复杂度

trie 构建对每个节点线性扫描候选祖先，复杂度约 O(n²)，适合数百至数千条规则的策略集；
覆盖差集基于标准库 `ipaddress.address_exclude`。若需要超大规模（数万条以上），可将
祖先查找替换为按版本分组的 radix tree，分析器输出契约不变。
