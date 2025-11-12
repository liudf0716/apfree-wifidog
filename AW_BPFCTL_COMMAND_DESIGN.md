# aw-bpfctl 命令设计分析

## 当前命令对比

### 1. `aw-bpfctl domain <list|json>`
**数据源**: `/proc/xdpi_domains` (内核 xDPI 模块)

**显示内容**:
```
Index | Domain        | SID | Title
------|---------------|-----|-------
1     | baidu.com     | 101 | 百度
2     | taobao.com    | 102 | 淘宝
```

**用途**: 查看当前在内核 xDPI 中**注册的域名列表**（静态信息）

---

### 2. `aw-bpfctl dns <list|json>` (新增)
**数据源**: `/tmp/dns_stats.txt` (用户态 dns_monitor 导出)

**显示内容**:
```
Rank | Domain        | Access Count | SID | Age  | Last Access
-----|---------------|--------------|-----|------|-------------
1    | baidu.com     | 15234        | 101 | 3h   | 2m ago
2    | taobao.com    | 12890        | 102 | 3h   | 0m ago
```

**用途**: 查看域名**访问统计信息**（动态数据，包含访问频率）

---

## 设计建议

### 方案1: 保持独立 (推荐 ✅)

**优点**:
- 语义清晰：`domain` = xDPI 域名管理，`dns` = DNS 访问统计
- 符合 Unix 哲学：每个命令做好一件事
- 易于理解和维护

**命令结构**:
```bash
# xDPI 域名管理
aw-bpfctl domain list          # 列出 xDPI 域名
aw-bpfctl domain json          # JSON 格式输出

# DNS 访问统计
aw-bpfctl dns list             # 列出 DNS 统计
aw-bpfctl dns json             # JSON 格式输出
aw-bpfctl dns top [N]          # 显示前 N 个热门域名（可选扩展）
```

---

### 方案2: 合并到 domain 命令

**缺点**:
- 混淆概念：xDPI 域名 vs DNS 统计
- 命令参数变复杂
- 不够直观

**命令结构** (如果要合并):
```bash
aw-bpfctl domain list          # 列出 xDPI 域名
aw-bpfctl domain json          # JSON 格式
aw-bpfctl domain stats         # 显示 DNS 统计 (?)
aw-bpfctl domain stats --json  # 统计 JSON 格式 (?)
```

这样会导致 `domain` 命令承担两个不同的职责。

---

## 最终建议：保持独立，但增强功能

### 当前实现 (已完成)
```bash
aw-bpfctl domain list    # xDPI 域名列表
aw-bpfctl domain json    # xDPI JSON

aw-bpfctl dns list       # DNS 统计列表
aw-bpfctl dns json       # DNS 统计 JSON
```

### 未来可扩展
```bash
# DNS 命令扩展
aw-bpfctl dns top 10           # 前10个热门域名
aw-bpfctl dns search <domain>  # 搜索特定域名统计
aw-bpfctl dns reset            # 重置统计（清空文件）

# Domain 命令扩展
aw-bpfctl domain add <name>    # 手动添加域名到 xDPI
aw-bpfctl domain del <name>    # 删除域名
aw-bpfctl domain sync          # 同步到内核
```

---

## 用户使用场景

### 场景1: 查看当前系统识别了哪些域名
```bash
$ aw-bpfctl domain list
===== Domains =====
Index | Domain        | SID | Title
------|---------------|-----|-------
1     | baidu.com     | 101 | 百度
2     | taobao.com    | 102 | 淘宝
...
```

### 场景2: 查看用户访问最多的域名
```bash
$ aw-bpfctl dns list
========================================
  DNS Domain Access Statistics
========================================
Rank  Domain              Access Count  SID   Age   Last Access
----  ------              ------------  ---   ---   -----------
1     baidu.com           15234         101   3h    2m ago
2     taobao.com          12890         102   3h    0m ago
3     wechat.com          9876          105   2h    5m ago
...
```

### 场景3: 程序化处理（脚本/监控）
```bash
# 获取 JSON 数据
$ aw-bpfctl dns json | jq '.domains[] | select(.access_count > 10000)'
{
  "rank": 1,
  "domain": "baidu.com",
  "access_count": 15234,
  "sid": 101,
  ...
}
```

---

## 总结

**不应该合并**！原因：

1. ✅ **职责分离**: `domain` 管理 xDPI 域名，`dns` 统计访问频率
2. ✅ **数据源不同**: 内核 vs 用户态
3. ✅ **用途不同**: 配置管理 vs 监控统计
4. ✅ **扩展性好**: 各自可以独立添加功能

**当前设计是合理的！** 建议保持现状。
