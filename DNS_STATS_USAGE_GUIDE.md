# aw-bpfctl DNS 统计功能使用指南

## 功能概述

`aw-bpfctl dns` 命令用于查询 DNS 域名访问统计信息，这些统计数据由 `dns_monitor` 模块实时收集并定期导出。

---

## 命令对比

### `aw-bpfctl domain` vs `aw-bpfctl dns`

| 特性 | `domain <list\|json>` | `dns <list\|json>` |
|------|---------------------|-------------------|
| **数据源** | `/proc/xdpi_domains` (内核) | `/tmp/dns_stats.txt` (用户态) |
| **内容** | xDPI 注册的域名列表 | DNS 访问统计信息 |
| **信息** | 域名、SID、标题 | 访问次数、排名、时间 |
| **用途** | 查看系统识别的域名 | 查看用户访问频率 |
| **动态性** | 相对静态 | 实时更新 |

---

## 命令用法

### 1. 列表格式查看 DNS 统计

```bash
aw-bpfctl dns list
```

**输出示例**:
```
========================================================================================================
                              DNS Domain Access Statistics
========================================================================================================
Rank Domain                                   Access Count SID    Age            Last Access    
--------------------------------------------------------------------------------------------------------
1    baidu.com                               15234        101    3h             2m ago         
2    taobao.com                              12890        102    3h             0m ago         
3    wechat.com                              9876         105    2h             5m ago         
4    qq.com                                  8765         108    2h             1m ago         
5    google.com                              7654         110    3h             10m ago        
6    youtube.com                             6543         112    2h             3m ago         
7    facebook.com                            5432         115    1h             20m ago        
...
--------------------------------------------------------------------------------------------------------
Total domains: 156
========================================================================================================
```

**字段说明**:
- **Rank**: 排名（按访问次数降序）
- **Domain**: 域名
- **Access Count**: 总访问次数
- **SID**: xDPI Session ID
- **Age**: 首次发现到现在的时长
- **Last Access**: 最后一次访问的时间

---

### 2. JSON 格式输出

```bash
aw-bpfctl dns json
```

**输出示例**:
```json
{
  "total": 156,
  "timestamp": 1728000000,
  "domains": [
    {
      "rank": 1,
      "domain": "baidu.com",
      "access_count": 15234,
      "sid": 101,
      "first_seen": 1727989200,
      "last_access": 1727999880,
      "age_seconds": 10800,
      "last_access_seconds_ago": 120
    },
    {
      "rank": 2,
      "domain": "taobao.com",
      "access_count": 12890,
      "sid": 102,
      "first_seen": 1727989200,
      "last_access": 1728000000,
      "age_seconds": 10800,
      "last_access_seconds_ago": 0
    },
    ...
  ]
}
```

**JSON 字段说明**:
- `total`: 域名总数
- `timestamp`: 当前时间戳
- `domains`: 域名数组
  - `rank`: 排名
  - `domain`: 域名
  - `access_count`: 访问次数
  - `sid`: Session ID
  - `first_seen`: 首次发现时间戳
  - `last_access`: 最后访问时间戳
  - `age_seconds`: 存活时长（秒）
  - `last_access_seconds_ago`: 距上次访问的秒数

---

## 使用场景

### 场景 1: 监控热门网站

查看用户最常访问的网站：

```bash
aw-bpfctl dns list | head -20
```

### 场景 2: 导出统计数据

将统计数据导出为 JSON 文件：

```bash
aw-bpfctl dns json > dns_stats_$(date +%Y%m%d_%H%M%S).json
```

### 场景 3: 查询特定域名

使用 `grep` 查找特定域名的统计：

```bash
aw-bpfctl dns list | grep "baidu"
```

### 场景 4: 程序化处理

使用 `jq` 处理 JSON 数据：

```bash
# 查询访问次数超过 10000 的域名
aw-bpfctl dns json | jq '.domains[] | select(.access_count > 10000)'

# 统计前 10 个域名的总访问量
aw-bpfctl dns json | jq '[.domains[:10] | .[].access_count] | add'

# 查找最近 5 分钟内访问过的域名
aw-bpfctl dns json | jq '.domains[] | select(.last_access_seconds_ago < 300)'
```

### 场景 5: 监控脚本

创建定期监控脚本：

```bash
#!/bin/bash
# monitor_dns.sh - 每小时记录一次 DNS 统计

LOG_DIR="/var/log/dns_stats"
mkdir -p "$LOG_DIR"

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    aw-bpfctl dns json > "$LOG_DIR/dns_stats_$TIMESTAMP.json"
    echo "$(date): DNS statistics saved to dns_stats_$TIMESTAMP.json"
    sleep 3600  # 每小时执行一次
done
```

### 场景 6: 告警系统

检测异常访问模式：

```bash
#!/bin/bash
# alert_high_access.sh - 检测访问次数异常高的域名

THRESHOLD=50000

aw-bpfctl dns json | jq -r ".domains[] | select(.access_count > $THRESHOLD) | 
    \"ALERT: \(.domain) has \(.access_count) accesses (threshold: $THRESHOLD)\""
```

---

## 数据更新频率

DNS 统计数据的更新机制：

1. **实时统计**: DNS 响应到达时立即更新内存中的计数器
2. **文件导出**: 每 5 分钟自动导出一次到 `/tmp/dns_stats.txt`
3. **程序退出**: wifidog 退出时会最后导出一次

因此，`aw-bpfctl dns` 命令读取的数据最多延迟 5 分钟。

---

## 故障排查

### 问题 1: "Failed to open DNS stats file"

**原因**: DNS monitor 未运行或统计文件未生成

**解决方案**:
```bash
# 检查 wifidog 是否运行
ps aux | grep wifidog

# 检查统计文件是否存在
ls -l /tmp/dns_stats.txt

# 检查 wifidog 日志
tail -f /var/log/wifidog.log | grep "DNS"
```

### 问题 2: 统计数据为空

**原因**: 
- wifidog 刚启动，还没有 DNS 流量
- DNS monitor 功能未启用

**解决方案**:
```bash
# 等待几分钟让统计数据积累
# 或手动触发一些 DNS 查询
nslookup baidu.com
nslookup google.com

# 5分钟后再查询
aw-bpfctl dns list
```

### 问题 3: 数据不更新

**原因**: DNS monitor 线程可能出现问题

**解决方案**:
```bash
# 检查日志
tail -100 /var/log/wifidog.log | grep -E "DNS|domain"

# 重启 wifidog
/etc/init.d/wifidog restart
```

---

## 与其他命令的配合使用

### 1. 结合 `domain` 命令

```bash
# 查看 xDPI 注册的域名
aw-bpfctl domain list

# 查看这些域名的访问统计
aw-bpfctl dns list
```

### 2. 结合 `l7` 命令

```bash
# 查看 L7 协议统计
aw-bpfctl l7 list

# 查看域名访问统计
aw-bpfctl dns list
```

### 3. 综合监控脚本

```bash
#!/bin/bash
# comprehensive_stats.sh - 综合统计报告

echo "===== xDPI Domain List ====="
aw-bpfctl domain list

echo ""
echo "===== DNS Access Statistics (Top 20) ====="
aw-bpfctl dns list | head -25

echo ""
echo "===== L7 Protocol Statistics ====="
aw-bpfctl l7 list
```

---

## 性能考虑

- **文件读取**: 命令执行时读取 `/tmp/dns_stats.txt`，通常小于 100KB
- **响应时间**: < 100ms（取决于域名数量）
- **资源占用**: 极低，只进行文件读取和格式化输出
- **并发安全**: 可以同时执行多个 `aw-bpfctl dns` 命令

---

## 未来扩展

可能的功能增强：

```bash
# 计划中的功能
aw-bpfctl dns top [N]              # 只显示前 N 个
aw-bpfctl dns search <domain>      # 搜索特定域名
aw-bpfctl dns reset                # 重置统计
aw-bpfctl dns export [file]        # 导出到指定文件
aw-bpfctl dns filter <pattern>     # 过滤域名
```

---

## 总结

`aw-bpfctl dns` 命令提供了强大的 DNS 访问统计查询功能，与现有的 `domain` 和 `l7` 命令相辅相成，共同构成完整的网络流量监控体系。

**关键优势**:
- ✅ 实时统计，准确反映用户访问行为
- ✅ 支持文本和 JSON 两种输出格式
- ✅ 易于集成到监控和告警系统
- ✅ 与 xDPI 域名管理无缝配合
