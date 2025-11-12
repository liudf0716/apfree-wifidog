# DNS统计查询功能 - aw-bpfctl 集成

## 功能概述

本次改进为 `aw-bpfctl` 工具添加了 DNS 域名访问统计查询功能，使用户可以通过命令行实时查看域名访问频率排行。

## 实现架构

```
┌─────────────────────────────────────────────────────────────┐
│                 DNS Monitor (dns_monitor.c)                  │
│  - 收集DNS响应                                                │
│  - 统计访问次数                                               │
│  - LFU管理域名                                                │
│  ├─ 每5分钟导出统计 → /tmp/dns_stats.txt                     │
│  └─ 格式化输出供aw-bpfctl读取                                 │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ 文件共享接口
                       │ /tmp/dns_stats.txt
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                aw-bpfctl (aw-bpfctl.c)                       │
│  - 读取统计文件                                               │
│  - 解析域名访问数据                                           │
│  ├─ aw-bpfctl dns list → 表格格式输出                        │
│  └─ aw-bpfctl dns json → JSON格式输出                        │
└─────────────────────────────────────────────────────────────┘
```

---

## 修改内容

### 1. dns_monitor.c 修改

#### 新增常量
```c
#define DNS_STATS_EXPORT_FILE "/tmp/dns_stats.txt"  // 统计导出文件
```

#### 新增函数
```c
static int export_dns_stats_to_file(void)
```

**功能：**
- 从内存中的 `domain_entries[]` 导出统计数据
- 按访问次数降序排序
- 写入格式化的文本文件
- 每5分钟自动更新
- 程序退出时最后更新一次

**导出文件格式：**
```
# DNS Domain Access Statistics
# Format: Rank | Domain | Access Count | SID | First Seen | Last Access
# Generated at: 1696320000
#
1|baidu.com|15234|101|1696300000|1696319950
2|taobao.com|12890|102|1696300100|1696319940
3|qq.com|9876|103|1696300200|1696319930
...
```

#### 集成到主循环
```c
// 每5分钟导出一次
if (current_time - last_save_time >= 300) {
    save_domain_stats_to_file();
    export_dns_stats_to_file();  // 新增
    last_save_time = current_time;
}

// 退出前导出
save_domain_stats_to_file();
export_dns_stats_to_file();  // 新增
```

---

### 2. aw-bpfctl.c 修改

#### 新增常量
```c
#define DNS_STATS_FILE "/tmp/dns_stats.txt"
```

#### 新增数据结构
```c
struct dns_stat_entry {
    int rank;                       // 排名
    char domain[128];               // 域名
    unsigned long long access_count; // 访问次数
    int sid;                        // SID
    time_t first_seen;              // 首次发现时间
    time_t last_access;             // 最后访问时间
};
```

#### 新增函数

**1. `load_dns_stats()`**
- 从文件读取DNS统计数据
- 解析每一行数据
- 填充到 `dns_stat_entry` 数组

**2. `print_dns_stats()`**
- 以表格格式打印统计信息
- 计算人类可读的时间（如"2h ago", "3d"）
- 显示排名、域名、访问次数、SID、存活时长、最后访问

**3. `print_dns_stats_json()`**
- 以JSON格式输出统计信息
- 包含完整的时间戳和相对时间

**4. `handle_dns_command()`**
- 处理 `aw-bpfctl dns list` 和 `aw-bpfctl dns json` 命令

#### 更新 main() 函数
```c
// 支持 dns 命令类型
if (strcmp(map_type, "dns") == 0) {
    if (!is_valid_command(cmd)) {
        fprintf(stderr, "Invalid command for dns. Use 'list' or 'json'.\n");
        aw_bpf_usage();
        return EXIT_FAILURE;
    }
    return handle_dns_command(cmd) ? EXIT_SUCCESS : EXIT_FAILURE;
}
```

#### 更新 usage
```c
fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7|dns> list\n");
fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7|dns> json\n");
fprintf(stderr, "\nDNS Statistics:\n");
fprintf(stderr, "  aw-bpfctl dns list    - Show DNS domain access statistics\n");
fprintf(stderr, "  aw-bpfctl dns json    - Show DNS statistics in JSON format\n");
```

---

## 使用示例

### 命令 1: 查看DNS统计（表格格式）

```bash
aw-bpfctl dns list
```

**输出示例：**
```
========================================================================================================
                              DNS Domain Access Statistics
========================================================================================================
Rank Domain                                   Access Count SID    Age             Last Access    
--------------------------------------------------------------------------------------------------------
1    baidu.com                                15234        101    3h              2m ago         
2    taobao.com                               12890        102    3h              0m ago         
3    qq.com                                   9876         103    2h              5m ago         
4    google.com                               8543         104    3h              1m ago         
5    wechat.com                               7654         105    2h              3m ago         
6    jd.com                                   6789         106    2h              8m ago         
7    alipay.com                               5432         107    1h              4m ago         
8    sina.com.cn                              4321         108    3h              15m ago        
9    163.com                                  3210         109    2h              6m ago         
10   tmall.com                                2987         110    1h              2m ago         
--------------------------------------------------------------------------------------------------------
Total domains: 234
========================================================================================================
```

---

### 命令 2: 查看DNS统计（JSON格式）

```bash
aw-bpfctl dns json
```

**输出示例：**
```json
{
  "total": 234,
  "timestamp": 1696320000,
  "domains": [
    {
      "rank": 1,
      "domain": "baidu.com",
      "access_count": 15234,
      "sid": 101,
      "first_seen": 1696300000,
      "last_access": 1696319950,
      "age_seconds": 20000,
      "last_access_seconds_ago": 50
    },
    {
      "rank": 2,
      "domain": "taobao.com",
      "access_count": 12890,
      "sid": 102,
      "first_seen": 1696300100,
      "last_access": 1696319940,
      "age_seconds": 19900,
      "last_access_seconds_ago": 60
    }
  ]
}
```

---

## 应用场景

### 1. 网络管理员监控

```bash
# 定期检查热门域名
watch -n 60 'aw-bpfctl dns list | head -20'

# 导出JSON用于分析
aw-bpfctl dns json > dns_stats_$(date +%Y%m%d_%H%M%S).json
```

### 2. 自动化脚本集成

```bash
#!/bin/bash
# 获取访问量前5的域名

TOP5=$(aw-bpfctl dns json | jq -r '.domains[:5][] | "\(.domain): \(.access_count)"')
echo "Top 5 Domains:"
echo "$TOP5"

# 发送告警
if echo "$TOP5" | grep -q "suspicious-domain.com"; then
    echo "Alert: Suspicious domain detected!" | mail -s "Security Alert" admin@example.com
fi
```

### 3. Web Dashboard 数据源

```javascript
// Node.js 示例
const { exec } = require('child_process');

app.get('/api/dns-stats', (req, res) => {
    exec('aw-bpfctl dns json', (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr });
        }
        res.json(JSON.parse(stdout));
    });
});
```

---

## 数据更新频率

| 操作 | 频率 | 说明 |
|------|------|------|
| DNS访问计数 | 实时 | 每次DNS响应立即更新内存 |
| 文件导出 | 5分钟 | 定期写入 `/tmp/dns_stats.txt` |
| aw-bpfctl读取 | 按需 | 用户执行命令时读取文件 |

**注意：** 文件最多延迟5分钟，对于实时监控需求，可以修改导出频率。

---

## 性能考虑

### 文件I/O性能
- 文件大小：约10-20KB（256个域名）
- 写入耗时：<10ms
- 读取耗时：<5ms
- **影响：** 几乎可忽略

### 内存使用
- 导出缓冲区：约64KB（临时排序用）
- **影响：** 微不足道

### CPU开销
- 排序操作：O(n log n)，n=256
- 格式化输出：O(n)
- **影响：** 每5分钟一次，可忽略

---

## 故障排查

### 问题 1: 文件不存在
```
Failed to open DNS stats file: /tmp/dns_stats.txt
Make sure wifidog DNS monitor is running.
```

**原因：**
- DNS monitor 未启动
- 首次启动未满5分钟（还未导出）

**解决：**
```bash
# 检查DNS monitor是否运行
ps aux | grep wifidog

# 等待5分钟后重试
sleep 300 && aw-bpfctl dns list
```

### 问题 2: 数据为空
```
No DNS statistics available.
```

**原因：**
- 系统刚启动，还没有DNS流量
- DNS响应未被eBPF捕获

**解决：**
```bash
# 生成一些DNS流量
nslookup google.com
nslookup baidu.com

# 等待统计更新
sleep 10 && aw-bpfctl dns list
```

### 问题 3: 权限问题
```
Permission denied: /tmp/dns_stats.txt
```

**解决：**
```bash
# 检查文件权限
ls -l /tmp/dns_stats.txt

# 修复权限（由root运行wifidog）
sudo chmod 644 /tmp/dns_stats.txt
```

---

## 扩展建议

### 1. 实时更新
如果需要更快的更新频率，修改导出间隔：

```c
// 在 dns_monitor.c 中
// 从 300秒（5分钟）改为 60秒（1分钟）
if (current_time - last_save_time >= 60) {  // 改这里
    save_domain_stats_to_file();
    export_dns_stats_to_file();
    last_save_time = current_time;
}
```

### 2. 过滤功能
为 `aw-bpfctl` 添加过滤选项：

```bash
# 仅显示访问量>1000的域名
aw-bpfctl dns list --min-count 1000

# 仅显示前N个域名
aw-bpfctl dns list --top 10

# 搜索特定域名
aw-bpfctl dns list --domain baidu
```

### 3. 历史趋势
保存历史快照进行趋势分析：

```bash
# 定时保存快照
*/5 * * * * aw-bpfctl dns json > /var/log/dns_stats/$(date +\%Y\%m\%d_\%H\%M).json

# 分析趋势
python3 analyze_dns_trends.py /var/log/dns_stats/
```

---

## 对比其他工具

| 工具 | DNS统计 | 实时性 | 易用性 | 性能 |
|------|---------|--------|--------|------|
| **aw-bpfctl** | ✅ | 5分钟延迟 | ⭐⭐⭐⭐⭐ | 极高 |
| tcpdump | ❌ | 实时 | ⭐⭐ | 低 |
| wireshark | ✅ | 实时 | ⭐⭐⭐ | 低 |
| dnsmasq log | ✅ | 实时 | ⭐⭐ | 中等 |

**优势：**
- 零配置，开箱即用
- 统一的命令行接口
- JSON格式便于集成
- 基于eBPF，性能极佳

---

## 总结

通过这次改进，`aw-bpfctl` 工具现在可以：

✅ 查询DNS域名访问排行  
✅ 显示域名访问频率  
✅ 导出JSON格式数据  
✅ 集成到自动化脚本  
✅ 为Web Dashboard提供数据  

这使得wifidog系统的DNS监控功能更加完善和实用！
