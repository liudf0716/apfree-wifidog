# DNS Monitor LFU Enhancement - 改进说明

## 概述

本次改进为 `dns_monitor.c` 增加了完整的访问频率统计和 LFU (Least Frequently Used) 淘汰算法，使其能够真正实现"获取用户访问最多的域名并下发到 xDPI"的设计目标。

## 改进内容

### 1. ✅ 增强数据结构

#### 修改的结构体：`struct domain_entry`

```c
struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    int domain_len;
    int sid;
    bool used;
    // 新增字段 ↓
    __u64 access_count;         // 访问计数
    time_t last_access_time;    // 最后访问时间
    time_t first_seen_time;     // 首次发现时间
};
```

**新增常量：**
- `LFU_MIN_ACCESS_THRESHOLD` = 5 (最少访问阈值)
- `TOP_DOMAINS_REPORT_INTERVAL` = 600秒 (10分钟报告周期)
- `TOP_DOMAINS_COUNT` = 20 (报告前20个热门域名)
- `DOMAIN_STATS_FILE` = "/tmp/wifidog_domain_stats.dat" (持久化文件路径)

---

### 2. ✅ 实现 LFU 淘汰算法

#### 核心改进：`xdpi_add_domain()` 函数

**之前的逻辑：**
```
遇到域名 → 检查是否存在 → 不存在则添加
如果数组满了 → 直接拒绝 ❌
```

**现在的逻辑：**
```
遇到域名 → 检查是否存在
  ├─ 存在 → 增加 access_count++，更新 last_access_time
  └─ 不存在 → 寻找空槽位
      ├─ 有空槽 → 直接添加，初始 access_count=1
      └─ 无空槽 → 调用 LFU 算法
          ├─ 找到访问次数 < 5 的域名 → 淘汰并替换
          └─ 所有域名访问次数都 ≥ 5 → 拒绝添加
```

#### 新增函数：

1. **`find_least_frequently_used_domain()`**
   - 查找访问频率最低的域名
   - 如果访问次数相同，淘汰最久未访问的（LRU+LFU混合策略）

2. **`remove_domain_from_kernel()`**
   - 从内核 xDPI 模块删除域名
   - 通过 `XDPI_IOC_DEL` ioctl 实现
   - 记录淘汰日志

---

### 3. ✅ 定期统计和报告功能

#### 新增函数：

**`print_top_domains(int top_n)`**
- 对域名按访问次数降序排序
- 打印热门域名及其统计信息
- 显示内容：
  - 排名
  - 域名
  - 访问次数
  - 最后访问时间（多少分钟前）
  - 存活时长（多少小时）
  - SID

**`compare_domain_by_access_count()`**
- qsort 比较函数
- 按访问次数降序排列
- 未使用的条目排在最后

#### 主循环集成：

在 `dns_monitor_thread()` 中增加定期任务：
- **每 30 秒**：打印 eBPF 统计信息（DNS查询/响应数量）
- **每 10 分钟**：报告 Top 20 热门域名
- **每 5 分钟**：保存域名统计到文件

**输出示例：**
```
========================================
  Top 20 Most Accessed Domains
========================================
#1  baidu.com                             | Count: 15234    | Last: 2m ago | Age: 3h | SID: 101
#2  taobao.com                            | Count: 12890    | Last: 0m ago | Age: 3h | SID: 102
#3  wechat.com                            | Count: 9876     | Last: 5m ago | Age: 2h | SID: 105
...
========================================
```

---

### 4. ✅ 持久化功能

#### 新增函数：

**`save_domain_stats_to_file()`**
- 保存域名统计到二进制文件
- 文件格式：
  ```
  [魔数: 0x44535441] [版本: 1] [有效条目数] [条目1] [条目2] ...
  ```
- 每 5 分钟自动保存
- 程序退出时最后保存一次

**`load_domain_stats_from_file()`**
- 从文件恢复域名统计
- 验证魔数和版本号
- 加载后自动同步到内核 xDPI
- 在 `dns_monitor_thread()` 启动时首先调用

#### 使用场景：

**系统重启后：**
```
1. dns_monitor 启动
2. 调用 load_domain_stats_from_file()
3. 从 /tmp/wifidog_domain_stats.dat 恢复统计
4. 包含所有历史访问计数
5. 热门域名立即可用，无需重新积累
```

---

## 工作流程对比

### 改进前：

```
DNS响应 → 解析域名 → 检查是否有效后缀 → 尝试添加到xDPI
                                         ↓
                                    数组满了 → 拒绝 ❌
```

**问题：**
- 第一批遇到的 256 个域名永久占据位置
- 无法知道哪些域名访问频繁
- 低频域名占用宝贵的缓存空间

### 改进后：

```
DNS响应 → 解析域名 → 检查是否有效后缀
           ↓
    已存在？→ 是 → 增加访问计数 ✅
           ↓ 否
    有空槽？→ 是 → 添加，计数=1 ✅
           ↓ 否
    LFU淘汰 → 找到低频域名 → 淘汰并替换 ✅
           ↓ 无低频域名
    拒绝添加（保护高频域名） ✅
```

**优势：**
- 动态管理，高频域名始终保留
- 低频域名自动淘汰
- 统计完整，可查看热门域名
- 持久化支持，重启不丢失数据

---

## 性能影响分析

### 内存开销：

每个 `domain_entry` 增加：
- `access_count`: 8 字节
- `last_access_time`: 8 字节
- `first_seen_time`: 8 字节

总增加：`256 * 24 = 6KB`（几乎可忽略）

### CPU 开销：

1. **访问计数更新**：O(1) - 仅一次加法
2. **LFU 查找**：O(256) - 仅在数组满时触发（罕见）
3. **Top N 排序**：O(256 log 256) - 每10分钟一次，影响极小
4. **持久化保存**：O(256) - 每5分钟一次，影响极小

**结论：性能影响微乎其微**

---

## 使用建议

### 调优参数：

根据实际环境调整以下常量：

```c
// 如果环境中域名变化频繁，可降低阈值
#define LFU_MIN_ACCESS_THRESHOLD 3  // 默认 5

// 如果希望更频繁地查看统计
#define TOP_DOMAINS_REPORT_INTERVAL 300  // 改为5分钟

// 如果希望看到更多热门域名
#define TOP_DOMAINS_COUNT 50  // 默认 20
```

### 监控建议：

1. **查看实时日志**：
   ```bash
   tail -f /var/log/wifidog.log | grep "Top.*Most Accessed Domains"
   ```

2. **查看持久化文件**：
   ```bash
   ls -lh /tmp/wifidog_domain_stats.dat
   ```

3. **手动触发保存**（如果需要）：
   - 向 wifidog 进程发送 SIGTERM，程序会在退出前保存

---

## 测试验证

### 编译测试：

```bash
cd /home/liudf/work/wifidogx/build
cmake ../apfree-wifidog
make
```

### 运行测试：

1. 启动 wifidog
2. 观察日志中的"Top Domains"报告（10分钟后）
3. 验证 `/tmp/wifidog_domain_stats.dat` 文件生成
4. 重启 wifidog，验证统计数据恢复

---

## 潜在扩展

### 未来可以添加：

1. **导出 API**：通过 HTTP 接口查询热门域名
2. **实时仪表板**：Web UI 展示域名访问排行
3. **域名分类**：按访问类型（社交/视频/购物）分类统计
4. **时间窗口统计**：最近1小时/24小时的热门域名
5. **用户级统计**：每个用户的访问偏好

---

## 总结

本次改进彻底解决了原有实现的"先到先得"问题，实现了真正的**基于访问频率的智能域名管理**。系统现在能够：

✅ 准确统计每个域名的访问次数  
✅ 自动淘汰低频域名  
✅ 定期报告热门域名排行  
✅ 持久化保存统计数据  
✅ 系统重启后快速恢复

这使得 xDPI 域名识别系统能够更高效地利用有限的缓存空间，始终保持最热门的域名在内核中，提升整体性能和准确性。
