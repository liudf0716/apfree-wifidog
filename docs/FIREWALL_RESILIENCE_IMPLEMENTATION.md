# 防火墙重载免重启实施方案（ApFree WiFiDog）

## 目标
在 OpenWrt 上运行的 apfree-wifidog（wifidogx）在 nftables 防火墙重载/重启后，不再依赖进程重启来恢复 portal 功能，保持 MQTT/WebSocket 远控连接稳定。

## 适用范围
- OpenWrt
- nftables（AW_FW4）为主，iptables（AW_FW3）作为兼容思路
- 现有代码结构：`src/firewall.c`, `src/fw_nft.c`, `src/gateway.c`, `src/ping_thread.c`, `src/dns_monitor.c`, `src/mqtt_thread.c`

---

## 核心设计
### 1) 规则重建器（Reconciler）
将“初始化规则”的逻辑抽象成**可重复调用**函数，用于防火墙重载后的快速恢复。

**目标能力**：
- 检测关键表/链/规则是否存在
- 若缺失则原子式重建
- 恢复 nft set（在线用户、信任域、临时放行）

### 2) 防火墙重载检测
采用“双保险”方式：
- 周期性巡检：每 3–10 秒检查关键链
- 可选系统 hook：在 firewall reload 后触发重建（ubus/信号/Unix socket）

### 3) 状态快照与快速恢复
将在线用户集合等状态**持久化**到本地（轻量文件），重建时直接恢复 nft set，避免全量规则遍历。

### 4) 降级策略
重建失败时：
- 进入“门户降级模式”（暂停 portal 拦截）
- 继续保持 MQTT/WebSocket 连接
- 周期性重试重建

---

## 详细实施步骤

### Step 1：新增防火墙一致性检测接口
新增头文件与接口：
- 文件：`src/firewall.h`
- 新增函数：
  - `int fw_reconcile(void);`  // 核心重建器
  - `int fw_is_ready(void);`   // 检测关键链/规则是否存在

**实施要点**：
- `fw_is_ready()` 只做轻量检测（表/链/关键规则）。
- `fw_reconcile()` 在缺失时创建必要表/链/规则，并恢复 nft set。

### Step 2：实现 nftables 规则存在检测
位置建议：`src/fw_nft.c`

新增函数：
- `int nft_check_core_rules(void);`

检测逻辑建议：
- 使用 `nft list ruleset` 的解析（已有命令执行工具可复用）
- 重点检测：
  - 表（如 `inet apfree`）
  - 关键链（redirect/auth/pass）
  - 关键 jump 规则

### Step 3：实现规则重建器
位置建议：`src/firewall.c`

`fw_reconcile()` 典型流程：
1. `if (fw_is_ready()) return 1;`
2. `fw_destroy()`（清理残留）
3. `fw_init()`（重建核心规则）
4. 恢复 nft set：
   - 已认证用户
   - 可信域/白名单
   - 临时放行

### Step 4：状态快照机制
新增文件：
- `src/client_snapshot.c/.h`

持久化内容：
- 客户端 IP/MAC/状态/过期时间
- 可信域列表（已有域管理可复用）

建议实现：
- 启动时加载快照到内存
- 每 N 秒刷新快照
- 重建时直接基于快照恢复 nft set

### Step 5：巡检线程（无需改系统脚本）
新增线程：`thread_fw_reconcile`（建议放在 `src/gateway.c`）

伪流程：
```
while (running) {
  if (!fw_is_ready()) {
     if (fw_reconcile()) exit_degraded_mode();
     else enter_degraded_mode();
  }
  sleep(3);
}
```

**线程挂载**：
- 在 `threads_init()` 中启动

### Step 6：降级策略
新增全局状态：
- `g_fw_degraded`

行为：
- 降级时关闭 HTTP/HTTPS portal 拦截（可返回固定页面或直接旁路）
- MQTT/WebSocket 保持
- 定期尝试 `fw_reconcile()`

### Step 7：可选系统 hook（更稳）
在 OpenWrt 防火墙脚本中添加：
- `ubus call` 或 `kill -USR1 <pid>` 通知 wifidogx

wifidogx 中监听信号：
- `SIGUSR1` 触发 `fw_reconcile()`

---

## 关键文件修改清单
- `src/firewall.h`
  - 添加 `fw_reconcile()`、`fw_is_ready()` 声明
- `src/firewall.c`
  - 实现 `fw_reconcile()`、`fw_is_ready()`
- `src/fw_nft.c`
  - 添加 `nft_check_core_rules()`
- `src/gateway.c`
  - 新增巡检线程
- `src/client_snapshot.c/.h`
  - 新增状态快照模块
- `src/debug.c`
  - 增加降级状态与重建日志

---

## 运行流程图
```
[启动]
  |
  v
[fw_init]
  |
  v
[启动巡检线程]
  |
  v
[检测规则]
  |      
  |--规则缺失?-->[fw_reconcile]
  |                   |
  |                成功? ----No-->[降级模式 + 重试]
  |                   |
  |                  Yes
  v
[正常运行]
```

---

## 验证与测试
1) 正常启动并认证一个客户端
2) 执行 `service firewall restart`
3) 观察：
   - 进程不退出
   - 3–10 秒内恢复 portal 规则
   - 已认证用户仍能访问
4) 断开认证服务器，重载防火墙，再恢复

---

## 预期收益
- 防火墙重载不再触发 wifidogx 进程重启
- MQTT/WebSocket 远控稳定
- 用户认证状态快速恢复

---

## 版本落地建议
- 首期仅实现巡检 + 重建（不依赖系统 hook）
- 第二期增加快照恢复和 hook
- 第三期优化 nft set 与批量更新性能
