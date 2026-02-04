# 防火墙重载免重启实施方案（ApFree WiFiDog）

## 目标
在 OpenWrt 上运行的 apfree-wifidog（wifidogx）采用**独立 wifidogx 表**承载全部规则，并将 hook 优先级设置为**最高**，实现：
1) 防火墙重载/重启后不依赖进程重启恢复 portal。
2) 与 fw4 规则解耦，便于检测 fw4 重启。
3) 规则恢复更快且代价更小。

## 适用范围
- OpenWrt + firewall4（nftables）
- 仅实现 AW_FW4 路径（不覆盖 AW_FW3）
- 现有代码结构：`src/firewall.c`, `src/fw_nft.c`, `src/gateway.c`, `src/wdctlx_thread.c`, `src/client_snapshot.c`

---

## 核心设计（方案A：独立 wifidogx 表 + 最高优先级）
### 1) 独立表与最高优先级 hook
将全部规则迁移到 `inet wifidogx` 表，**不再依赖 `inet fw4` 表及其链**。在 `wifidogx` 表内创建：
- `prerouting`（`type nat hook prerouting priority -300`）
- `forward`（`type filter hook forward priority -300`）

这样 wifidogx 规则始终先于 fw4 执行，最大化 portal 劫持一致性。

### 2) 规则重建器（Reconciler）
将“初始化规则”的逻辑抽象成**可重复调用**函数，用于防火墙重载后的快速恢复。

**目标能力**：
- 检测关键表/链/规则是否存在
- 若缺失则原子式重建
- 恢复 nft set（在线用户、信任域、临时放行）

### 3) 防火墙重载检测
采用**固定实现**：
- 周期性巡检：每 3 秒检查 `inet wifidogx` 表与关键链是否存在

不使用 firewall reload hook。

### 4) 状态快照与快速恢复
将在线用户集合等状态**持久化**到本地（轻量文件），重建时直接恢复 nft set，避免全量规则遍历。

### 5) 降级策略
重建失败时：
- 进入“门户降级模式”（暂停 portal 拦截）
- 继续保持 MQTT/WebSocket 连接
- 周期性重试重建

---

## 详细实施步骤

### Step 1：规则迁移到独立 wifidogx 表（核心）
将当前所有 fw4 依赖链与 set 移动到 `inet wifidogx` 表：
- 不再创建 `inet fw4` 的 `dstnat_wifidogx_*` / `forward_wifidogx_*` 链
- 不再插入 `accept_to_wan` 等 fw4 链
- 所有 set 与链归属 `inet wifidogx`

**优先级设置**：
- `prerouting`：`priority -300`（高于 fw4 的默认 dstnat 优先级）
- `forward`：`priority -300`（高于 fw4 的默认 forward）

### Step 2：新增防火墙一致性检测接口
新增头文件与接口：
- 文件：`src/firewall.h`
- 新增函数：
  - `int fw_reconcile(void);`  // 核心重建器
  - `int fw_is_ready(void);`   // 检测关键链/规则是否存在

**实施要点**：
- `fw_is_ready()` 只做轻量检测（表/链/关键规则）。
- `fw_reconcile()` 在缺失时创建必要表/链/规则，并恢复 nft set。

### Step 3：实现 nftables 规则存在检测
位置：`src/fw_nft.c`

新增函数：
- `int nft_check_core_rules(void);`

检测逻辑要求：
- 使用 `nft list table inet wifidogx`、`nft list chain inet wifidogx <chain>`
- 必须检测以下对象存在：
  - 表：`inet wifidogx`
  - 链：`prerouting`、`forward`、`dstnat_wifidogx_unknown`、`dstnat_wifidogx_auth_server`、`dstnat_wifidogx_trust_domains`、`dstnat_wifidogx_wildcard_trust_domains`、`forward_wifidogx_unknown`、`forward_wifidogx_auth_servers`、`forward_wifidogx_trust_domains`
  - 规则：
    - `prerouting` 中必须存在对 80/443 的 redirect 规则
    - `forward` 中必须存在对 auth server / trust domains 的 accept 规则

### Step 4：实现规则重建器
位置：`src/firewall.c`

`fw_reconcile()` 典型流程：
1. `if (fw_is_ready()) return 1;`
2. `fw_destroy()`（仅清理 wifidogx 表与链）
3. `fw_init()`（重建核心规则，确保 hook 优先级为 -300）
4. 恢复 nft set：
   - 已认证用户
   - 可信域/白名单
   - 临时放行

### Step 5：状态快照机制（统一迁移到 client_snapshot）
新增 `src/client_snapshot.c/.h`，并**移除** `bypass_user.c/.h`。

持久化内容：
- `trustedmaclist`（包含 `remaining_time` 字段）
- `online_clients`（客户端 IP/MAC/first_login/last_updated/auth_type + 统计字段）

实现要求：
- 启动时调用 `client_snapshot_load()` 恢复并写入 nft set
- 每 60 秒调用一次 `client_snapshot_save()`
- `fw_reconcile()` 成功后立刻调用恢复逻辑

### Step 6：巡检线程（无需改系统脚本）
新增线程：`thread_fw_reconcile`（放在 `src/gateway.c`），该线程同时负责：
- 每 3 秒执行 `fw_is_ready()`
- 每 60 秒执行 `client_snapshot_save()`

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

### Step 7：降级策略
新增全局状态：
- `g_fw_degraded`

行为：
- 降级时关闭 HTTP/HTTPS portal 拦截（可返回固定页面或直接旁路）
- MQTT/WebSocket 保持
- 定期尝试 `fw_reconcile()`

### Step 8：不使用系统 hook
不添加 firewall reload hook，也不使用 `SIGUSR1` 触发重建。

---

## 关键文件修改清单
- `src/firewall.h`
  - 添加 `fw_reconcile()`、`fw_is_ready()` 声明
- `src/firewall.c`
  - 实现 `fw_reconcile()`、`fw_is_ready()`
- `src/fw_nft.c`
  - 修改初始化规则脚本，全部迁移到 `inet wifidogx`
  - 添加 `nft_check_core_rules()`
- `src/gateway.c`
  - 新增巡检线程
- `src/client_snapshot.c/.h`
  - 新增快照模块（保存/恢复 online_clients 与 trustedmaclist）
- `src/wdctlx_thread.c`
  - 迁移 `save_user/restore_user` 到 client_snapshot
- `src/bypass_user.c/.h`
  - 删除文件与全部引用
- `src/debug.c`
  - 增加降级状态与重建日志

---

## 规则迁移清单（从 fw4 迁移到 wifidogx）
**目标**：所有规则与 set 仅存在于 `inet wifidogx` 表中，避免依赖 `inet fw4` 的链/规则。

### 0) 现有 wifidogx 表的合并冲突处理（必须执行）
当前实现已存在 `inet wifidogx` 表与部分链/规则（含 anti-nat 逻辑）。迁移时必须按以下合并规则执行，避免冲突：

1) **复用现有表/链，不重复创建**
- 仅保留一个 `wifidogx.prerouting` 链
- 仅保留一个 `wifidogx.mangle_prerouting` 链

2) **统一 `prerouting` hook 优先级**
- 将现有 `prerouting` 的 priority 统一为 **-300**
- 不允许同名链存在多个不同 priority

3) **在 `prerouting` 内分流子链**
新增并固定顺序：
- `wifidogx_antinat`（承载 anti-nat 规则）
- `wifidogx_redirect`（承载 portal redirect 规则）

固定顺序：
1. `jump wifidogx_antinat`
2. 放行白名单/认证用户
3. `jump wifidogx_redirect`

4) **mangle_prerouting 保留原逻辑**
- anti-nat 的 mangle 规则继续保留在 `wifidogx.mangle_prerouting`
- 不在 mangle 链中做 redirect

5) **set 重名冲突处理（强制改名）**
- 将原有 `wifidogx` 表内用于 anti-nat 的 `set_wifidogx_local_trust_clients` 改名为：
  - `set_wifidogx_antinat_local_macs`
- 迁移后的 trustedmaclist 相关 set 使用：
  - `set_wifidogx_trust_clients_out`
- 禁止复用同名 set；所有规则与代码引用必须同步改名

### 1) 表与链
迁移前（示意）：
- 表：`inet fw4`
- 链：`dstnat_wifidogx_*`、`forward_wifidogx_*`、`accept_to_wan`

迁移后（固定命名）：
- 表：`inet wifidogx`
- 链：
  - `prerouting`（hook=prerouting, type=nat, priority=-300）
  - `forward`（hook=forward, type=filter, priority=-300）
  - `dstnat_wifidogx_auth_server`
  - `dstnat_wifidogx_trust_domains`
  - `dstnat_wifidogx_wildcard_trust_domains`
  - `dstnat_wifidogx_unknown`
  - `forward_wifidogx_auth_servers`
  - `forward_wifidogx_trust_domains`
  - `forward_wifidogx_unknown`

### 2) set 定义
将所有 `set_wifidogx_*` 从 `inet fw4` 迁移到 `inet wifidogx`：
- `set_wifidogx_auth_servers`
- `set_wifidogx_auth_servers_v6`
- `set_wifidogx_gateway`
- `set_wifidogx_gateway_v6`
- `set_wifidogx_trust_domains`
- `set_wifidogx_trust_domains_v6`
- `set_wifidogx_wildcard_trust_domains`
- `set_wifidogx_wildcard_trust_domains_v6`
- `set_wifidogx_inner_trust_domains`
- `set_wifidogx_inner_trust_domains_v6`
- `set_wifidogx_bypass_clients`
- `set_wifidogx_bypass_clients_v6`
- `set_wifidogx_trust_clients_out`
- `set_wifidogx_tmp_trust_clients`
- `set_wifidogx_antinat_local_macs`

### 3) 规则迁移映射
将下列规则从 `inet fw4` 迁移到 `inet wifidogx`：
- `dstnat_wifidogx_outgoing` 与其 `jump dstnat_wifidogx_wan`
- `dstnat_wifidogx_wan` 中的 trust/bypass/mark 放行
- `dstnat_wifidogx_unknown` 中的 HTTPS/HTTP redirect
- `dstnat_wifidogx_auth_server`/`trust_domains`/`wildcard_trust_domains` 放行
- `forward_wifidogx_wan` 与 `forward_wifidogx_*` 规则

**移除**：
- `insert rule inet fw4 accept_to_wan jump forward_wifidogx_wan`

---

## 最高优先级规则设计（避免冲突）
### 1) 优先级设置（固定）
- `prerouting`：`priority -300`（高于 fw4 dstnat 默认 -100）
- `forward`：`priority -300`（高于 fw4 默认 0）

### 2) 冲突规避原则
1) **先放行后重定向**：在 prerouting 中优先放行已认证/可信/绕行流量，避免重复重定向。
2) **只对未认证流量重定向**：所有 redirect 规则必须在“未命中放行条件”之后。
3) **避免双重标记**：使用单一 `meta mark` 或 set，作为认证状态的唯一判据。

### 3) 固定顺序（prerouting）
1. 放行 gateway 本机/白名单/绕行客户端
2. 放行已认证（set / mark）
3. 放行 auth server / trust domains
4. 未命中 -> http/https redirect

---

## 快速恢复设计（低代价）
### 1) 恢复优先级
1) 表与核心 hook 链
2) set 定义
3) set 元素（在线用户/可信域）
4) redirect/forward 规则

### 2) 增量恢复策略
避免 `flush ruleset` 与全量重建，使用：
- `nft list table inet wifidogx` 检测是否存在
- `nft list chain inet wifidogx <chain>` 检测链
- 仅缺失则创建

### 3) 批量恢复 set
必须使用批量 `add element`：
- 将在线用户/IP/域名拼成 `add element inet wifidogx set_x { ... }`
- 一次性写入，减少命令调用与锁争用

---

## fw4 重启检测与处置
### 检测方法（固定）
仅采用：
- 巡检线程每 3 秒检测 `inet wifidogx` 表与关键链

### 处置策略（固定）
检测到规则缺失时：
- 立即触发 `fw_reconcile()`
- 若 wifidogx 表仍在，仅补齐缺失链/规则
- 若表被清空，则完整重建

---

## 具体改动清单（函数级）
### 1) `src/fw_nft.c`
- 修改 `nft_wifidogx_init_script[]`：所有 `inet fw4` 改为 `inet wifidogx`
- 新增 `nft_check_core_rules()`：检测 `inet wifidogx` 表与关键链
- 新增 `nft_reconcile_rules()`：增量创建缺失表/链/规则

### 2) `src/firewall.c`
- `fw_is_ready()` 调用 `nft_check_core_rules()`
- `fw_reconcile()` 调用 `nft_reconcile_rules()` + `restore_sets()`

### 3) `src/gateway.c`
- 新增 `thread_fw_reconcile`，周期巡检
- 若降级：暂停 portal 拦截但不停止 MQTT/WebSocket

---

## 快照机制实现方案（统一 client_snapshot）
### 背景与结论
将快照功能统一迁移到 `client_snapshot`，并完全移除 `bypass_user` 模块。

### 快照文件
路径固定为：`/etc/client_snapshot.json`

### JSON 格式（固定）
```
{
  "trustedmaclist": [
    { "mac": "AA:BB:CC:DD:EE:FF", "serial": "S001", "remaining_time": 3600, "first_time": 1707000000 }
  ],
  "online_clients": [
    {
      "mac": "AA:BB:CC:DD:EE:11",
      "ip": "192.168.1.10",
      "first_login": 1707000100,
      "last_updated": 1707000200,
      "auth_type": "AUTH_SERVER",
      "incoming_bytes": 123456,
      "outgoing_bytes": 654321,
      "incoming_packets": 1200,
      "outgoing_packets": 1100,
      "incoming_rate": 1024,
      "outgoing_rate": 2048
    }
  ]
}
```

### 接口（固定）
新增接口：
- `int client_snapshot_save(void);`
- `int client_snapshot_load(void);`
- `char *client_snapshot_dump_json(void);`
- `char *client_snapshot_query_status(const char *key, const char *gw_mac, const char *gw_address, query_choice_t choice);`

### 头文件定义（固定）
新增头文件：`src/client_snapshot.h`
```
#ifndef _CLIENT_SNAPSHOT_H_
#define _CLIENT_SNAPSHOT_H_

#include <stdbool.h>

typedef enum {
  QUERY_BY_IP = 0,
  QUERY_BY_MAC = 1
} query_choice_t;

int client_snapshot_save(void);
int client_snapshot_load(void);
char *client_snapshot_dump_json(void);
char *client_snapshot_query_status(const char *key,
                   const char *gw_mac,
                   const char *gw_address,
                   query_choice_t choice);

bool client_snapshot_add_trusted_mac(const char *mac, uint32_t remaining_time, const char *serial);
bool client_snapshot_remove_trusted_mac(const char *mac);

#endif
```

### 实现要求（固定）
- `client_snapshot_dump_json()` 输出兼容 `wdctlx apfree user_list`
- `client_snapshot_query_status()` 输出兼容当前 HTTP 查询接口
- `client_snapshot_add_trusted_mac/remove_trusted_mac` 维护 `trustedmaclist`

### 修改点（固定）
1) **保存**：
  - 在 `client_snapshot_save()` 中序列化 `trustedmaclist` + `client_list`
  - 对在线客户端保存 `first_login`、`counters.last_updated` 与流量统计字段
2) **恢复**：
  - 在 `client_snapshot_load()` 中恢复 `trustedmaclist` + `client_list`
  - 在线客户端恢复 `first_login`、`counters.last_updated` 与流量统计字段
  - 恢复后立即写入 nft set（认证/放行 set）
3) **触发时机**：
  - 启动后自动调用 `client_snapshot_load()`
  - 巡检线程每 60 秒调用 `client_snapshot_save()`
  - `fw_reconcile()` 成功后立刻调用 `client_snapshot_load()`

### 迁移与删除
- 删除文件：`src/bypass_user.c/.h`
- 删除 `wdctlx apfree save_user/restore_user` 的旧实现
- 新的 `save_user/restore_user` 直接调用 `client_snapshot_save/load`

### 恢复后的规则联动
恢复在线用户后必须：
- 立即写入 nft set（已认证/临时放行/绕行）
- 调用 `fw_set_trusted_maclist()` 等同步接口

---

## 快照整合后的验证点
1) 执行 `wdctlx apfree save_user` 后，检查 /etc/client_snapshot.json 含 `online_clients`
2) 重启进程后自动恢复在线用户并写入 nft set
3) `service firewall restart` 后不重启进程也能恢复认证状态

---

## 删除 bypass_user 的引用清单（必须全部迁移/替换）
以下引用必须删除或改为 `client_snapshot` 实现：

1) 头文件引用
- [src/conf.h](src/conf.h#L13) 引用 `bypass_user.h`

2) 规则初始化与恢复调用
- [src/firewall.c](src/firewall.c#L266) 调用 `load_bypass_user_list()`

3) HTTP 端点查询
- [src/http.c](src/http.c#L1218) 调用 `query_bypass_user_status()`

4) 控制接口与命令处理
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L871) `dump_bypass_user_list_json()`
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L883) `save_bypass_user_list()`
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L890) `load_bypass_user_list()`
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L950) `remove_bypass_user()`
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L952) `add_bypass_user()`
- [src/wdctlx_thread.c](src/wdctlx_thread.c#L961) `save_bypass_user_list()`

5) 文件本体
- [src/bypass_user.c](src/bypass_user.c)
- [src/bypass_user.h](src/bypass_user.h)

### 替换要求（固定）
- `dump_bypass_user_list_json()` → `client_snapshot_dump_json()`
- `save_bypass_user_list()` → `client_snapshot_save()`
- `load_bypass_user_list()` → `client_snapshot_load()`
- `add_bypass_user()` / `remove_bypass_user()` → 由 `client_snapshot` 维护 trustedmaclist API
- `query_bypass_user_status()` → 由 `client_snapshot` 提供等价查询接口

---

## 验证用例（更细）
1) 正常启动，确认 `nft list table inet wifidogx` 存在
2) 认证客户端，确认 set 元素写入
3) `service firewall restart`：
  - wifidogx 进程不退出
  - 3–10 秒内规则恢复
4) `nft flush ruleset`：
  - wifidogx 自动重建
5) 高并发模拟（50+客户端）：
  - 重载后访问恢复时间 < 5s
  - MQTT/WebSocket 保持连接

---

## 运行流程图
```
[启动]
  |
  v
[fw_init]
  |
  v
[启动巡检线程 (检测 wifidogx 表)]
  |
  v
[检测规则 (wifidogx 表/链/规则)]
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

## 版本落地计划
- 首期完成独立表迁移 + 巡检 + 重建
- 第二期增加快照恢复
- 第三期优化 nft set 与批量更新性能

---

