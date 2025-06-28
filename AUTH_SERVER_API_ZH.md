```markdown
# ApFree WiFiDog - 认证服务器API文档

本文档详细说明了 ApFree WiFiDog 与认证服务器之间的通信接口。

## 1. Ping (心跳) 接口

此接口供 ApFree WiFiDog 定期通知认证服务器其处于活动状态，并报告基本系统状态。

*   **方法:** `GET`
*   **路径:** 由 `auth_server_path` + `auth_server_ping_script_path_fragment` 构建 (在 `wifidog.conf` 中配置)。
*   **频率:** 通常每 60 秒一次。
*   **查询参数:**
    *   `device_id`: (字符串) WiFiDog 网关的唯一标识符。
    *   `sys_uptime`: (长整型) 系统运行时间 (秒)。
    *   `sys_memfree`: (无符号整型) 系统空闲内存 (KB)。
    *   `sys_load`: (浮点型) 系统平均负载 (1分钟)。
    *   `nf_conntrack_count`: (长整型) Netfilter 连接跟踪计数。
    *   `cpu_usage`: (双精度浮点型) CPU 使用率百分比。
    *   `wifidog_uptime`: (长整型) WiFiDog 进程运行时间 (秒)。
    *   `online_clients`: (整型) 当前在线客户端数量。
    *   `offline_clients`: (整型) 最近断开连接并已老化的客户端数量。
    *   `ssid`: (字符串) 网关的主 SSID (URL编码)。默认为 "NULL"。
    *   `fm_version`: (字符串) 设备固件版本。默认为 "null"。
    *   `type`: (字符串) 设备主板类型。默认为 "null"。
    *   `name`: (字符串) 设备主板名称。默认为 "null"。
    *   `wired_passed`: (整型) 如果有线客户端绕过门户则为1，否则为0。
    *   `aw_version`: (字符串) ApFree WiFiDog 软件版本。

*   **服务器响应:**
    *   **成功:** 响应体必须包含字符串 "Pong"。
    *   **成功操作:** WiFiDog 将认证服务器标记为在线。如果先前标记为离线，则更新防火墙规则。
    *   **失败:** 如果未找到 "Pong"，或发生连接错误，WiFiDog 将认证服务器标记为离线，并可能更新防火墙规则以处理认证服务器不可用的情况 (例如，阻止客户端或允许所有客户端)。

## 2. Counters (计数器) 接口 (V2 版本)

此接口供 ApFree WiFiDog 定期向认证服务器发送所有已连接客户端的详细计数器信息。然后，服务器可以对特定客户端进行操作响应 (例如，断开连接)。

*   **方法:** `POST`
*   **路径:** 由 `auth_server_path` + `auth_server_auth_script_path_fragment` 构建。
*   **路径中的查询参数:** `stage=counters_v2`
*   **频率:** 通常每 `checkinterval` (例如 60 秒) 一次。
*   **请求体:** `application/json`
    ```json
    {
      "device_id": "字符串", // WiFiDog 网关的唯一标识符
      "gateway": [
        {
          "gw_id": "字符串",      // 网关 ID
          "gw_channel": "字符串", // 网关信道
          "clients": [
            {
              "id": "整数",                  // WiFiDog 内部客户端 ID
              "ip": "字符串",                // 客户端 IPv4 地址
              "ip6": "字符串",               // 客户端 IPv6 地址 (或 "N/A")
              "mac": "字符串",               // 客户端 MAC 地址
              "token": "字符串",             // 客户端的认证令牌
              "name": "字符串",              // 客户端名称 (或 "N/A")
              "incoming_bytes": "长长整型",
              "outgoing_bytes": "长长整型",
              "incoming_rate": "长长整型",   // 字节/秒
              "outgoing_rate": "长长整型",   // 字节/秒
              "incoming_packets": "长长整型",
              "outgoing_packets": "长长整型",
              "incoming_bytes_v6": "长长整型",
              "outgoing_bytes_v6": "长长整型",
              "incoming_rate_v6": "长长整型", // 字节/秒
              "outgoing_rate_v6": "长长整型", // 字节/秒
              "incoming_packets_v6": "长长整型",
              "outgoing_packets_v6": "长长整型",
              "first_login": "长长整型",     // 客户端首次登录的时间戳
              "is_online": "布尔型",         // WiFiDog 知晓的当前在线状态
              "wired": "布尔型"              // 如果客户端是有线连接则为 true
            }
            // ... 更多客户端对象
          ]
        }
        // ... 更多网关对象 (单个设备通常只有一个)
      ]
    }
    ```

*   **服务器响应:** `application/json`
    ```json
    {
      "result": [
        {
          "gw_id": "字符串", // 此操作适用的网关 ID
          "auth_op": [
            {
              "id": "整数",        // 需要操作的 WiFiDog 内部客户端 ID
              "auth_code": "整数"  // 针对此客户端的操作代码
            }
            // ... 更多针对其他客户端的 auth_op 对象
          ]
        }
        // ... 更多 result 对象
      ]
    }
    ```
    *   **`auth_code` 值及 WiFiDog 操作:**
        *   `0` (AUTH_ALLOWED): 允许客户端。如果先前处于验证状态，计数器可能会被重置。
        *   `1` (AUTH_DENIED): 拒绝客户端。应用防火墙规则以阻止客户端，并将客户端从 WiFiDog 的活动列表中移除。
        *   `2` (AUTH_VALIDATION): 客户端处于验证阶段 (例如，等待邮件验证)。访问可能受限。
        *   `5` (AUTH_VALIDATION_FAILED): 验证失败或超时。拒绝客户端，应用防火墙规则，并移除客户端。
        *   其他代码可能用于特定的错误条件。

## 3. WebSocket 接口

此接口提供 ApFree WiFiDog 与认证服务器之间的持久性实时通信通道。

### 3.1. 连接建立

1.  **HTTP Upgrade 请求 (客户端到服务器):**
    *   **方法:** `GET`
    *   **路径:** 通过 `wifidog.conf` 中的 `ws_server_path` 配置。
    *   **头部信息:**
        *   `Host`: `<ws_server_hostname>:<ws_server_port>`
        *   `User-Agent`: `apfree-wifidog`
        *   `Upgrade`: `websocket`
        *   `Connection`: `upgrade`
        *   `Sec-WebSocket-Key`: 随机生成的24字节 Base64 字符串。
        *   `Sec-WebSocket-Version`: `13`

2.  **HTTP Upgrade 响应 (服务器到客户端):**
    *   **状态码:** `101 Switching Protocols`
    *   **头部信息:**
        *   `Upgrade`: `websocket`
        *   `Connection`: `Upgrade`
        *   `Sec-WebSocket-Accept`: 服务器计算的接受密钥 (客户端 `Sec-WebSocket-Key` 与标准 GUID 串联后的 SHA1 哈希值，再进行 Base64 编码)。

### 3.2. 客户端到服务器消息 (通过 WebSocket TEXT_FRAME 发送的 JSON 载荷)

1.  **初始 "Connect" (连接) 消息:**
    *   在 WebSocket 成功升级后立即发送。
    *   **JSON 结构:**
        ```json
        {
          "type": "connect", // 或 "heartbeat"
          "device_id": "字符串", // WiFiDog 网关的唯一 ID
          "gateway": [
            {
              "gw_id": "字符串",
              "gw_channel": "字符串",
              "gw_address_v4": "字符串",
              "auth_mode": "整数", // 网关当前认证模式
              "gw_interface": "字符串",
              "gw_address_v6": "字符串" // (可选)
            }
            // ... 如果配置了多个网关，则有更多网关对象
          ]
        }
        ```

2.  **周期性 "Heartbeat" (心跳) 消息:**
    *   每 60 秒发送一次。
    *   **JSON 结构:** 与 "connect" 消息结构相同，但 `"type": "heartbeat"`。
        ```json
        {
          "type": "heartbeat",
          "device_id": "字符串",
          "gateway": [ /* ... 与 connect 结构相同 ... */ ]
        }
        ```

### 3.3. 服务器到客户端消息 (通过 WebSocket TEXT_FRAME 发送的 JSON 载荷)

WiFiDog 根据 JSON 载荷中的 `"type"` 字段解析传入消息。

1.  **Type: "heartbeat" 或 "connect" (服务器对客户端消息的响应)**
    *   这是服务器对客户端 connect/heartbeat 消息的确认/响应。
    *   **JSON 结构:**
        ```json
        {
          "type": "heartbeat", // 或 "connect"
          "gateway": [
            {
              "gw_id": "字符串",
              "auth_mode": "整数" // 此网关的新认证模式
            }
            // ... 更多网关对象
          ]
        }
        ```
    *   **WiFiDog 操作:** 更新每个指定 `gw_id` 的本地 `auth_mode`。如果任何模式发生更改，可能会重新加载防火墙规则。

2.  **Type: "auth" (服务器授予认证)**
    *   **JSON 结构:**
        ```json
        {
          "type": "auth",
          "token": "字符串",         // 客户端的认证令牌
          "client_ip": "字符串",
          "client_mac": "字符串",
          "client_name": "字符串",   // (可选)
          "gw_id": "字符串",         // 客户端所在的网关 ID
          "once_auth": "布尔型"     // 如果为 true，则为特殊的一次性认证处理
        }
        ```
    *   **WiFiDog 操作:**
        *   如果 `once_auth` 为 true: 将指定网关的 `auth_mode` 设置为 0 (绕过/无认证模式) 并重新加载防火墙。
        *   如果 `once_auth` 为 false: 使用提供的详细信息将客户端添加到已认证列表，并应用防火墙规则以允许访问。

3.  **Type: "kickoff" (服务器请求断开客户端连接)**
    *   **JSON 结构:**
        ```json
        {
          "type": "kickoff",
          "client_ip": "字符串",
          "client_mac": "字符串",
          "device_id": "字符串", // 必须与 WiFiDog 自身的 device_id 匹配
          "gw_id": "字符串"      // 必须与客户端当前的 gw_id 匹配
        }
        ```
    *   **WiFiDog 操作:** 验证 `device_id` 和 `gw_id`。如果正确且客户端存在，则应用防火墙规则拒绝访问，并将客户端从活动列表中移除。

4.  **Type: "tmp_pass" (服务器授予临时访问权限)**
    *   **JSON 结构:**
        ```json
        {
          "type": "tmp_pass",
          "client_mac": "字符串",
          "timeout": "整数" // (可选) 访问持续时间 (秒)，默认为 300
        }
        ```
    *   **WiFiDog 操作:** 通过更新防火墙规则，为指定的 MAC 地址授予指定超时时间的临时网络访问权限。

5.  **Type: "firmware_upgrade" (固件升级指令)**
    *   服务器发送此消息以指示设备下载并应用新的固件。
    *   **JSON 结构:**
        ```json
        {
          "type": "firmware_upgrade",
          "url": "<firmware_download_url>"
        }
        ```
        *   `type`: (字符串) 必须为 "firmware_upgrade"。
        *   `url`: (字符串) 固件文件的下载地址。
    *   **WiFiDog 操作:**
        *   设备将记录接收到的 URL。
        *   设备将构造并执行系统命令: `sysupgrade <firmware_download_url>`。
        *   **重要提示:** 执行此命令后，设备预计将开始固件升级过程并随后重新启动。因此，**WiFiDog 不会就此特定命令向服务器发送任何显式的成功或失败确认消息**。认证服务器应通过监控设备的在线/离线状态来间接判断固件升级的结果。例如，设备在升级后重新上线并以新的固件版本进行心跳或连接，则可以认为升级成功。
```
