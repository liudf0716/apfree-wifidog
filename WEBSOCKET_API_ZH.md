# WiFiDogX WebSocket API 文档

## 概述

WiFiDogX 实现了一个 WebSocket 客户端，用于连接到中央管理服务器以进行实时通信和控制。本文档描述了所有支持的 WebSocket 消息类型及其各自的请求/响应格式。

## 连接详情

- **协议**: WebSocket (RFC 6455)
- **消息格式**: JSON
- **帧类型**: 文本帧
- **认证**: 通过 `device_id` 进行基于设备的身份识别

## 消息类型

### 1. 连接与心跳

#### 1.1 连接消息 (设备 → 服务器)
WebSocket 连接建立时自动发送。

**请求:**
```json
{
  "type": "connect",
  "device_id": "<device_identifier>",
  "gateway": [
    {
      "gw_id": "<gateway_id>",
      "gw_channel": "<channel_name>",
      "gw_address_v4": "<ipv4_address>",
      "gw_address_v6": "<ipv6_address>",  // 可选
      "auth_mode": <integer>,
      "gw_interface": "<interface_name>"
    }
  ]
}
```

#### 1.2 心跳消息 (设备 → 服务器)
每60秒发送一次以维持连接并同步网关状态。

**请求:**
```json
{
  "type": "heartbeat",
  "device_id": "<device_identifier>",
  "gateway": [
    {
      "gw_id": "<gateway_id>",
      "gw_channel": "<channel_name>",
      "gw_address_v4": "<ipv4_address>",
      "gw_address_v6": "<ipv6_address>",  // 可选
      "auth_mode": <integer>,
      "gw_interface": "<interface_name>"
    }
  ]
}
```

**响应 (服务器 → 设备):**
```json
{
  "type": "heartbeat",
  "gateway": [
    {
      "gw_id": "<gateway_id>",
      "auth_mode": <new_auth_mode>
    }
  ]
}
```

---

### 2. 客户端认证

#### 2.1 认证请求 (服务器 → 设备)
服务器发送客户端的认证指令。

**请求:**
```json
{
  "type": "auth",
  "token": "<auth_token>",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "client_name": "<client_name>",        // 可选
  "gw_id": "<gateway_id>",
  "once_auth": <boolean>
}
```

**行为:**
- 如果 `once_auth` 为 `true`: 设置网关认证模式为0并重新加载防火墙规则
- 如果 `once_auth` 为 `false`: 将客户端添加到允许列表并设置防火墙规则
- **不向服务器发送响应**

---

### 3. 客户端剔除

#### 3.1 剔除请求 (服务器 → 设备)
服务器请求断开特定客户端的连接。

**请求:**
```json
{
  "type": "kickoff",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "device_id": "<device_identifier>",
  "gw_id": "<gateway_id>"
}
```

**成功响应 (设备 → 服务器):**
```json
{
  "type": "kickoff_response",
  "status": "success",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "message": "客户端已成功剔除"
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "kickoff_error",
  "error": "请求中缺少必填字段"
}
```

```json
{
  "type": "kickoff_error",
  "error": "未找到客户端",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>"
}
```

```json
{
  "type": "kickoff_error",
  "error": "设备 ID 不匹配",
  "expected_device_id": "<expected_id>",
  "actual_device_id": "<actual_id>"
}
```

```json
{
  "type": "kickoff_error",
  "error": "网关 ID 不匹配",
  "client_mac": "<client_mac_address>",
  "expected_gw_id": "<expected_gateway_id>",
  "actual_gw_id": "<actual_gateway_id>"
}
```

---

### 4. 临时访问

#### 4.1 临时通行请求 (服务器 → 设备)
服务器授予客户端 MAC 地址临时网络访问权限。

**请求:**
```json
{
  "type": "tmp_pass",
  "client_mac": "<client_mac_address>",
  "timeout": <seconds>                   // 可选, 默认: 300 (5 分钟)
}
```

**行为:**
- 为指定的 MAC 地址设置临时防火墙访问权限
- 访问权限在超时后过期
- **不向服务器发送响应**

---

### 5. 固件信息

#### 5.1 获取固件信息请求 (服务器 → 设备)
服务器请求设备当前的固件信息。

**请求:**
```json
{
  "type": "get_firmware_info"
}
```

**成功响应 (设备 → 服务器):**
```json
{
  "type": "firmware_info_response",
  "data": {
    "DISTRIB_ID": "ChaWrt",
    "DISTRIB_RELEASE": "24.10-SNAPSHOT",
    "DISTRIB_REVISION": "r28790-abc123",
    "DISTRIB_CODENAME": "snapshot",
    "DISTRIB_TARGET": "ramips/mt7621",
    "DISTRIB_DESCRIPTION": "ChaWrt 24.10-SNAPSHOT r28790-abc123",
    // ... /etc/openwrt_release 中的其他键值对
  }
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "firmware_info_error",
  "error": "执行命令失败"
}
```

---

### 6. 固件升级

#### 6.1 固件升级请求 (服务器 → 设备)
服务器在设备上启动固件升级。

**请求:**
```json
{
  "type": "firmware_upgrade",
  "url": "<firmware_image_url>",         // 必填
  "force": <boolean>                     // 可选, 默认: false
}
```

**参数:**
- `url`: 固件镜像的直接下载 URL
- `force`: 如果为 `true`, 使用 `sysupgrade -F` (强制升级，不进行检查)

**成功响应 (设备 → 服务器):**
```json
{
  "type": "firmware_upgrade_response",
  "status": "success",
  "message": "固件升级已成功启动"
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "firmware_upgrade_error",
  "error": "缺少或无效的 'url' 字段"
}
```

```json
{
  "type": "firmware_upgrade_error",
  "error": "执行 sysupgrade 命令失败"
}
```

**重要说明:**
- 成功响应在系统重启**之前**发送
- 成功执行命令后，设备可能会重启并断开连接
- 服务器应在成功固件升级后预期连接丢失

---

## 错误处理

### 常规错误场景
1. **JSON 解析错误**: 无效的 JSON 格式将被记录，但不发送响应
2. **缺少消息类型**: 缺少 `type` 字段将被记录，但不发送响应
3. **未知消息类型**: 未知的消息类型将被记录，但不发送响应

### 验证错误
- 缺少必填字段会导致特定的错误响应
- 无效的字段类型或值会导致特定的错误响应
- 认证/授权失败包括详细的错误信息

---

## 实现说明

### 对于服务器开发人员

1. **连接管理**:
   - 设备在 WebSocket 升级后立即发送 `connect` 消息
   - 心跳消息每60秒发送一次
   - 服务器应通过网关配置更新来响应心跳

2. **消息顺序**:
   - 不保证消息顺序
   - 每个请求-响应对都是独立的
   - 服务器应处理乱序或重复的消息

3. **响应处理**:
   - 某些命令 (`auth`, `tmp_pass`) 不发送响应
   - 错误响应始终包含描述性的错误消息
   - 成功响应包含相关的上下文数据

4. **连接恢复**:
   - 设备在连接失败时自动重新连接
   - 重新连接间隔: 错误为2秒，EOF为5秒
   - 最多重试5次后放弃

5. **固件升级**:
   - 响应在系统重启前发送
   - 服务器应监控连接状态以检测成功升级
   - 设备将在成功重启后使用新固件重新连接

### 安全考虑

1. **认证**: 设备识别基于 `device_id`
2. **验证**: 所有客户端操作都会验证设备和网关 ID
3. **访问控制**: 临时访问授权有时间限制
4. **命令验证**: 固件升级命令在执行前会进行验证

---

## 示例工作流程

### 客户端认证流程
1. 设备从服务器接收 `auth` 请求
2. 设备验证网关和客户端信息
3. 设备将客户端添加到防火墙允许列表
4. 不向服务器发送响应

### 客户端剔除流程
1. 服务器发送包含客户端详细信息的 `kickoff` 请求
2. 设备验证请求参数
3. 设备从防火墙和客户端列表中移除客户端
4. 设备向服务器发送成功或错误响应

### 固件升级流程
1. 服务器发送包含固件 URL 的 `firmware_upgrade` 请求
2. 设备验证 URL 参数
3. 设备执行 `sysupgrade` 命令
4. 设备发送成功响应
5. 设备重启 (连接丢失)
6. 设备在成功升级后重新连接

---

## 测试与开发

### WebSocket 客户端测试
使用 `wscat` 或浏览器 WebSocket API 等工具进行测试:

```bash
# 连接到设备 WebSocket (如果设备充当服务器)
wscat -c ws://device-ip:port/path

# 发送测试消息
{"type": "get_firmware_info"}
```

### 消息验证
确保所有 JSON 消息符合文档化的模式并包含必填字段。

### 错误模拟
通过发送格式错误的请求或无效参数来测试错误场景，以验证正确的错误处理和响应生成。
