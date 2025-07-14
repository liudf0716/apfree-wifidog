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
  "device_info": {
    "ap_device_id": "<ap_device_id>",
    "ap_mac_address": "<ap_mac_address>", 
    "ap_longitude": "<ap_longitude>",
    "ap_latitude": "<ap_latitude>",
    "location_id": "<location_id>"
  },
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
  "device_info": {
    "ap_device_id": "<ap_device_id>",
    "ap_mac_address": "<ap_mac_address>", 
    "ap_longitude": "<ap_longitude>",
    "ap_latitude": "<ap_latitude>",
    "location_id": "<location_id>"
  },
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
      "auth_mode": "<new_auth_mode>"
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

### 7. 设备重启

#### 7.1 设备重启请求 (服务器 → 设备)
服务器请求立即重启设备，用于维护或配置更改。

**请求:**
```json
{
  "type": "reboot_device"
}
```

**成功行为:**
- 设备立即开始重启过程
- 不向服务器发送响应，因为设备会关机
- WebSocket 连接被系统关机终止
- 所有运行的进程和网络连接都将被终止

**错误响应 (设备 → 服务器):**
仅当重启命令执行失败时发送:
```json
{
  "type": "reboot_device_error", 
  "error": "执行重启命令失败"
}
```

**重要说明:**
- 这是需要系统 root 权限的特权操作
- 所有未保存的数据和活动连接都将丢失
- 设备重启后遵循正常的启动序列
- 谨慎使用，因为它会中断所有正在进行的操作
- 应仅由经过身份验证的管理连接使用

**安全注意事项:**
- 在处理重启请求前实施适当的授权检查
- 考虑实施速率限制以防止滥用
- 记录所有重启请求以供审计

---

### 8. 更新设备信息

#### 8.1 更新设备信息请求 (服务器 → 设备)
服务器请求更新设备的信息。

**请求:**
```json
{
  "type": "update_device_info",
  "device_info": {
    "ap_device_id": "<new_ap_device_id>",      // 可选
    "ap_mac_address": "<new_ap_mac_address>", // 可选
    "ap_longitude": "<new_ap_longitude>",     // 可选
    "ap_latitude": "<new_ap_latitude>",       // 可选
    "location_id": "<new_location_id>"        // 可选
  }
}
```

**成功响应 (设备 → 服务器):**
```json
{
  "type": "update_device_info_response",
  "status": "success",
  "message": "设备信息更新成功"
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "update_device_info_error",
  "error": "缺少 'device_info' 字段"
}
```

---

### 9. Wi-Fi 信息

#### 9.1 获取 Wi-Fi 信息请求 (服务器 → 设备)
服务器请求获取设备当前的 Wi-Fi 信息。

**请求:**
```json
{
  "type": "get_wifi_info"
}
```

**成功响应 (设备 → 服务器):**
```json
{
  "type": "get_wifi_info_response",
  "data": {
    "default_radio0": {
      "ssid": "OpenWrt",
      "mesh_id": "chawrt-aw-mesh"
    },
    "default_radio1": {
      "ssid": "OpenWrt",
      "mesh_id": "chawrt-aw-mesh"
    }
  }
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "get_wifi_info_error",
  "error": "执行命令失败"
}
```

#### 9.2 设置 Wi-Fi 信息请求 (服务器 → 设备)
服务器请求更新设备的 Wi-Fi 信息。

**请求:**
```json
{
  "type": "set_wifi_info",
  "data": {
    "default_radio0": {
      "ssid": "new_ssid",
      "mesh_id": "new_mesh_id"
    }
  }
}
```

**成功响应 (设备 → 服务器):**
```json
{
  "type": "set_wifi_info_response",
  "data": {
    "status": "success",
    "message": "Wi-Fi 信息更新成功"
  }
}
```

**错误响应 (设备 → 服务器):**
```json
{
  "type": "set_wifi_info_error",
  "error": "执行命令失败"
}
```

---

### 10. 域名管理

域名管理功能允许通过 WebSocket 连接动态管理受信任的域名列表，包括精确匹配的域名和通配符域名。这些域名的网络流量可以在不需要用户认证的情况下通过防火墙。

#### 10.1 同步受信任域名列表 (服务器 → 设备)

完全替换当前的受信任域名列表。

**请求:**
```json
{
  "type": "sync_trusted_domain",
  "domains": [
    "example.com",
    "trusted-site.org", 
    "api.service.com"
  ]
}
```

**响应:**
```json
{
  "type": "sync_trusted_domain_response",
  "status": "success",
  "message": "受信任域名同步成功"
}
```

**功能说明:**
- 清除所有现有的受信任域名
- 添加请求中提供的所有域名
- 更新 UCI 配置以保持持久化
- 更改立即生效

#### 10.2 获取受信任域名列表 (服务器 → 设备)

获取当前配置的所有受信任域名。

**请求:**
```json
{
  "type": "get_trusted_domains"
}
```

**响应:**
```json
{
  "type": "get_trusted_domains_response",
  "domains": [
    "example.com",
    "api.service.com",
    "cdn.provider.net"
  ]
}
```

**功能说明:**
- 返回当前所有精确匹配的域名
- 如果没有配置域名，返回空数组
- 响应中的域名顺序可能与配置顺序不同

#### 10.3 同步受信任通配符域名列表 (服务器 → 设备)

完全替换当前的受信任通配符域名列表。

**请求:**
```json
{
  "type": "sync_trusted_wildcard_domains", 
  "domains": [
    "*.googleapis.com",
    "*.cloudflare.com",
    "*.github.io",
    "*.example.org"
  ]
}
```

**响应:**
```json
{
  "type": "sync_trusted_wildcard_domains_response",
  "status": "success", 
  "message": "受信任通配符域名同步成功"
}
```

**功能说明:**
- 清除所有现有的受信任通配符域名
- 添加请求中提供的所有通配符域名模式
- 通配符通常使用 `*.` 前缀匹配子域名
- 更新 UCI 配置以保持持久化
- 更改立即生效

**通配符域名示例:**
- `*.example.com` - 匹配 api.example.com, cdn.example.com 等
- `*.github.io` - 匹配 username.github.io, project.github.io 等  
- `*.googleapis.com` - 匹配 maps.googleapis.com, fonts.googleapis.com 等

#### 10.4 获取受信任通配符域名列表 (服务器 → 设备)

获取当前配置的所有受信任通配符域名。

**请求:**
```json
{
  "type": "get_trusted_wildcard_domains"
}
```

**响应:**
```json
{
  "type": "get_trusted_wildcard_domains_response",
  "domains": [
    "*.googleapis.com",
    "*.cloudflare.com",
    "*.github.io"
  ]
}
```

**功能说明:**
- 返回当前所有通配符域名模式
- 如果没有配置通配符域名，返回空数组
- 响应中的域名顺序可能与配置顺序不同

#### 域名管理技术实现细节

**数据持久化:**
- 所有域名配置都会同步更新到 UCI 配置系统
- 配置在系统重启后自动恢复
- 普通域名存储在 `wifidogx.common.trusted_domains` 
- 通配符域名存储在 `wifidogx.common.trusted_wildcard_domains`

**内存管理:**
- 使用链表结构管理域名数据
- 同步操作会先清除现有数据再添加新数据
- 自动处理内存分配和释放

**错误处理:**
- JSON 解析错误会记录到调试日志
- 无效的请求格式会被忽略
- UCI 配置更新失败会记录错误但不影响内存中的配置

**性能考虑:**
- 域名匹配在网络流量处理中频繁使用
- 建议将最常用的域名放在列表前面
- 通配符匹配比精确匹配消耗更多资源

**使用建议:**
1. **批量更新**: 使用同步接口一次性更新所有域名，避免频繁的单独更新
2. **通配符使用**: 对于有很多子域名的服务，使用通配符域名更高效
3. **监控和验证**: 使用获取接口来验证更新后的配置
4. **备份和恢复**: 重要的域名配置应定期备份到外部系统

**兼容性:**
- 支持 IPv4 和 IPv6 网络
- 兼容标准的域名解析机制
- 通配符模式依赖于底层的域名解析实现
- 建议在测试环境中验证通配符匹配行为

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
