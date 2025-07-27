# WiFi配置接口文档

## 概述

本文档描述了通过WebSocket接口获取和配置OpenWrt设备无线网络设置的完整API。支持AP模式、Mesh模式和网络接口的完整配置管理。

## 接口列表

### 1. 获取WiFi配置信息

**请求类型**: `get_wifi_info`

**请求格式**:
```json
{
  "type": "get_wifi_info"
}
```

**响应格式**:
```json
{
  "type": "get_wifi_info_response",
  "data": {
    "radio0": {
      "type": "mac80211",
      "path": "platform/soc/18000000.wifi",
      "band": "2g",
      "channel": 8,
      "htmode": "HT20",
      "cell_density": 0,
      "interfaces": [
        {
          "interface_name": "wifinet3",
          "mode": "ap",
          "ssid": "nokia-2.4g",
          "key": "123456789",
          "encryption": "psk2",
          "network": "lan2",
          "disabled": false
        }
      ]
    },
    "radio1": {
      "type": "mac80211",
      "path": "platform/soc/18000000.wifi+1",
      "band": "5g",
      "channel": 36,
      "htmode": "HE80",
      "cell_density": 0,
      "interfaces": [
        {
          "interface_name": "default_radio1",
          "mode": "mesh",
          "mesh_id": "chawrt-aw-mesh-5g",
          "key": "apfree-wifidog",
          "encryption": "sae",
          "network": "lan3",
          "disabled": true
        },
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "nokia-5g",
          "key": "123456789",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    },
    "networks": {
      "lan": {"ipaddr": "192.168.1.254"},
      "lan2": {"ipaddr": "192.168.67.1"},
      "lan3": {"ipaddr": "169.254.31.1"}
    }
  }
}
```

**错误响应**:
```json
{
  "type": "get_wifi_info_error",
  "error": "Failed to execute command"
}
```

### 2. 设置WiFi配置信息

**请求类型**: `set_wifi_info`

**请求格式**:
```json
{
  "type": "set_wifi_info",
  "data": {
    "radio0": {
      "channel": "8",
      "htmode": "HT20",
      "cell_density": 0,
      "interfaces": [
        {
          "interface_name": "wifinet3",
          "mode": "ap",
          "ssid": "MyNetwork-2.4G",
          "key": "newpassword123",
          "encryption": "psk2",
          "network": "lan2",
          "disabled": false
        }
      ]
    },
    "radio1": {
      "channel": "36",
      "htmode": "HE80",
      "cell_density": 0,
      "interfaces": [
        {
          "interface_name": "default_radio1",
          "mode": "mesh",
          "mesh_id": "my-mesh-network",
          "key": "meshpassword",
          "encryption": "sae",
          "network": "lan3",
          "disabled": false
        },
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "MyNetwork-5G",
          "key": "newpassword123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    },
    "networks": {
      "lan2": {
        "ipaddr": "192.168.100.1",
        "netmask": "255.255.255.0"
      }
    }
  }
}
```

**成功响应**:
```json
{
  "type": "set_wifi_info_response",
  "data": {
    "status": "success",
    "message": "Wi-Fi and network configuration updated successfully"
  }
}
```

**错误响应**:
```json
{
  "type": "set_wifi_info_error",
  "error": "Failed to set SSID for interface wifinet2"
}
```

## 数据结构说明

### Radio设备信息

| 字段 | 类型 | 说明 | 示例值 |
|------|------|------|--------|
| type | string | 设备类型 | "mac80211" |
| path | string | 设备路径 | "platform/soc/18000000.wifi" |
| band | string | 频段 | "2g", "5g" |
| channel | integer | 信道号 | 8, 36 |
| htmode | string | HT模式 | "HT20", "HE80", "VHT80" |
| cell_density | integer | 小区密度 | 0, 1, 2, 3 |

### 接口信息

| 字段 | 类型 | 说明 | 示例值 |
|------|------|------|--------|
| interface_name | string | 接口名称 | "wifinet2", "default_radio1" |
| mode | string | 接口模式 | "ap", "mesh", "sta" |
| ssid | string | SSID名称（AP模式） | "MyNetwork" |
| key | string | 密码/密钥 | "password123" |
| encryption | string | 加密方式 | "psk2", "sae", "none" |
| network | string | 绑定网络接口 | "lan", "lan2", "lan3" |
| mesh_id | string | Mesh网络ID（Mesh模式） | "my-mesh-network" |
| disabled | boolean | 是否禁用 | true, false |

### 网络接口信息

| 字段 | 类型 | 说明 | 示例值 |
|------|------|------|--------|
| ipaddr | string | IP地址 | "192.168.1.1" |
| netmask | string | 子网掩码 | "255.255.255.0" |

## 配置模式说明

### AP模式配置

AP（接入点）模式用于创建WiFi热点，客户端可以连接到此网络。

**必需字段**:
- `mode`: "ap"
- `ssid`: WiFi网络名称
- `key`: WiFi密码（如果使用加密）
- `encryption`: 加密方式
- `network`: 绑定的网络接口

**示例**:
```json
{
  "interface_name": "wifinet2",
  "mode": "ap",
  "ssid": "MyHomeWiFi",
  "key": "mypassword123",
  "encryption": "psk2",
  "network": "lan",
  "disabled": false
}
```

### Mesh模式配置

Mesh模式用于创建网状网络，多个设备可以互相连接形成扩展网络。

**必需字段**:
- `mode`: "mesh"
- `mesh_id`: Mesh网络标识符
- `key`: Mesh网络密钥
- `encryption`: 加密方式（推荐使用"sae"）
- `network`: 绑定的网络接口

**示例**:
```json
{
  "interface_name": "default_radio1",
  "mode": "mesh",
  "mesh_id": "my-mesh-network",
  "key": "meshsecretkey",
  "encryption": "sae",
  "network": "lan3",
  "disabled": false
}
```

## 支持的加密方式

| 加密方式 | 说明 | 适用模式 |
|----------|------|----------|
| none | 无加密 | AP, Mesh |
| psk | WPA-PSK | AP |
| psk2 | WPA2-PSK | AP |
| sae | WPA3-SAE | AP, Mesh |
| psk-mixed | WPA/WPA2混合 | AP |

## 支持的HT模式

| HT模式 | 说明 | 频段 |
|--------|------|------|
| HT20 | 20MHz带宽 | 2.4G, 5G |
| HT40 | 40MHz带宽 | 2.4G, 5G |
| VHT80 | 80MHz带宽 | 5G |
| HE80 | 802.11ax 80MHz | 5G |
| HE160 | 802.11ax 160MHz | 5G |

## 网络接口说明

| 接口名 | 说明 | 默认IP |
|--------|------|--------|
| lan | 主LAN接口 | 192.168.1.254 |
| lan2 | 第二LAN接口 | 192.168.67.1 |
| lan3 | 第三LAN接口 | 169.254.31.1 |

## 使用示例

### 1. 配置双频AP

```json
{
  "type": "set_wifi_info",
  "data": {
    "radio0": {
      "channel": "6",
      "htmode": "HT20",
      "interfaces": [
        {
          "interface_name": "wifinet3",
          "mode": "ap",
          "ssid": "MyHome-2.4G",
          "key": "password123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    },
    "radio1": {
      "channel": "36",
      "htmode": "VHT80",
      "interfaces": [
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "MyHome-5G",
          "key": "password123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    }
  }
}
```

### 2. 配置Mesh网络

```json
{
  "type": "set_wifi_info",
  "data": {
    "radio1": {
      "channel": "36",
      "htmode": "HE80",
      "interfaces": [
        {
          "interface_name": "default_radio1",
          "mode": "mesh",
          "mesh_id": "home-mesh-5g",
          "key": "meshkey123",
          "encryption": "sae",
          "network": "lan3",
          "disabled": false
        }
      ]
    }
  }
}
```

### 3. 混合模式配置（AP + Mesh）

```json
{
  "type": "set_wifi_info",
  "data": {
    "radio1": {
      "channel": "36",
      "htmode": "HE80",
      "interfaces": [
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "MyHome-5G",
          "key": "password123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        },
        {
          "interface_name": "default_radio1",
          "mode": "mesh",
          "mesh_id": "home-mesh-5g",
          "key": "meshkey123",
          "encryption": "sae",
          "network": "lan3",
          "disabled": false
        }
      ]
    }
  }
}
```

## 错误处理

### 常见错误类型

1. **配置验证错误**: 缺少必需字段或字段值无效
2. **UCI命令执行错误**: 系统命令执行失败
3. **服务重载错误**: WiFi或网络服务重载失败

### 错误响应格式

```json
{
  "type": "set_wifi_info_error",
  "error": "具体错误描述"
}
```

## 注意事项

1. **配置生效**: 配置更改后会自动执行`wifi reload`和`network reload`使配置生效
2. **接口命名**: 接口名称必须与现有UCI配置中的section名称匹配
3. **信道选择**: 确保选择的信道在当前地区是合法的
4. **Mesh兼容性**: Mesh模式需要所有参与设备使用相同的mesh_id和加密配置
5. **网络隔离**: 不同network接口之间默认是隔离的，需要通过防火墙规则配置互通

## 版本历史

- **v1.0**: 初始版本，支持基本的AP和Mesh配置
- **v1.1**: 移除mesh_fwding和mesh_rssi_threshold字段，简化Mesh配置
- **v1.2**: 增加网络接口IP地址配置支持