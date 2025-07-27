# WiFi配置接口使用指南

## 快速开始

通过WebSocket连接到apfree-wifidog，可以远程获取和配置OpenWrt设备的无线网络设置。

## 基本用法

### 1. 获取当前WiFi配置

```javascript
// 发送请求
const request = {
  type: "get_wifi_info"
};

// 响应示例
{
  "type": "get_wifi_info_response",
  "data": {
    "radio0": {
      "band": "2g",
      "channel": 8,
      "htmode": "HT20",
      "interfaces": [
        {
          "interface_name": "wifinet3",
          "mode": "ap",
          "ssid": "MyWiFi-2.4G",
          "encryption": "psk2",
          "network": "lan2",
          "disabled": false
        }
      ]
    },
    "radio1": {
      "band": "5g",
      "channel": 36,
      "htmode": "HE80",
      "interfaces": [
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "MyWiFi-5G",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    }
  }
}
```

### 2. 设置WiFi配置

```javascript
// 修改WiFi设置
const request = {
  type: "set_wifi_info",
  data: {
    radio0: {
      channel: "6",
      interfaces: [
        {
          interface_name: "wifinet3",
          mode: "ap",
          ssid: "NewWiFi-2.4G",
          key: "newpassword123",
          encryption: "psk2",
          network: "lan2",
          disabled: false
        }
      ]
    }
  }
};

// 成功响应
{
  "type": "set_wifi_info_response",
  "data": {
    "status": "success",
    "message": "Wi-Fi and network configuration updated successfully"
  }
}
```

## 常用配置场景

### 场景1: 修改WiFi密码

```javascript
{
  type: "set_wifi_info",
  data: {
    radio0: {
      interfaces: [
        {
          interface_name: "wifinet3",
          key: "新密码123"
        }
      ]
    },
    radio1: {
      interfaces: [
        {
          interface_name: "wifinet2", 
          key: "新密码123"
        }
      ]
    }
  }
}
```

### 场景2: 启用Mesh网络

```javascript
{
  type: "set_wifi_info",
  data: {
    radio1: {
      interfaces: [
        {
          interface_name: "default_radio1",
          mode: "mesh",
          mesh_id: "家庭网状网络",
          key: "mesh密钥123",
          encryption: "sae",
          network: "lan3",
          disabled: false
        }
      ]
    }
  }
}
```

### 场景3: 更改WiFi信道

```javascript
{
  type: "set_wifi_info",
  data: {
    radio0: {
      channel: "11"  // 2.4G信道
    },
    radio1: {
      channel: "149" // 5G信道
    }
  }
}
```

## 配置字段说明

### Radio设备配置
- `channel`: 信道号
- `htmode`: 带宽模式（HT20, HT40, VHT80, HE80等）
- `cell_density`: 小区密度（0-3）

### 接口配置
- `interface_name`: 接口名称（必需）
- `mode`: 模式（"ap", "mesh", "sta"）
- `ssid`: WiFi名称（AP模式）
- `key`: 密码
- `encryption`: 加密方式（"psk2", "sae", "none"）
- `network`: 网络接口（"lan", "lan2", "lan3"）
- `mesh_id`: Mesh网络ID（Mesh模式）
- `disabled`: 是否禁用（true/false）

## 注意事项

1. **配置生效时间**: 设置后需要等待约10-30秒WiFi服务重启
2. **接口名称**: 必须使用现有的接口名称，可通过get_wifi_info获取
3. **信道限制**: 不同地区对信道有不同限制
4. **Mesh要求**: 所有Mesh节点必须使用相同的mesh_id和密钥

## 错误处理

```javascript
// 错误响应示例
{
  "type": "set_wifi_info_error",
  "error": "Failed to set SSID for interface wifinet2"
}
```

常见错误：
- 接口名称不存在
- 信道号无效
- 密码格式不正确
- 系统命令执行失败

## 完整示例

```javascript
// WebSocket连接示例
const ws = new WebSocket('ws://192.168.1.254:2060');

ws.onopen = function() {
  // 获取当前配置
  ws.send(JSON.stringify({
    type: "get_wifi_info"
  }));
};

ws.onmessage = function(event) {
  const response = JSON.parse(event.data);
  
  if (response.type === "get_wifi_info_response") {
    console.log("当前WiFi配置:", response.data);
    
    // 修改配置
    ws.send(JSON.stringify({
      type: "set_wifi_info",
      data: {
        radio0: {
          interfaces: [
            {
              interface_name: "wifinet3",
              ssid: "新的WiFi名称",
              key: "新密码123"
            }
          ]
        }
      }
    }));
  }
  
  if (response.type === "set_wifi_info_response") {
    console.log("配置更新成功:", response.data.message);
  }
};
```

更多详细信息请参考 [完整API文档](wifi-config-api.md)。