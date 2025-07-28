# WiFiDogX WebSocket API Documentation

## Overview

WiFiDogX implements a WebSocket client that connects to a central management server for real-time communication and control. This document describes all supported WebSocket message types and their respective request/response formats.

## Connection Details

- **Protocol**: WebSocket (RFC 6455)
- **Message Format**: JSON
- **Frame Type**: Text frames
- **Authentication**: Device-based identification via `device_id`

## Message Types

### 1. Connection & Heartbeat

#### 1.1 Connect Message (Device → Server)
Sent automatically when WebSocket connection is established.

**Request:**
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
      "gw_address_v6": "<ipv6_address>",  // Optional
      "auth_mode": <integer>,
      "gw_interface": "<interface_name>"
    }
  ]
}
```

#### 1.2 Heartbeat Message (Device → Server)
Sent every 60 seconds to maintain connection and sync gateway states.

**Request:**
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
      "gw_address_v6": "<ipv6_address>",  // Optional
      "auth_mode": <integer>,
      "gw_interface": "<interface_name>"
    }
  ]
}
```

**Response (Server → Device):**
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

### 2. Client Authentication

#### 2.1 Auth Request (Server → Device)
Server sends authentication instructions for clients.

**Request:**
```json
{
  "type": "auth",
  "token": "<auth_token>",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "client_name": "<client_name>",        // Optional
  "gw_id": "<gateway_id>",
  "once_auth": <boolean>
}
```

**Behavior:**
- If `once_auth` is `true`: Sets gateway auth mode to 0 and reloads firewall rules
- If `once_auth` is `false`: Adds client to allowed list with firewall rules
- **No response sent back to server**

---

### 3. Client Kickoff

#### 3.1 Kickoff Request (Server → Device)
Server requests to disconnect a specific client.

**Request:**
```json
{
  "type": "kickoff",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "device_id": "<device_identifier>",
  "gw_id": "<gateway_id>"
}
```

**Success Response (Device → Server):**
```json
{
  "type": "kickoff_response",
  "status": "success",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>",
  "message": "Client kicked off successfully"
}
```

**Error Responses (Device → Server):**
```json
{
  "type": "kickoff_error",
  "error": "Missing required fields in request"
}
```

```json
{
  "type": "kickoff_error",
  "error": "Client not found",
  "client_ip": "<client_ip_address>",
  "client_mac": "<client_mac_address>"
}
```

```json
{
  "type": "kickoff_error",
  "error": "Device ID mismatch",
  "expected_device_id": "<expected_id>",
  "actual_device_id": "<actual_id>"
}
```

```json
{
  "type": "kickoff_error",
  "error": "Gateway ID mismatch",
  "client_mac": "<client_mac_address>",
  "expected_gw_id": "<expected_gateway_id>",
  "actual_gw_id": "<actual_gateway_id>"
}
```

---

### 4. Temporary Access

#### 4.1 Temporary Pass Request (Server → Device)
Server grants temporary network access to a client MAC address.

**Request:**
```json
{
  "type": "tmp_pass",
  "client_mac": "<client_mac_address>",
  "timeout": <seconds>                   // Optional, default: 300 (5 minutes)
}
```

**Behavior:**
- Sets up temporary firewall access for the specified MAC address
- Access expires after the timeout period
- **No response sent back to server**

---

### 5. Firmware Information

#### 5.1 Get Firmware Info Request (Server → Device)
Server requests current firmware information from the device.

**Request:**
```json
{
  "type": "get_firmware_info"
}
```

**Success Response (Device → Server):**
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
    // ... other key-value pairs from /etc/openwrt_release
  }
}
```

**Error Response (Device → Server):**
```json
{
  "type": "firmware_info_error",
  "error": "Failed to execute command"
}
```

---

### 6. Firmware Upgrade

#### 6.1 Firmware Upgrade Request (Server → Device)
Server initiates firmware upgrade on the device.

**Request:**
```json
{
  "type": "firmware_upgrade",
  "url": "<firmware_image_url>",         // Required
  "force": <boolean>                     // Optional, default: false
}
```

**Parameters:**
- `url`: Direct download URL to the firmware image
- `force`: If `true`, uses `sysupgrade -F` (force upgrade without checks)

**Success Response (Device → Server):**
```json
{
  "type": "firmware_upgrade_response",
  "status": "success",
  "message": "Firmware upgrade initiated successfully"
}
```

**Error Responses (Device → Server):**
```json
{
  "type": "firmware_upgrade_error",
  "error": "Missing or invalid 'url' field"
}
```

```json
{
  "type": "firmware_upgrade_error",
  "error": "Failed to execute sysupgrade command"
}
```

**Important Notes:**
- Success response is sent **before** the system reboots
- After successful command execution, the device will likely reboot and disconnect
- Server should expect connection loss after successful firmware upgrade

---

### 7. Device Reboot

#### 7.1 Reboot Device Request (Server → Device)
Server requests an immediate device reboot for maintenance or configuration changes.

**Request:**
```json
{
  "type": "reboot_device"
}
```

**Success Behavior:**
- Device begins reboot process immediately
- No response is sent back to server as the device shuts down
- WebSocket connection is terminated by system shutdown
- All running processes and network connections will be terminated

**Error Response (Device → Server):**
Only sent if the reboot command fails to execute:
```json
{
  "type": "reboot_device_error", 
  "error": "Failed to execute reboot command"
}
```

**Important Notes:**
- This is a privileged operation requiring root system access
- All unsaved data and active connections will be lost
- Device follows normal boot sequence after restart
- Use with caution as it interrupts all ongoing operations
- Should only be used by authenticated management connections

**Security Considerations:**
- Implement proper authorization checks before processing reboot requests
- Consider rate limiting to prevent abuse
- Log all reboot requests for audit purposes

---

### 8. Update Device Info

#### 8.1 Update Device Info Request (Server → Device)
Server requests to update the device's information.

**Request:**
```json
{
  "type": "update_device_info",
  "device_info": {
    "ap_device_id": "<new_ap_device_id>",      // Optional
    "ap_mac_address": "<new_ap_mac_address>", // Optional
    "ap_longitude": "<new_ap_longitude>",     // Optional
    "ap_latitude": "<new_ap_latitude>",       // Optional
    "location_id": "<new_location_id>"        // Optional
  }
}
```

**Success Response (Device → Server):**
```json
{
  "type": "update_device_info_response",
  "status": "success",
  "message": "Device info updated successfully"
}
```

**Error Response (Device → Server):**
```json
{
  "type": "update_device_info_error",
  "error": "Missing 'device_info' field"
}
```

---

### 9. Wi-Fi Information

#### 9.1 Get Wi-Fi Info Request (Server → Device)
Server requests complete Wi-Fi configuration information from the device. The device returns detailed configuration for all radio devices, interface information, and available network interfaces list.

**Request:**
```json
{
  "type": "get_wifi_info"
}
```

**Success Response (Device → Server):**
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
          "ssid": "MyWiFi-2.4G",
          "key": "password123",
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
          "mesh_id": "my-mesh-network",
          "key": "meshkey123",
          "encryption": "sae",
          "network": "lan3",
          "disabled": false
        },
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "MyWiFi-5G",
          "key": "password123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    },
    "available_networks": ["lan", "lan2", "lan3"]
  }
}
```

**Response Fields:**

**Radio Device Information:**
- `type`: Device type, typically "mac80211"
- `path`: Device path
- `band`: Frequency band, "2g" or "5g"
- `channel`: Channel number
- `htmode`: HT mode, such as "HT20", "HE80", "VHT80", etc.
- `cell_density`: Cell density, 0-3

**Interface Information:**
- `interface_name`: Interface name
- `mode`: Interface mode, "ap" (access point), "mesh" (mesh network), "sta" (station)
- `ssid`: WiFi network name (AP mode, included only when non-empty)
- `key`: Password/key (included only when non-empty)
- `encryption`: Encryption type, "psk2", "sae", "none", etc.
- `network`: Bound network interface
- `mesh_id`: Mesh network ID (mesh mode, included only when non-empty)
- `disabled`: Whether disabled (boolean value)

**Available Network Interfaces:**
- `available_networks`: String array containing network interface names with protocol type `static`, used for WiFi interface binding selection, excluding system interfaces (loopback, globals)

**Implementation Details:**
- Retrieves complete wireless configuration via `uci show wireless` command
- Parses UCI configuration, distinguishing between radio devices and interface configurations
- Only non-empty fields are included in the response (ssid, key, mesh_id)
- Automatically discovers the radio device each interface belongs to
- Obtains available network interfaces via `uci show network | grep '\.proto=.static.'`

**Error Response (Device → Server):**
```json
{
  "type": "get_wifi_info_error",
  "error": "Failed to execute command"
}
```

#### 9.2 Set Wi-Fi Info Request (Server → Device)
Server requests to update the device's complete Wi-Fi configuration information, including radio device parameters and interface configurations. After configuration changes, the WiFi service will be automatically reloaded to apply the settings.

**Request:**
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
          "ssid": "NewWiFi-2.4G",
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
          "key": "meshkey123",
          "encryption": "sae",
          "network": "lan3",
          "disabled": false
        },
        {
          "interface_name": "wifinet2",
          "mode": "ap",
          "ssid": "NewWiFi-5G",
          "key": "newpassword123",
          "encryption": "psk2",
          "network": "lan",
          "disabled": false
        }
      ]
    }
  }
}
```

**Request Fields:**

**Radio Device Configuration:**
- `channel`: Channel number
- `htmode`: HT mode (HT20, HT40, VHT80, HE80, etc.)
- `cell_density`: Cell density (0-3)

**Interface Configuration:**
- `interface_name`: Interface name (required, must match existing UCI configuration)
- `mode`: Interface mode ("ap", "mesh", "sta")
- `ssid`: WiFi network name (AP mode)
- `key`: Password/key
- `encryption`: Encryption type ("psk2", "sae", "none", etc.)
- `network`: Bound network interface (must be proto=static interface)
- `mesh_id`: Mesh network ID (mesh mode)
- `disabled`: Whether disabled (true/false)

**Configuration Modes:**

1. **AP Mode**: Create WiFi hotspot
   - Required fields: `mode`="ap", `ssid`, `key`, `encryption`, `network`

2. **Mesh Mode**: Create mesh network
   - Required fields: `mode`="mesh", `mesh_id`, `key`, `encryption`, `network`
   - Recommended to use `encryption`="sae" (WPA3)

**Supported Encryption Types:**
- `none`: No encryption
- `psk`: WPA-PSK
- `psk2`: WPA2-PSK
- `sae`: WPA3-SAE (recommended for mesh)
- `psk-mixed`: WPA/WPA2 mixed

**Processing Logic:**
1. Validate request data format and required fields
2. Configure radio device parameters (channel, htmode, cell_density)
3. Configure each interface properties (mode, ssid, key, encryption, network, mesh_id, disabled)
4. Set interface-to-radio device associations
5. Commit UCI configuration changes
6. Reload WiFi service to apply configuration

**Success Response (Device → Server):**
```json
{
  "type": "set_wifi_info_response",
  "data": {
    "status": "success",
    "message": "Wi-Fi configuration updated successfully"
  }
}
```

**Error Response (Device → Server):**
```json
{
  "type": "set_wifi_info_error",
  "error": "Failed to set SSID for interface wifinet2"
}
```

**Important Notes:**
1. Configuration changes require approximately 10-30 seconds for WiFi service restart
2. Interface names must match section names in existing UCI configuration
3. Channel selection must comply with current regional regulatory requirements
4. Mesh mode requires all participating devices to use the same mesh_id and encryption configuration
5. WiFi interfaces can only be bound to static network interfaces listed in available_networks
6. Only proto=static network interfaces are available for WiFi binding

---

### 10. System Information

#### 10.1 Get System Info Request (Server → Device)
Server requests current system information from the device. This provides comprehensive monitoring data including system resource usage, process status, and hardware metrics.

**Request:**
```json
{
  "type": "get_sys_info"
}
```

**Success Response (Device → Server):**
```json
{
  "type": "get_sys_info_response",
  "data": {
    "sys_uptime": 12345,
    "sys_memfree": 512000,
    "sys_load": 0.25,
    "nf_conntrack_count": 100,
    "cpu_usage": 15.5,
    "wifidog_uptime": 3600,
    "cpu_temp": 45
  }
}
```

**Response Fields:**
- `sys_uptime`: System uptime in seconds since last boot
- `sys_memfree`: Available free memory in KB
- `sys_load`: System load average (1-minute average)
- `nf_conntrack_count`: Number of active network connection tracking entries
- `cpu_usage`: Current CPU usage percentage (0.0-100.0)
- `wifidog_uptime`: WiFidog process uptime in seconds since process start
- `cpu_temp`: CPU temperature in degrees Celsius

**Data Collection Details:**
- **System Uptime**: Retrieved from `/proc/uptime`
- **Memory Information**: Retrieved from `/proc/meminfo` (MemFree field)
- **Load Average**: Retrieved from `/proc/loadavg` (1-minute average)
- **Connection Tracking**: Retrieved from `/proc/sys/net/netfilter/nf_conntrack_count`
- **CPU Usage**: Calculated from `/proc/stat` sampling
- **Process Uptime**: Calculated from WiFidog process start time
- **CPU Temperature**: Retrieved from thermal sensors in `/sys/class/thermal/thermal_zone*/temp` or `/sys/class/hwmon/hwmon*/temp1_input`

**Error Response (Device → Server):**
```json
{
  "type": "get_sys_info_error",
  "error": "Failed to retrieve system information"
}
```

**Usage Scenarios:**
- **System Monitoring**: Real-time monitoring of device health and performance
- **Resource Management**: Tracking memory and CPU usage for capacity planning  
- **Performance Analysis**: Monitoring system load and connection counts
- **Temperature Monitoring**: Hardware health monitoring and thermal management
- **Process Monitoring**: Tracking WiFidog process status and uptime

**Implementation Notes:**
- All system information is collected in real-time when the request is received
- Temperature reading attempts multiple thermal sensor paths for compatibility
- CPU usage calculation involves sampling `/proc/stat` at intervals
- Error handling ensures partial data collection if some metrics are unavailable
- Response includes all available metrics even if some collection methods fail

---

### 11. Domain Management

Domain management functionality allows dynamic management of trusted domain lists through WebSocket connections, including exact-match domains and wildcard domains. Network traffic to these domains can pass through the firewall without user authentication.

#### 11.1 Synchronize Trusted Domains List (Server → Device)

Completely replaces the current trusted domains list.

**Request:**
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

**Response:**
```json
{
  "type": "sync_trusted_domain_response",
  "status": "success",
  "message": "Trusted domains synchronized successfully"
}
```

**Features:**
- Clears all existing trusted domains
- Adds all domains provided in the request
- Updates UCI configuration for persistence
- Changes take effect immediately

#### 11.2 Get Trusted Domains List (Server → Device)

Retrieves the complete list of currently configured trusted domains.

**Request:**
```json
{
  "type": "get_trusted_domains"
}
```

**Response:**
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

**Features:**
- Returns all currently configured exact-match domains
- Returns empty array if no domains are configured
- Domain order in response may not match configuration order

#### 11.3 Synchronize Trusted Wildcard Domains List (Server → Device)

Completely replaces the current trusted wildcard domains list.

**Request:**
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

**Response:**
```json
{
  "type": "sync_trusted_wildcard_domains_response",
  "status": "success", 
  "message": "Trusted wildcard domains synchronized successfully"
}
```

**Features:**
- Clears all existing trusted wildcard domains
- Adds all wildcard domain patterns provided in the request
- Wildcards typically use `*.` prefix to match subdomains
- Updates UCI configuration for persistence
- Changes take effect immediately

**Wildcard Domain Examples:**
- `*.example.com` - matches api.example.com, cdn.example.com, etc.
- `*.github.io` - matches username.github.io, project.github.io, etc.
- `*.googleapis.com` - matches maps.googleapis.com, fonts.googleapis.com, etc.

#### 11.4 Get Trusted Wildcard Domains List (Server → Device)

Retrieves the complete list of currently configured trusted wildcard domains.

**Request:**
```json
{
  "type": "get_trusted_wildcard_domains"
}
```

**Response:**
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

**Features:**
- Returns all currently configured wildcard domain patterns
- Returns empty array if no wildcard domains are configured
- Domain order in response may not match configuration order

#### Domain Management Technical Implementation

**Data Persistence:**
- All domain configurations are synchronized to UCI configuration system
- Configuration automatically restored after system restart
- Regular domains stored in `wifidogx.common.trusted_domains`
- Wildcard domains stored in `wifidogx.common.trusted_wildcard_domains`

**Memory Management:**
- Uses linked list structures to manage domain data
- Synchronization operations clear existing data before adding new data
- Automatic memory allocation and deallocation handling

**Error Handling:**
- JSON parsing errors are logged to debug logs
- Invalid request formats are ignored
- UCI configuration update failures are logged but don't affect in-memory configuration

**Performance Considerations:**
- Domain matching is used frequently in network traffic processing
- Recommend placing most commonly used domains at the front of the list
- Wildcard matching consumes more resources than exact matching

**Usage Recommendations:**
1. **Batch Updates**: Use synchronization interfaces to update all domains at once, avoiding frequent individual updates
2. **Wildcard Usage**: For services with many subdomains, using wildcard domains is more efficient
3. **Monitoring and Validation**: Use get interfaces to validate configuration after updates
4. **Backup and Recovery**: Important domain configurations should be regularly backed up to external systems

**Compatibility:**
- Supports IPv4 and IPv6 networks
- Compatible with standard domain resolution mechanisms
- Wildcard patterns depend on underlying domain resolution implementation
- Recommend validating wildcard matching behavior in test environments

````
