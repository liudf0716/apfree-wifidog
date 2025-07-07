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
      "auth_mode": <new_auth_mode>
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

### 7. Update Device Info

#### 7.1 Update Device Info Request (Server → Device)
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

### 7. Domain Management

Domain management functionality allows dynamic management of trusted domain lists through WebSocket connections, including exact-match domains and wildcard domains. Network traffic to these domains can pass through the firewall without user authentication.

#### 7.1 Synchronize Trusted Domains List (Server → Device)

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

#### 7.2 Get Trusted Domains List (Server → Device)

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

#### 7.3 Synchronize Trusted Wildcard Domains List (Server → Device)

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

#### 7.4 Get Trusted Wildcard Domains List (Server → Device)

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
