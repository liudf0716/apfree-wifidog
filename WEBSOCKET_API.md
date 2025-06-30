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

## Error Handling

### General Error Scenarios
1. **JSON Parse Errors**: Invalid JSON format will be logged but no response sent
2. **Missing Message Type**: Missing `type` field will be logged but no response sent
3. **Unknown Message Type**: Unknown message types will be logged but no response sent

### Validation Errors
- Missing required fields result in specific error responses
- Invalid field types or values result in specific error responses
- Authentication/authorization failures include detailed error information

---

## Implementation Notes

### For Server Developers

1. **Connection Management**:
   - Device sends `connect` message immediately after WebSocket upgrade
   - Heartbeat messages are sent every 60 seconds
   - Server should respond to heartbeat with gateway configuration updates

2. **Message Ordering**:
   - No guaranteed message ordering
   - Each request-response pair is independent
   - Server should handle out-of-order or duplicate messages

3. **Response Handling**:
   - Some commands (`auth`, `tmp_pass`) don't send responses
   - Error responses always include descriptive error messages
   - Success responses include relevant context data

4. **Connection Recovery**:
   - Device automatically reconnects on connection failure
   - Reconnection intervals: 2 seconds for errors, 5 seconds for EOF
   - Maximum 5 retry attempts before giving up

5. **Firmware Upgrade**:
   - Response is sent before system reboot
   - Server should monitor connection status to detect successful upgrade
   - Device will reconnect after successful reboot with new firmware

### Security Considerations

1. **Authentication**: Device identification is based on `device_id`
2. **Validation**: All client operations validate device and gateway IDs
3. **Access Control**: Temporary access grants are time-limited
4. **Command Verification**: Firmware upgrade commands are validated before execution

---

## Example Workflows

### Client Authentication Flow
1. Device receives `auth` request from server
2. Device validates gateway and client information
3. Device adds client to firewall allow list
4. No response sent to server

### Client Kickoff Flow
1. Server sends `kickoff` request with client details
2. Device validates request parameters
3. Device removes client from firewall and client list
4. Device sends success or error response to server

### Firmware Upgrade Flow
1. Server sends `firmware_upgrade` request with firmware URL
2. Device validates URL parameter
3. Device executes `sysupgrade` command
4. Device sends success response
5. Device reboots (connection lost)
6. Device reconnects after successful upgrade

---

## Testing and Development

### WebSocket Client Testing
Use tools like `wscat` or browser WebSocket APIs to test:

```bash
# Connect to device WebSocket (if device acts as server)
wscat -c ws://device-ip:port/path

# Send test message
{"type": "get_firmware_info"}
```

### Message Validation
Ensure all JSON messages conform to the documented schemas and include required fields.

### Error Simulation
Test error scenarios by sending malformed requests or invalid parameters to verify proper error handling and response generation.
