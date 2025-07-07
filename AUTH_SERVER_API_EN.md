```markdown
# ApFree WiFiDog - Authentication Server API Documentation

This document details the communication interfaces between ApFree WiFiDog and the Authentication Server.

## 1. Ping Interface

This interface is used by ApFree WiFiDog to periodically inform the authentication server that it is active and to report basic system status.

*   **Method:** `GET`
*   **Path:** Constructed from `auth_server_path` + `auth_server_ping_script_path_fragment` (configurable in `wifidog.conf`).
*   **Frequency:** Typically every 60 seconds.
*   **Query Parameters:**
    *   `device_id`: (string) Unique identifier of the WiFiDog gateway.
    *   `sys_uptime`: (long) System uptime in seconds.
    *   `sys_memfree`: (unsigned int) Free system memory in Kilobytes.
    *   `sys_load`: (float) System load average (1-minute).
    *   `nf_conntrack_count`: (long) Netfilter connection track count.
    *   `cpu_usage`: (double) CPU utilization percentage.
    *   `wifidog_uptime`: (long) WiFiDog process uptime in seconds.
    *   `online_clients`: (int) Number of currently authenticated clients.
    *   `offline_clients`: (int) Number of recently disconnected clients that have aged out.
    *   `ssid`: (string) The primary SSID of the gateway (URL encoded). Defaults to "NULL".
    *   `fm_version`: (string) Firmware version of the device. Defaults to "null".
    *   `type`: (string) Device board type. Defaults to "null".
    *   `name`: (string) Device board name. Defaults to "null".
    *   `wired_passed`: (int) 1 if wired clients bypass portal, 0 otherwise.
    *   `aw_version`: (string) ApFree WiFiDog software version.

*   **Server Response:**
    *   **Success:** The response body must contain the string "Pong".
    *   **Action on Success:** WiFiDog marks the auth server as online. If previously marked down, firewall rules are updated.
    *   **Failure:** If "Pong" is not found, or if there's a connection error, WiFiDog marks the auth server as offline, and firewall rules may be updated to handle auth server unavailability (e.g., block clients or allow all).

## 2. Counters Interface (Version 2)

This interface is used by ApFree WiFiDog to periodically send detailed counter information for all connected clients to the authentication server. The server can then respond with actions for specific clients (e.g., disconnect).

*   **Method:** `POST`
*   **Path:** Constructed from `auth_server_path` + `auth_server_auth_script_path_fragment`.
*   **Query Parameter on Path:** `stage=counters_v2`
*   **Frequency:** Typically every `checkinterval` (e.g., 60 seconds).
*   **Request Body:** `application/json`
    ```json
    {
      "device_id": "string", // Unique identifier of the WiFiDog gateway
      "gateway": [
        {
          "gw_id": "string",      // Gateway ID
          "gw_channel": "string", // Gateway channel
          "clients": [
            {
              "id": "integer",                // WiFiDog's internal client ID
              "ip": "string",                 // Client IPv4 address
              "ip6": "string",                // Client IPv6 address (or "N/A")
              "mac": "string",                // Client MAC address
              "token": "string",              // Client's authentication token
              "name": "string",               // Client name (or "N/A")
              "incoming_bytes": "long long",
              "outgoing_bytes": "long long",
              "incoming_rate": "long long",   // Bytes/sec
              "outgoing_rate": "long long",   // Bytes/sec
              "incoming_packets": "long long",
              "outgoing_packets": "long long",
              "incoming_bytes_v6": "long long",
              "outgoing_bytes_v6": "long long",
              "incoming_rate_v6": "long long", // Bytes/sec
              "outgoing_rate_v6": "long long", // Bytes/sec
              "incoming_packets_v6": "long long",
              "outgoing_packets_v6": "long long",
              "first_login": "long long",     // Timestamp of client's first login
              "is_online": "boolean",         // Current online status known to WiFiDog
              "wired": "boolean"              // True if the client is on a wired connection
            }
            // ... more client objects
          ]
        }
        // ... more gateway objects (usually one for a single device)
      ]
    }
    ```

*   **Server Response:** `application/json`
    ```json
    {
      "result": [
        {
          "gw_id": "string", // Gateway ID this operation applies to
          "auth_op": [
            {
              "id": "integer",        // WiFiDog's internal client ID to act upon
              "auth_code": "integer"  // Action code for this client
            }
            // ... more auth_op objects for other clients
          ]
        }
        // ... more result objects
      ]
    }
    ```
    *   **`auth_code` values and WiFiDog actions:**
        *   `0` (AUTH_ALLOWED): Client is allowed. If previously in validation, counters might be reset.
        *   `1` (AUTH_DENIED): Client is denied. Firewall rules are applied to block the client, and the client is removed from WiFiDog's active list.
        *   `2` (AUTH_VALIDATION): Client is in a validation period (e.g., email verification pending). Access might be restricted.
        *   `5` (AUTH_VALIDATION_FAILED): Validation failed or timed out. Client is denied, firewall rules applied, and client removed.
        *   Other codes might exist for specific error conditions.

## 3. WebSocket Interface

This interface provides a persistent, real-time communication channel between ApFree WiFiDog and the authentication server.

### 3.1. Connection Establishment

1.  **HTTP Upgrade Request (Client to Server):**
    *   **Method:** `GET`
    *   **Path:** Configured via `ws_server_path` in `wifidog.conf`.
    *   **Headers:**
        *   `Host`: `<ws_server_hostname>:<ws_server_port>`
        *   `User-Agent`: `apfree-wifidog`
        *   `Upgrade`: `websocket`
        *   `Connection`: `upgrade`
        *   `Sec-WebSocket-Key`: Randomly generated 24-byte Base64 string.
        *   `Sec-WebSocket-Version`: `13`

2.  **HTTP Upgrade Response (Server to Client):**
    *   **Status Code:** `101 Switching Protocols`
    *   **Headers:**
        *   `Upgrade`: `websocket`
        *   `Connection`: `Upgrade`
        *   `Sec-WebSocket-Accept`: Server's computed accept key (SHA1 hash of client's `Sec-WebSocket-Key` concatenated with a standard GUID, then Base64 encoded).

### 3.2. Client to Server Messages (JSON Payloads via WebSocket TEXT_FRAME)

1.  **Initial "Connect" Message:**
    *   Sent immediately after successful WebSocket upgrade.
    *   **JSON Structure:**
        ```json
        {
          "type": "connect",
          "device_id": "string", // WiFiDog gateway's unique ID
          "gateway": [
            {
              "gw_id": "string",
              "gw_channel": "string",
              "gw_address_v4": "string",
              "auth_mode": "integer", // Current authentication mode of the gateway
              "gw_interface": "string",
              "gw_address_v6": "string" // (Optional)
            }
            // ... more gateway objects if configured
          ]
        }
        ```

2.  **Periodic "Heartbeat" Message:**
    *   Sent every 60 seconds.
    *   **JSON Structure:** Same as the "connect" message, but with `"type": "heartbeat"`.
        ```json
        {
          "type": "heartbeat",
          "device_id": "string",
          "gateway": [ /* ... same structure as connect ... */ ]
        }
        ```

### 3.3. Server to Client Messages (JSON Payloads via WebSocket TEXT_FRAME)

WiFiDog parses incoming messages based on the `"type"` field in the JSON payload.

1.  **Type: "heartbeat" or "connect" (Response from Server)**
    *   This is the server's acknowledgment/response to client's connect/heartbeat.
    *   **JSON Structure:**
        ```json
        {
          "type": "heartbeat", // or "connect"
          "gateway": [
            {
              "gw_id": "string",
              "auth_mode": "integer" // New auth mode for this gateway
            }
            // ... more gateway objects
          ]
        }
        ```
    *   **WiFiDog Action:** Updates the local `auth_mode` for each specified `gw_id`. If any mode changes, firewall rules may be reloaded.

2.  **Type: "auth" (Server Grants Authentication)**
    *   **JSON Structure:**
        ```json
        {
          "type": "auth",
          "token": "string",         // Authentication token for the client
          "client_ip": "string",
          "client_mac": "string",
          "client_name": "string",   // (Optional)
          "gw_id": "string",         // Gateway ID the client is on
          "once_auth": "boolean"     // If true, special one-time auth handling
        }
        ```
    *   **WiFiDog Action:**
        *   If `once_auth` is true: Sets the specified gateway's `auth_mode` to 0 (bypass/no auth) and reloads firewall.
        *   If `once_auth` is false: Adds the client to the authenticated list with the provided details, applies firewall rules to allow access.

3.  **Type: "kickoff" (Server Requests Client Disconnection)**
    *   **JSON Structure:**
        ```json
        {
          "type": "kickoff",
          "client_ip": "string",
          "client_mac": "string",
          "device_id": "string", // Must match WiFiDog's own device_id
          "gw_id": "string"      // Must match the client's current gw_id
        }
        ```
    *   **WiFiDog Action:** Validates `device_id` and `gw_id`. If correct and client exists, applies firewall rules to deny access and removes the client from the active list.

4.  **Type: "tmp_pass" (Server Grants Temporary Access)**
    *   **JSON Structure:**
        ```json
        {
          "type": "tmp_pass",
          "client_mac": "string",
          "timeout": "integer" // (Optional) Access duration in seconds, defaults to 300
        }
        ```
    *   **WiFiDog Action:** Grants temporary network access to the specified MAC address for the duration of the timeout by updating firewall rules.

5.  **Type: "get_trusted_domains" (Server Requests Trusted Domains)**
    *   **JSON Structure:**
        ```json
        {
          "type": "get_trusted_domains"
        }
        ```
    *   **WiFiDog Action:** Responds with a `get_trusted_domains_response` message containing the current list of trusted domains.

6.  **Type: "sync_trusted_domain" (Server Synchronizes Trusted Domains)**
    *   **JSON Structure:**
        ```json
        {
          "type": "sync_trusted_domain",
          "domains": ["domain1.com", "domain2.com"]
        }
        ```
    *   **WiFiDog Action:** Clears the existing trusted domains list and replaces it with the domains provided in the `domains` array.

7.  **Type: "get_trusted_wildcard_domains" (Server Requests Trusted Wildcard Domains)**
    *   **JSON Structure:**
        ```json
        {
          "type": "get_trusted_wildcard_domains"
        }
        ```
    *   **WiFiDog Action:** Responds with a `get_trusted_wildcard_domains_response` message containing the current list of trusted wildcard domains.

8.  **Type: "sync_trusted_wildcard_domain" (Server Synchronizes Trusted Wildcard Domains)**
    *   **JSON Structure:**
        ```json
        {
          "type": "sync_trusted_wildcard_domain",
          "domains": [".domain1.com", ".domain2.com"]
        }
        ```
    *   **WiFiDog Action:** Clears the existing trusted wildcard domains list and replaces it with the domains provided in the `domains` array.
```
