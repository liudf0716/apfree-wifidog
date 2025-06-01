
<div align="center">
    <img src="https://user-images.githubusercontent.com/1182593/213065247-9a3cb0a5-dd08-4383-b217-b141ad32e88a.png" alt="ApFree WiFiDog Logo" width="400" height="400"/>
</div>

[![License](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING) 
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/pulls) 
[![Issues Welcome](https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/issues/new) 
[![Release Version](https://img.shields.io/badge/release-7.10.2082-red.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/releases) 
[![OpenWRT](https://img.shields.io/badge/Platform-%20OpenWRT%20-brightgreen.svg?style=plastic)](https://github.com/openwrt) 
[![Join the QQ Group](https://img.shields.io/badge/chat-qq%20group-brightgreen.svg)](https://jq.qq.com/?_wv=1027&k=4ADDSev)

[English Version](README.md) | [中文版本](README-zh.md) | [Auth Server API](AUTH_SERVER_API_EN.md)

## ApFree WiFiDog: A High-Performance Captive Portal Solution for HTTP(S)

ApFree WiFiDog is an open-source, high-performance captive portal solution for HTTP and HTTPS, specifically designed for authenticating users on wireless networks operating on the OpenWrt platform. It boasts the capability to handle high concurrency and traffic volumes seamlessly.

### Introduction Videos

<div align="center">
    <a href="https://www.bilibili.com/video/BV18m411d7Yj/?vd_source=b303f6e8e0ed18809d8752d41ab1de7d">
        <img width="972" alt="ApFree WiFiDog Introduction Video" src="apfree-wifidog_intr.png">
    </a>
</div>

### Why Choose ApFree WiFiDog?

1. **Stability**: Employing API-based iptables rules, it enhances stability in multithreaded environments.
2. **Performance**: Built on libevent2 with epoll support, it significantly outperforms the original WiFiDog.
3. **HTTPS Support**: Ensures secure HTTPS redirection, aligning with modern web security standards.
4. **Long Connection Support**: Accommodates long connections, including WebSocket and MQTT, for real-time communication.
5. **Flexible Authentication**: Offers both local and cloud-based authentication methods, catering to diverse user needs.
6. **Advanced Rules Management**: Enables dynamic management of access rules, including MAC address and IP/domain management, without requiring restarts.
7. **Active Support**: Benefits from active community support and responsive issue resolution.
8. **eBPF-based Traffic Control & DPI**: Leverages eBPF for efficient traffic control and Deep Packet Inspection (DPI) capabilities.

### Installation

The package manager commands for OpenWrt vary depending on the version.

**For latest OpenWrt versions (typically using `apk`):**
1. Update package lists:
   ```bash
   apk update
   ```
2. Install ApFree WiFiDog:
   ```bash
   apk add apfree-wifidog
   ```

**For older OpenWrt versions (typically using `opkg`):**
1. Update package lists:
   ```bash
   opkg update
   ```
2. Install ApFree WiFiDog:
   ```bash
   opkg install apfree-wifidog
   ```

**LuCI Web Interface:**
The `luci-app-apfree-wifidog` package is **not** installed using the commands above. For guidance on setting up the LuCI web interface, please refer to the "LuCI Integration" section, which recommends using the `chawrt` project or integrating LuCI from the main `luci` repository if you are building your own firmware.

### LuCI Integration

For simplified configuration, ApFree WiFiDog has a LuCI interface. While the `luci-app-apfree-wifidog` package was previously standalone, it is now integrated into the main `luci` repository available at [https://github.com/liudf0716/luci](https://github.com/liudf0716/luci).

**Recommended Setup:**
We recommend users adopt the **`chawrt`** project for their OpenWrt setup, which can be found at [https://github.com/liudf0716/chawrt](https://github.com/liudf0716/chawrt). The `chawrt` project includes `luci-app-apfree-wifidog` and provides a comprehensive, ready-to-use OpenWrt firmware solution with ApFree WiFiDog integrated. Using `chawrt` is the easiest way to get started with a fully configured system.

If you are building your own firmware or prefer manual installation, you can find the LuCI application as part of the `luci` repository mentioned above. However, for most users, **`chawrt`** offers a more streamlined experience.

### Basic Usage Example: Guest Network

Configuring ApFree WiFiDog is best done using the `luci-app-apfree-wifidog` web interface, which provides a user-friendly way to manage all settings. Manual editing of configuration files is discouraged.

Here are two common scenarios:

1.  **Cloud Authentication Mode:**
    *   This mode requires an external authentication server.
    *   **Steps via LuCI:**
        *   Navigate to the ApFree WiFiDog configuration page in LuCI.
        *   **Authentication Server Settings:** Configure the `Hostname`, `Port`, and `Path` for your authentication server.
        *   **Gateway Settings:** Ensure the `Gateway Interface` is correctly set to your guest network interface (e.g., `br-guest`).
        *   **Advanced Settings:** For real-time communication and status updates (often needed by cloud solutions), enable and configure `WebSocket Support` (e.g., specify WebSocket URL/Path).
    *   Clients connecting to the guest network will be redirected to your cloud authentication portal. After successful authentication, they will be granted internet access.

2.  **Local Authentication Mode (Splash Page Only):**
    *   This mode does not require an external authentication server and is typically used for simpler scenarios like displaying a welcome page or terms of service before granting access.
    *   **Steps via LuCI:**
        *   Navigate to the ApFree WiFiDog configuration page in LuCI.
        *   **Gateway Settings:** Ensure the `Gateway Interface` is correctly set to your guest network interface (e.g., `br-guest`).
        *   **Authentication Mode:** Select a local or splash page mode if available, or ensure no external `AuthServer` is configured.
        *   **Redirect URL / Splash Page URL:** Configure the `Redirect URL` (or similar field) to point to your desired local splash page or an external informational page. This is the page users will see before being granted access. For a simple "click-to-continue" setup, this might be a page you host on the router itself or a simple external site.
    *   Clients connecting to the guest network will be redirected to this specified URL. Depending on the specific local authentication setup (which might vary by firmware or custom configurations), they might be granted access immediately after viewing the page or after a simple action like clicking a button.

This approach provides a controlled and isolated network for guests while requiring them to pass through your configured portal or splash page for access. Remember to save and apply your changes in LuCI.

### Troubleshooting

Encountering issues? Here are some steps and common problems to help you troubleshoot your ApFree WiFiDog setup.

#### Checking Logs

ApFree WiFiDog logs messages that can provide valuable insights into its operation and any errors.

*   **Log Output:** By default, ApFree WiFiDog outputs log messages to `stderr`. If you are running it via an init script or service manager on OpenWrt, these logs might be directed to the system log (syslog), which can typically be viewed using the `logread` command. Some configurations might allow specifying a log file directly.
*   **Log Verbosity (Debug Level):** You can increase the verbosity of log messages to get more detailed information. This is often controlled by a `DaemonLogLevel` or similar setting in the `wifidog.conf` / `wifidogx.conf` file. Setting this to a higher level (e.g., 7 for debug) will produce more output. Consult the sample configuration file for specific options related to logging.

#### Common Issues and Solutions

*   **Client Not Redirected to Captive Portal:**
    *   **Service Status:** Ensure the ApFree WiFiDog service is running. You can check this via LuCI or by using `ps | grep wifidog` in the command line.
    *   **`GatewayInterface`:** Verify that the `GatewayInterface` in your configuration file correctly matches the network interface your clients are on (e.g., `br-lan`, or your specific guest interface).
    *   **Firewall Rules:** ApFree WiFiDog relies on firewall rules to intercept traffic. Check if the necessary iptables rules are present (`iptables -L -t nat`). Sometimes, custom firewall configurations or other services might interfere.
    *   **DNS Resolution:** Ensure clients are using a DNS server that can resolve your authentication server's hostname. Also, the router itself must be able to resolve DNS for domain whitelisting features.

*   **Client Authenticated but Can't Access Specific Websites/Services:**
    *   **Trusted Domains/Hosts:** ApFree WiFiDog maintains a list of trusted domains and IP addresses that clients can access before authentication (and sometimes after, depending on policy). Use the `wdctlx show_trusted_domains` command to view the currently active trusted domain/IP list. If a site is not working, its domain or the domains of its resources (CDNs, APIs) might need to be added to your trusted lists in the configuration.

*   **Device-Specific Portal or Authentication Issues:**
    *   **MAC Address Lists:** ApFree WiFiDog can have lists of trusted (whitelisted) and untrusted (blacklisted) MAC addresses.
        *   Use `wdctlx show mac` to see MAC addresses that are configured (e.g., trusted or blocked based on system setup).
        Check these lists if a specific device is behaving unexpectedly.

#### Using `wdctlx` for Diagnostics

ApFree WiFiDog comes with a command-line utility called `wdctlx` (WiFiDog Control) that is very useful for diagnostics. It allows you to inspect the current state of WiFiDog without needing to restart the service. Some helpful commands include:

*   `wdctlx status [client|auth|wifidogx]`: Shows the general status of the daemon.
*   `wdctlx status client`: Lists all connected and authenticated clients.
*   `wdctlx show domain`: Displays the current list of trusted domains.
*   `wdctlx show wildcard_domain`: Displays the current list of trusted wildcard domains.
*   `wdctlx show mac`: Displays the MAC address list.
*   `wdctlx add <domain|wildcard_domain|mac> <value1,value2...>`: Adds specified values to the trusted domain, wildcard domain, or MAC list.
*   `wdctlx del <domain|wildcard_domain|mac> <value1,value2...>`: Deletes specified values from the trusted domain, wildcard domain, or MAC list.
*   `wdctlx clear <domain|wildcard_domain|mac>`: Clears all entries from the specified trusted list (domain, wildcard domain, or MAC).
*   `wdctlx stop`: Stops the wifidogx daemon.
*   `wdctlx reset <value>`: Resets specified wifidogx parameter or component.
*   `wdctlx refresh`: Refreshes wifidogx (e.g., reloads configurations or rules).
*   `wdctlx apfree <user_list|user_info|user_auth|save_user|restore_user> [values]`: Manages ApFree user sessions.
    *   `user_list`: Shows the list of online users.
    *   `user_info <MAC>`: Shows information for a specific user.
    *   `user_auth <MAC>`: Authenticates a user.
    *   `save_user`: Saves current user data.
    *   `restore_user`: Restores user data.
*   `wdctlx hotplugin <json_value>`: Sends a JSON configuration to the hotplugin system.

Refer to `wdctlx help` (or `wdctlx ?`) for more commands and options.

### Technical Details

This section provides a brief overview of ApFree WiFiDog's internal workings.

*   **Core Components:**
    *   **Main Gateway Process:** The central daemon that manages client connections, traffic, and interaction with other modules.
    *   **Authentication Module:** Handles the logic for client authentication, including communication with external authentication servers.
    *   **Firewall Interaction Module:** Responsible for dynamically updating firewall rules to control client access based on their authentication state.

*   **Event-Driven Architecture:** ApFree WiFiDog is built using an event-driven model, primarily leveraging the `libevent2` library. This allows it to handle a large number of concurrent client connections efficiently with low resource overhead, contributing to its high performance.

*   **Firewall Interaction:**
    *   ApFree WiFiDog dynamically manages network access by interacting with the Linux netfilter framework. It typically uses `iptables` for this purpose, but support for `nftables` might be available or configurable in newer versions or specific builds. The system may auto-detect the available firewall utility.
    *   It controls client access by adding and removing rules that can, for example, mark packets from authenticated clients for acceptance by the firewall or use connection tracking states to manage access. Unauthenticated clients are typically subject to rules that redirect their web traffic to the captive portal.

*   **High-Level Authentication Flow:**
    1.  **Redirection:** When an unauthenticated client attempts to access the internet (typically via HTTP/HTTPS), ApFree WiFiDog's firewall rules intercept the traffic. The client is then redirected to the captive portal URL, which is usually hosted on an external authentication server.
    2.  **Authentication Server Communication:** The client interacts with the authentication server (e.g., enters credentials, clicks a button, or makes a payment). The authentication server then validates the client.
    3.  **Firewall Update:** Upon successful authentication, the authentication server notifies ApFree WiFiDog. ApFree WiFiDog then updates the firewall rules (e.g., adds the client's IP or MAC address to an allowed list or marks their connections) to grant the client internet access for a specified duration or according to the defined policy. Client status and session validity are periodically checked.

### Authentication Server API

For developers looking to integrate ApFree WiFiDog with a custom authentication server, or to understand the communication protocol in detail, a dedicated API documentation is available. This document outlines the Ping, Counters (V2), and WebSocket interfaces used for communication between WiFiDog and the authentication server.

[View the Authentication Server API Documentation (English)](AUTH_SERVER_API_EN.md)

### Using ApFree WiFiDog in Cloud Auth Mode

To operate ApFree WiFiDog in cloud auth mode, you must first establish an authentication server. Once set up, configure ApFree WiFiDog to connect to your server by specifying its IP address or domain in the configuration file.

ApFree WiFiDog is configured using a plain text file, typically named `wifidog.conf` or `wifidogx.conf` (when using the `apfree-wifidogx` variant which includes HTTPS support). This file contains various parameters that control the behavior of the captive portal.

Here are some of the key configuration options:

*   `GatewayInterface`: Specifies the network interface for the captive portal (e.g., `br-lan`).
*   `AuthServerHostname`: The hostname or IP address of your authentication server.
*   `AuthServerPort`: The port number on which your authentication server is listening.
*   `AuthServerPath`: The path to the authentication service on your server (e.g., `/wifidog/`).
*   `CheckInterval`: The time interval (in seconds) at which ApFree WiFiDog checks the status of connected clients.
*   `ClientTimeout`: The time (in seconds) after which an inactive client is deauthenticated.

A sample configuration file, `wifidogx.conf`, is available in the `doc/` directory of the source code, which you can use as a starting point.

Additionally, ApFree WiFiDog introduces several important parameters to fine-tune its operation:

*   `UpdateDomainInterval`: When set to a non-zero value, this enables periodic DNS resolution for domain whitelists, ensuring that IP addresses for allowed domains are kept up-to-date.
*   `DNSTimeout`: Sets the timeout (in seconds, default is 1s) for non-blocking DNS queries used in domain whitelist resolution. This prevents the daemon from hanging on slow DNS lookups.
*   `bypassAppleCNA`: If enabled, ApFree WiFiDog will handle the iOS "whisper" or Captive Network Assistant (CNA) detection process. This helps ensure that Apple devices connect to the WiFi smoothly and trigger the captive portal as expected.
*   `JsFilter`: When enabled, this feature uses JavaScript-based redirection. This is primarily intended to filter out non-browser HTTP requests, which can reduce the load on the authentication server. However, be aware that this might interfere with in-app authentication mechanisms for some mobile applications. When disabled, standard HTTP 307 redirects are used.

#### Building the Auth Server

You can build your authentication server using the official server provided by the ApFree WiFiDog developers, known as WWAS. Unfortunately, WWAS is no longer maintained, as I am currently focused on a closed version called AWAS. If you need assistance, please feel free to contact me to discuss private service options.

**Important Note on SSL Certificates**: When redirecting HTTPS requests, the SSL certificate presented by the captive portal may trigger untrusted warnings on client devices. This is typical behavior for captive portal solutions and can be safely ignored by users who can proceed past the warning.

### How to Contribute

We welcome contributions to ApFree WiFiDog! You can create issues or submit pull requests on our [GitHub repository](https://github.com/liudf0716/apfree-wifidog). Please review our [CONTRIBUTING.md](https://github.com/liudf0716/apfree-wifidog/blob/master/CONTRIBUTING.md) to ensure your contributions align with the project standards.

### Contact Us

Join our QQ group for discussions and support: [331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev).