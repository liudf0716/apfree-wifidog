<div align="center">
    <img src="https://user-images.githubusercontent.com/1182593/213065247-9a3cb0a5-dd08-4383-b217-b141ad32e88a.png" alt="ApFree WiFiDog Logo" width="400" height="400"/>
</div>

[![License](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING) 
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/pulls) 
[![Issues Welcome](https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/issues/new) 
[![Release Version](https://img.shields.io/badge/release-7.10.2082-red.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/releases) 
[![OpenWRT](https://img.shields.io/badge/Platform-%20OpenWRT%20-brightgreen.svg?style=plastic)](https://github.com/openwrt) 
[![Join the QQ Group](https://img.shields.io/badge/chat-qq%20group-brightgreen.svg)](https://jq.qq.com/?_wv=1027&k=4ADDSev)

[English Version](README.md) | [中文版本](README-zh.md) | [认证服务器API](AUTH_SERVER_API_ZH.md)

## ApFree WiFiDog: 高性能 HTTP(S) 认证门户解决方案

ApFree WiFiDog 是一个开源的高性能认证门户解决方案，专门用于在 OpenWrt 平台上对无线网络用户进行认证。它能够高效处理高并发和大量流量。

### 介绍视频

<div align="center">
    <a href="https://www.bilibili.com/video/BV18m411d7Yj/?vd_source=b303f6e8e0ed18809d8752d41ab1de7d">
        <img width="972" alt="ApFree WiFiDog 介绍视频" src="apfree-wifidog_intr.png">
    </a>
</div>

### 为什么选择 ApFree WiFiDog？

1. **稳定性**：通过 API 基于 iptables 规则，在多线程环境中增强稳定性。
2. **性能**：基于 libevent2 和 epoll 支持，显著超越原版 WiFiDog。
3. **HTTPS 支持**：确保安全的 HTTPS 重定向，符合现代网络安全标准。
4. **长连接支持**：支持长连接，包括 WebSocket 和 MQTT，实现实时通信。
5. **灵活的认证方式**：提供本地和云端认证，满足不同用户需求。
6. **高级规则管理**：支持动态管理访问规则，包括 MAC 地址和 IP/域名，无需重启。
7. **积极支持**：拥有积极活跃的社区支持及快速的问题响应。
8. **eBPF流控与DPI**：利用eBPF实现高效的流量控制和深度包检测(DPI)功能。

### 安装

OpenWrt 的包管理器命令因版本而异。

**对于最新的 OpenWrt 版本 (通常使用 `apk`):**
1. 更新软件包列表:
   ```bash
   apk update
   ```
2. 安装 ApFree WiFiDog:
   ```bash
   apk add apfree-wifidog
   ```

**对于较旧的 OpenWrt 版本 (通常使用 `opkg`):**
1. 更新软件包列表:
   ```bash
   opkg update
   ```
2. 安装 ApFree WiFiDog:
   ```bash
   opkg install apfree-wifidog
   ```

**LuCI Web 界面:**
`luci-app-apfree-wifidog` 软件包 **不能** 使用上述命令安装。有关设置 LuCI Web 界面的指导，请参阅“LuCI 集成”部分，其中推荐使用 `chawrt` 项目，或者如果您正在构建自己的固件，则从主 `luci` 仓库集成 LuCI。

### LuCI 集成

为了简化配置，ApFree WiFiDog 提供了 LuCI 界面。`luci-app-apfree-wifidog` 软件包之前是独立的，但现在已集成到主 `luci` 仓库中，地址为 [https://github.com/liudf0716/luci](https://github.com/liudf0716/luci)。

**推荐设置:**
我们建议用户采用 **`chawrt`** 项目来设置您的 OpenWrt 环境，该项目位于 [https://github.com/liudf0716/chawrt](https://github.com/liudf0716/chawrt)。`chawrt` 项目包含了 `luci-app-apfree-wifidog`，并提供了一个全面、即用型的 OpenWrt 固件解决方案，其中已集成了 ApFree WiFiDog。使用 `chawrt` 是开始使用完整配置系统的最简单方法。

如果您正在构建自己的固件或偏好手动安装，您可以在上面提到的 `luci` 仓库中找到该 LuCI 应用程序。然而，对于大多数用户来说，**`chawrt`** 提供了更简化的体验。

### 基本用法示例：访客网络

推荐使用 `luci-app-apfree-wifidog` 网页界面来配置 ApFree WiFiDog，它提供了一种用户友好的方式来管理所有设置。不鼓励手动编辑配置文件。

以下是两种常见的应用场景：

1.  **云认证方式:**
    *   此模式需要外部认证服务器。
    *   **通过 LuCI 配置步骤:**
        *   在 LuCI 中导航到 ApFree WiFiDog 配置页面。
        *   **认证服务器设置:** 配置认证服务器的 `主机名` (Hostname)、`端口` (Port) 和 `路径` (Path)。
        *   **网关配置:** 确保 `网关接口` (Gateway Interface) 正确设置为您的访客网络接口 (例如 `br-guest`)。
        *   **高级设置:** 为了支持实时通信和状态更新（云端方案通常需要），启用并配置 `WebSocket支持` (WebSocket Support) (例如，指定 WebSocket URL/路径)。
    *   连接到访客网络的客户端将被重定向到您的云认证门户。成功认证后，他们将被授予互联网访问权限。

2.  **本地认证方式 (仅展示页面):**
    *   此模式不需要外部认证服务器，通常用于较简单的场景，例如在授予访问权限之前显示欢迎页面或服务条款。
    *   **通过 LuCI 配置步骤:**
        *   在 LuCI 中导航到 ApFree WiFiDog 配置页面。
        *   **网关配置:** 确保 `网关接口` (Gateway Interface) 正确设置为您的访客网络接口 (例如 `br-guest`)。
        *   **认证模式:** 选择本地或展示页面模式（如果可用），或者确保没有配置外部 `AuthServer`。
        *   **跳转URL / 展示页面URL:** 配置 `跳转URL` (Redirect URL) (或类似字段) 指向您期望的本地展示页面或外部信息页面。这是用户在被授予访问权限之前将看到的页面。对于简单的“点击继续”设置，这可能是您在路由器本身上托管的页面或一个简单的外部站点。
    *   连接到访客网络的客户端将被重定向到此指定URL。根据具体的本地认证设置（可能因固件或自定义配置而异），他们可能在查看页面后或执行简单操作（如单击按钮）后立即获得访问权限。

这种方法为访客提供了一个受控且隔离的网络，同时要求他们通过您配置的门户或展示页面才能访问。记住在 LuCI 中保存并应用您的更改。

### 问题排查

遇到问题了？这里有一些步骤和常见问题可以帮助您排查 ApFree WiFiDog 设置。

#### 检查日志

ApFree WiFiDog 会记录日志消息，这些消息可以为其操作和任何错误提供有价值的见解。

*   **日志输出：** 默认情况下，ApFree WiFiDog 将日志消息输出到 `stderr`。如果您通过 OpenWrt 上的 init 脚本或服务管理器运行它，这些日志可能会被定向到系统日志 (syslog)，通常可以使用 `logread` 命令查看。某些配置可能允许直接指定日志文件。
*   **日志详细程度（调试级别）：** 您可以增加日志消息的详细程度以获取更多详细信息。这通常由 `wifidog.conf` / `wifidogx.conf` 文件中的 `DaemonLogLevel` 或类似设置控制。将其设置为更高级别（例如，7 表示调试）将产生更多输出。有关日志记录的具体选项，请查阅示例配置文件。

#### 常见问题和解决方案

*   **客户端未重定向到强制门户：**
    *   **服务状态：** 确保 ApFree WiFiDog 服务正在运行。您可以通过 LuCI 或在命令行中使用 `ps | grep wifidog` 来检查。
    *   **`GatewayInterface`：** 验证配置文件中的 `GatewayInterface` 是否与客户端所在的网络接口正确匹配（例如，`br-lan` 或您的特定访客接口）。
    *   **防火墙规则：** ApFree WiFiDog 依赖防火墙规则来拦截流量。检查是否存在必要的 iptables 规则 (`iptables -L -t nat`)。有时，自定义防火墙配置或其他服务可能会造成干扰。
    *   **DNS 解析：** 确保客户端使用的 DNS 服务器可以解析您的认证服务器的主机名。此外，路由器本身必须能够解析 DNS 以支持域名白名单功能。

*   **客户端已认证但无法访问特定网站/服务：**
    *   **受信任的域/主机：** ApFree WiFiDog 维护一个受信任的域和 IP 地址列表，客户端可以在认证前访问这些域和 IP 地址（有时在认证后也可以，具体取决于策略）。使用 `wdctlx show_trusted_domains` 命令查看当前活动的受信任域/IP 列表。如果某个站点无法正常工作，则其域或其资源（CDN、API）的域可能需要添加到配置中的受信任列表。

*   **特定设备的门户或认证问题：**
    *   **MAC 地址列表：** ApFree WiFiDog 可以包含受信任（白名单）和不受信任（黑名单）的 MAC 地址列表。
        *   使用 `wdctlx show mac` 查看已配置的 MAC 地址 (例如，根据系统设置可能是受信任的或已阻止的)。
        如果特定设备的行为异常，请检查这些列表。

#### 使用 `wdctlx` 进行诊断

ApFree WiFiDog 附带一个名为 `wdctlx` (WiFiDog Control) 的命令行实用程序，它对于诊断非常有用。它允许您检查 WiFiDog 的当前状态，而无需重新启动服务。一些有用的命令包括：

*   `wdctlx status [client|auth|wifidogx]`：显示守护进程的常规状态。
*   `wdctlx status client`：列出所有已连接和已认证的客户端。
*   `wdctlx show domain`：显示当前的受信任域列表。
*   `wdctlx show wildcard_domain`：显示当前的受信任通配符域列表。
*   `wdctlx show mac`：显示 MAC 地址列表。
*   `wdctlx add <domain|wildcard_domain|mac> <value1,value2...>`: 添加指定的值到信任的域名、通配符域名或 MAC 地址列表。
*   `wdctlx del <domain|wildcard_domain|mac> <value1,value2...>`: 从信任的域名、通配符域名或 MAC 地址列表中删除指定的值。
*   `wdctlx clear <domain|wildcard_domain|mac>`: 清除指定的信任列表（域名、通配符域名或 MAC 地址）中的所有条目。
*   `wdctlx stop`: 停止 wifidogx 守护进程。
*   `wdctlx reset <value>`: 重置指定的 wifidogx 参数或组件。
*   `wdctlx refresh`: 刷新 wifidogx (例如，重新加载配置或规则)。
*   `wdctlx apfree <user_list|user_info|user_auth|save_user|restore_user> [values]`: 管理 ApFree 用户会话。
    *   `user_list`: 显示在线用户列表。
    *   `user_info <MAC>`: 显示特定用户的信息。
    *   `user_auth <MAC>`: 认证一个用户。
    *   `save_user`: 保存当前用户数据。
    *   `restore_user`: 恢复用户数据。
*   `wdctlx hotplugin <json_value>`: 发送 JSON 配置到热插件系统。

有关更多命令和选项，请参阅 `wdctlx help` (或 `wdctlx ?`) 或文档。

### 技术细节

本节简要概述了 ApFree WiFiDog 的内部工作原理。

*   **核心组件：**
    *   **主网关进程：** 管理客户端连接、流量以及与其他模块交互的中央守护进程。
    *   **认证模块：** 处理客户端认证逻辑，包括与外部认证服务器的通信。
    *   **防火墙交互模块：** 负责根据客户端的认证状态动态更新防火墙规则以控制客户端访问。

*   **事件驱动架构：** ApFree WiFiDog 采用事件驱动模型构建，主要利用 `libevent2` 库。这使其能够以较低的资源开销高效处理大量并发客户端连接，从而实现高性能。

*   **防火墙交互：**
    *   ApFree WiFiDog 通过与 Linux netfilter 框架交互来动态管理网络访问。它通常为此目的使用 `iptables`，但在较新版本或特定构建中可能提供或可配置对 `nftables` 的支持。系统可能会自动检测可用的防火墙实用程序。
    *   它通过添加和删除规则来控制客户端访问，例如，这些规则可以标记来自已认证客户端的数据包以供防火墙接受，或使用连接跟踪状态来管理访问。未经认证的客户端通常会受到将其网络流量重定向到强制门户的规则的约束。

*   **高级认证流程：**
    1.  **重定向：** 当未经认证的客户端尝试访问互联网（通常通过 HTTP/HTTPS）时，ApFree WiFiDog 的防火墙规则会拦截该流量。然后，客户端将被重定向到强制门户 URL，该 URL 通常托管在外部认证服务器上。
    2.  **认证服务器通信：** 客户端与认证服务器交互（例如，输入凭据、单击按钮或付款）。然后，认证服务器验证客户端。
    3.  **防火墙更新：** 成功认证后，认证服务器会通知 ApFree WiFiDog。然后，ApFree WiFiDog 会更新防火墙规则（例如，将客户端的 IP 或 MAC 地址添加到允许列表或标记其连接），以在指定持续时间内或根据定义的策略授予客户端互联网访问权限。客户端状态和会话有效性会定期检查。

### 认证服务器API

对于希望将 ApFree WiFiDog 与自定义认证服务器集成，或希望详细了解通信协议的开发人员，我们提供了专门的 API 文档。该文档概述了 WiFiDog 与认证服务器之间通信所使用的 Ping (心跳)、Counters (计数器 V2) 和 WebSocket 接口。

[查看认证服务器API文档 (中文)](AUTH_SERVER_API_ZH.md)

### 在云认证模式下使用 ApFree WiFiDog

要在云认证模式下运行 ApFree WiFiDog，您必须首先建立一个认证服务器。设置完成后，通过在配置文件中指定其 IP 地址或域名来配置 ApFree WiFiDog 连接到您的服务器。

ApFree WiFiDog 使用纯文本文件进行配置，通常命名为 `wifidog.conf` 或 `wifidogx.conf`（当使用包含 HTTPS 支持的 `apfree-wifidogx` 变体时）。此文件包含控制强制门户行为的各种参数。

以下是一些关键配置选项：
*   `GatewayInterface`：指定强制门户的网络接口（例如，`br-lan`）。
*   `AuthServerHostname`：您的认证服务器的主机名或 IP 地址。
*   `AuthServerPort`：您的认证服务器正在侦听的端口号。
*   `AuthServerPath`：您的服务器上认证服务的路径（例如，`/wifidog/`）。
*   `CheckInterval`：ApFree WiFiDog 检查已连接客户端状态的时间间隔（以秒为单位）。
*   `ClientTimeout`：不活动客户端被取消认证的时间（以秒为单位）。

源代码的 `doc/` 目录中提供了一个示例配置文件 `wifidogx.conf`，您可以将其用作起点。

此外，ApFree WiFiDog 引入了几个重要的参数来微调其操作：
*   `UpdateDomainInterval`：当设置为非零值时，此选项启用域白名单的定期 DNS 解析，确保允许域的 IP 地址保持最新。
*   `DNSTimeout`：设置用于域白名单解析的非阻塞 DNS 查询的超时时间（以秒为单位，默认为 1 秒）。这可以防止守护进程因 DNS 查询缓慢而挂起。
*   `bypassAppleCNA`：如果启用，ApFree WiFiDog 将处理 iOS “whisper” 或强制网络助手 (CNA) 检测过程。这有助于确保 Apple 设备顺利连接到 WiFi 并按预期触发强制门户。
*   `JsFilter`：启用后，此功能使用基于 JavaScript 的重定向。这主要用于过滤掉非浏览器 HTTP 请求，从而减少认证服务器的负载。但是，请注意，这可能会干扰某些移动应用程序的应用内认证机制。禁用时，将使用标准的 HTTP 307 重定向。

#### 构建认证服务器

您可以使用 ApFree WiFiDog 开发者提供的官方服务器构建认证服务器，称为 WWAS。遗憾的是，WWAS 目前不再维护，因为我正在专注于维护一个名为 AWAS 的闭源版本。如果您需要帮助，请随时联系我以讨论私人服务选项。

**重要说明关于 SSL 证书**：重定向 HTTPS 请求时，认证门户提供的 SSL 证书可能会在客户端设备上触发不受信任的警告。这是认证门户解决方案的典型行为，用户可以安全地忽略该警告并继续操作。

### 如何贡献

我们欢迎您为 ApFree WiFiDog 贡献代码！您可以在我们的 [GitHub 仓库](https://github.com/liudf0716/apfree-wifidog) 上创建问题或提交拉取请求。请查看我们的 [CONTRIBUTING.md](https://github.com/liudf0716/apfree-wifidog/blob/master/CONTRIBUTING.md) 以确保您的贡献符合项目标准。

### 联系我们

加入我们的QQ群以进行讨论和支持：[331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev).
