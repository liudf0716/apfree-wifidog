
<div align="center">
    <img src="https://user-images.githubusercontent.com/1182593/213065247-9a3cb0a5-dd08-4383-b217-b141ad32e88a.png" alt="ApFree WiFiDog Logo" width="400" height="400"/>
</div>

[![License](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING) 
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/pulls) 
[![Issues Welcome](https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/issues/new) 
[![Release Version](https://img.shields.io/badge/release-7.10.2082-red.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/releases) 
[![OpenWRT](https://img.shields.io/badge/Platform-%20OpenWRT%20-brightgreen.svg?style=plastic)](https://github.com/openwrt) 
[![Join the QQ Group](https://img.shields.io/badge/chat-qq%20group-brightgreen.svg)](https://jq.qq.com/?_wv=1027&k=4ADDSev)

[English Version](README.md) | [中文版本](README-zh.md)

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

### LuCI 集成

为简化配置，ApFree WiFiDog 包含 LuCI 界面。您可以通过 [luci-app-apfree-wifidog 仓库](https://github.com/liudf0716/luci-app-apfree-wifidog) 轻松管理设置。

### 在云认证模式下使用 ApFree WiFiDog

要在云认证模式下运行 ApFree WiFiDog，您需要先建立一个认证服务器。设置完成后，通过在配置文件中指定服务器的 IP 地址或域名来配置 ApFree WiFiDog 连接到服务器。

#### 构建认证服务器

您可以使用 ApFree WiFiDog 开发者提供的官方服务器构建认证服务器，称为 WWAS。遗憾的是，WWAS 目前不再维护，因为我正在专注于维护一个名为 AWAS 的闭源版本。如果您需要帮助，请随时联系我以讨论私人服务选项。

**重要说明关于 SSL 证书**：重定向 HTTPS 请求时，认证门户提供的 SSL 证书可能会在客户端设备上触发不受信任的警告。这是认证门户解决方案的典型行为，用户可以安全地忽略该警告并继续操作。

### 如何贡献

我们欢迎您为 ApFree WiFiDog 贡献代码！您可以在我们的 [GitHub 仓库](https://github.com/liudf0716/apfree-wifidog) 上创建问题或提交拉取请求。请查看我们的 [CONTRIBUTING.md](https://github.com/liudf0716/apfree-wifidog/blob/master/CONTRIBUTING.md) 以确保您的贡献符合项目标准。

### 联系我们

加入我们的QQ群以进行讨论和支持：[331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev).
