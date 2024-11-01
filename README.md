[English Version](README.md) | [中文版本](README-zh.md)

<div align="center">
    <img src="https://user-images.githubusercontent.com/1182593/213065247-9a3cb0a5-dd08-4383-b217-b141ad32e88a.png" alt="ApFree WiFiDog Logo" width="400" height="400"/>
</div>

[![License](https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING) 
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/pulls) 
[![Issues Welcome](https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/issues/new) 
[![Release Version](https://img.shields.io/badge/release-7.10.2082-red.svg?style=plastic)](https://github.com/liudf0716/apfree_wifidog/releases) 
[![OpenWRT](https://img.shields.io/badge/Platform-%20OpenWRT%20-brightgreen.svg?style=plastic)](https://github.com/openwrt) 
[![Join the QQ Group](https://img.shields.io/badge/chat-qq%20group-brightgreen.svg)](https://jq.qq.com/?_wv=1027&k=4ADDSev)

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

### LuCI Integration

For simplified configuration, ApFree WiFiDog includes a LuCI interface. Manage your settings easily through a user-friendly web interface via the [luci-app-apfree-wifidog repository](https://github.com/liudf0716/luci-app-apfree-wifidog).

### Using ApFree WiFiDog in Cloud Auth Mode

To operate ApFree WiFiDog in cloud auth mode, you must first establish an authentication server. Once set up, configure ApFree WiFiDog to connect to your server by specifying its IP address or domain in the configuration file.

#### Building the Auth Server

You can build your authentication server using the official server provided by the ApFree WiFiDog developers, known as WWAS. Unfortunately, WWAS is no longer maintained, as I am currently focused on a closed version called AWAS. If you need assistance, please feel free to contact me to discuss private service options.

**Important Note on SSL Certificates**: When redirecting HTTPS requests, the SSL certificate presented by the captive portal may trigger untrusted warnings on client devices. This is typical behavior for captive portal solutions and can be safely ignored by users who can proceed past the warning.

### How to Contribute

We welcome contributions to ApFree WiFiDog! You can create issues or submit pull requests on our [GitHub repository](https://github.com/liudf0716/apfree-wifidog). Please review our [CONTRIBUTING.md](https://github.com/liudf0716/apfree-wifidog/blob/master/CONTRIBUTING.md) to ensure your contributions align with the project standards.

### Contact Us

Join our QQ group for discussions and support: [331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev).