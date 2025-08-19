
<p align="center">
  <img src="https://user-images.githubusercontent.com/1182593/213065247-9a3cb0a5-dd08-4383-b217-b141ad32e88a.png" alt="ApFree WiFiDog Logo" width="260"/>
</p>    

<h1 align="center">ApFree WiFiDog</h1>
<p align="center"><i>A High-Performance Captive Portal Solution for HTTP(S) on OpenWrt</i></p>

<p align="center">
  <a href="https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING">
    <img src="https://img.shields.io/badge/License-GPLv3-brightgreen.svg?style=flat-square" alt="License"/>
  </a>
  <a href="https://github.com/liudf0716/apfree_wifidog/pulls">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square" alt="PRs Welcome"/>
  </a>
  <a href="https://github.com/liudf0716/apfree_wifidog/issues/new">
    <img src="https://img.shields.io/badge/Issues-Welcome-brightgreen.svg?style=flat-square" alt="Issues Welcome"/>
  </a>
  <a href="https://github.com/liudf0716/apfree_wifidog/releases">
    <img src="https://img.shields.io/badge/Release-7.10.2082-red.svg?style=flat-square" alt="Release"/>
  </a>
  <a href="https://github.com/openwrt">
    <img src="https://img.shields.io/badge/Platform-OpenWrt-blue.svg?style=flat-square" alt="Platform"/>
  </a>
  <a href="https://jq.qq.com/?_wv=1027&k=4ADDSev">
    <img src="https://img.shields.io/badge/Chat-QQ%20Group-brightgreen.svg?style=flat-square" alt="QQ Group"/>
  </a>
</p>

<p align="center">
  🌍 <a href="README.md">English</a> | 🇨🇳 <a href="README-zh.md">中文</a> | 📑 <a href="AUTH_SERVER_API_EN.md">Auth Server API</a>
</p>

---

## 📖 Introduction

ApFree WiFiDog is an **open-source, high-performance captive portal** for HTTP and HTTPS, tailored for the **OpenWrt** platform.  
It provides **secure authentication, high concurrency handling, and flexible rule management** for Wi-Fi networks.

🎬 **Introduction Video**  
<p align="center">
  <a href="https://www.bilibili.com/video/BV18m411d7Yj/?vd_source=b303f6e8e0ed18809d8752d41ab1de7d">
    <img width="720" alt="ApFree WiFiDog Introduction" src="apfree-wifidog_intr.png">
  </a>
</p>

---

## 🚀 Features

- **Stable** – API-based iptables integration, thread-safe.  
- **Fast** – Built with libevent2 + epoll, far outperforms original WiFiDog.  
- **Secure** – Full HTTPS redirection support.  
- **Real-time** – Long connection support (WebSocket, MQTT).  
- **Flexible** – Local + Cloud authentication, splash page mode.  
- **Dynamic Rules** – Manage MAC, IP, domains without restart.  
- **eBPF Support** – Traffic control & DPI via eBPF.  
- **Active Community** – Fast responses and continuous updates.  

---

## 📦 Installation

On **OpenWrt (latest)**:  
```bash
apk update
apk add apfree-wifidog
```

On **older OpenWrt**:  
```bash
opkg update
opkg install apfree-wifidog
```

👉 For **LuCI Web Interface**, see [LuCI Integration](#-luci-integration).

---

## 🖥️ LuCI Integration

- ApFree WiFiDog provides a **LuCI Web UI** via `luci-app-apfree-wifidog`.  
- Integrated in the [luci repo](https://github.com/liudf0716/luci).  

💡 Recommended: use [**chawrt**](https://github.com/liudf0716/chawrt),  
which bundles ApFree WiFiDog + LuCI for a **ready-to-use OpenWrt firmware**.

---

## ⚙️ Basic Usage Example

### 1. Cloud Authentication Mode
- Requires external auth server.  
- Configure via LuCI: `Auth Server` (Hostname, Port, Path) + `Gateway Interface`.  
- Enable **WebSocket Support** for real-time status.

### 2. Local Authentication (Splash Page)
- No external auth server needed.  
- Configure LuCI: `Gateway Interface` + Redirect URL (welcome / terms page).  
- Simple click-to-continue or custom splash page.  

---

## 🛠️ Troubleshooting

### Logs
- Check via:  
  ```bash
  logread
  ```
- Increase debug level in `wifidogx.conf` → `DaemonLogLevel 7`.

### Common Issues
- **No redirection** → check `GatewayInterface`, firewall rules, DNS.  
- **Sites blocked** → update trusted domains via `wdctlx show domain`.  
- **Device issues** → check MAC lists (`wdctlx show mac`).  

### Useful `wdctlx` Commands
```bash
wdctlx status client       # Show authenticated clients
wdctlx show domain         # Show trusted domains
wdctlx add domain example.com
wdctlx apfree user_list    # List online users
```

---

## 🔬 Technical Overview

- **Event-driven architecture** (`libevent2`) for massive concurrency.  
- **Firewall integration** via `iptables` (with nftables support).  
- **Auth flow**: Redirect → Auth Server → Firewall update → Internet access.  

📑 See [Auth Server API](AUTH_SERVER_API_EN.md) for protocol details.

---

## 🤝 Contributing

We welcome contributions!  
- Submit issues: [GitHub Issues](https://github.com/liudf0716/apfree_wifidog/issues)  
- Pull requests: [GitHub PRs](https://github.com/liudf0716/apfree_wifidog/pulls)  
- Guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📬 Contact

- QQ Group: [331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev)  

---
