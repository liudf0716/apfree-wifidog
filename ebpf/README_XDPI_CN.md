# xDPI 快速 README（中文版）

> 本文件为面向新接触者 / 产品 / 运维人员的精简说明；更详细的设计、数据结构与深入说明请参阅同目录下 `XDPI_OVERVIEW.md`。

---
## 1. xDPI 是什么？
xDPI（Extended Deep Packet Inspection）是 apfree-wifidog 集成的一个轻量级七层协议 + 域名识别与流量统计子系统，基于 eBPF 与可选内核 kfunc 扩展实现：
- 常见 L7 协议识别：HTTP / HTTPS / SSH / SCP / MSTSC / DNS / DHCP / NTP / SNMP / TFTP / RTP 等
- 自动学习域名（从 DNS 响应提取 → 注册 → HTTP(S) 业务匹配）
- 连接会话事件输出（ring buffer）
- 多维度统计：按 协议SID / 域名SID / IP / MAC 聚合
- 支持（可选）速率估算与限速（令牌桶）
- 可通过编译开关快速启用 / 关闭：`ENABLE_XDPI_FEATURE`

应用价值：行为可视化、策略前置、准实时会话上报、便捷扩展协议识别能力。

---
## 2. 核心特性一览
| 类别 | 能力 | 说明 |
|------|------|------|
| 协议识别 | 内置指纹匹配 | 在 `xdpi-bpf.c` 中通过首包/特征字节判断 |
| 域名学习 | DNS 响应 → 归一 → 注册 | `/proc/xdpi_domains` 写入；用于 HTTP/HTTPS Payload 子串匹配 |
| 会话事件 | TCP / UDP 首次识别触发 | `session_events_map` ring buffer 输出结构体 `session_data_t` |
| 统计维度 | MAC / IPv4 / IPv6 / SID | Map：`mac_map` / `ipv4_map` / `ipv6_map` / `xdpi_l7_map` |
| 连接跟踪 | 五元组级别 | `tcp_conn_map` / `udp_conn_map` + 定时器（60s / 30s）|
| 速率限制 | 令牌桶（可选） | 通过 `incoming_rate_limit` / `outgoing_rate_limit` 字段控制 |
| 动态域名 | 最多 256 条 | 固定数组，可后续扩展回收策略 |
| 关闭回退 | 保留基础统计 | 关闭后仍有 MAC/IP 统计，不产出会话/协议事件 |

---
## 3. 高层工作流程
```
(1) DNS 响应 (egress) --> dns-bpf.c 抓取 --> ring buffer --> dns_monitor 解析域名
(2) 域名写入 /proc/xdpi_domains (IOCTL ADD) --> xdpi 内核模块维护 domains[]
(3) 业务流量经 tc_ingress / tc_egress --> aw-bpf.c 调 bpf_xdpi_skb_match() 识别协议/域名
(4) 新会话写 session_events_map；统计写入各类 map；可做速率控制
(5) 用户态 aw-bpfctl / event_daemon 读取、展示、上报
```

---
## 4. 关键组件对应表
| 文件/接口 | 作用 |
|-----------|------|
| `aw-bpf.c` | TC ingress/egress 主逻辑：连接跟踪 + 统计 + 事件输出 |
| `xdpi-bpf.c` | kfunc：协议/域名匹配（HTTP/HTTPS 字节扫描 + 协议指纹）|
| `dns-bpf.c` | 抓取 DNS 响应，推送原始负载至 ring buffer |
| `dns_monitor.c` | 解析 DNS，抽取有效域，调用 IOCTL 注册 |
| `event_daemon.c` | 消费会话事件，补充设备 / 地理信息（UCI 配置）|
| `aw-bpfctl.c` | CLI 工具：读取/打印统计、可扩展域名详情来源 |
| `/proc/xdpi_domains` | 域名追加/删除/更新入口 |
| `/proc/xdpi_l7_proto` | 已内置 L7 协议及 SID 列表 |

---
## 5. 关键数据结构 (精简)
| 名称 | 类型 | 作用 | 上限 |
|------|------|------|------|
| `mac_map` | HASH | 按源/目的 MAC 统计 | 1024 |
| `ipv4_map` / `ipv6_map` | HASH | 按 IP 统计 | 各 1024 |
| `tcp_conn_map` | HASH | 连接跟踪 + 定时器 (60s) | 10240 |
| `udp_conn_map` | HASH | 会话跟踪 + 定时器 (30s) | 10240 |
| `xdpi_l7_map` | HASH | 按 SID 聚合 L7 统计 | 1024 |
| `session_events_map` | RINGBUF | 会话事件输出 | 16MB |
| `dns_ringbuf` | RINGBUF | DNS 原始数据 | 256KB |
| `dns_stats_map` | PERCPU_ARRAY | DNS 查询/响应统计 | 1 |
| `domains[]` | 内核数组 | 域名（自养特征库，固定数组） | 256 |

## 6. 会话事件格式 (session_data_t 摘要)
| 字段 | 含义 |
|------|------|
| `sid` | 协议或域名 SID |
| `ip_version` | 4 / 6 |
| `proto` | 6=TCP / 17=UDP |
| `addrs` | 源/目的地址（IPv4 或 IPv6）|
| `sport` / `dport` | 源/目的端口 |

触发时机：首次识别该连接并确定 SID；同一连接只发送一次（标记 `event_sent`）。

---
## 7. 编译 / 启用
```bash
# CMake
cmake -DENABLE_XDPI_FEATURE=ON .. && make

# Makefile
make ENABLE_XDPI_FEATURE=1

# 关闭
cmake -DENABLE_XDPI_FEATURE=OFF .. && make
# 或
make ENABLE_XDPI_FEATURE=0
```
OpenWrt 示例：
```makefile
ifeq ($(CONFIG_TARGET_DEVICE_PROFILE),small)
  CMAKE_OPTIONS += -DENABLE_XDPI_FEATURE=OFF
else
  CMAKE_OPTIONS += -DENABLE_XDPI_FEATURE=ON
endif
```

---
## 8. 快速体验（示例）
```bash
# 1. 编译生成 aw-bpf.o, xdpi 模块已加载
./aw-loader &

# 2. 绑定到网卡 (示例 eth0)
tc qdisc add dev eth0 clsact || true
tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec tc_ingress || true
tc filter add dev eth0 egress  bpf da obj aw-bpf.o sec tc_egress  || true

# 3. 启动用户态处理
dns_monitor &
event_daemon &

# 4. 查看 L7 与域名
cat /proc/xdpi_l7_proto
cat /proc/xdpi_domains

# 5. 查看统计 / 会话
aw-bpfctl --list-sid
```

---
## 9. 常见问题 (FAQ 精简)
| 问题 | 解答 |
|------|------|
| 为什么 HTTPS 域名有时识别不到？ | 依赖明文 SNI / 初始握手字符串，遇 ECH/加密或非明文无法提取。 |
| 域名上限 256 会溢出吗？ | 当前为静态数组，后续可扩展 LRU / Aging。 |
| 能否新增协议？ | 在 `xdpi-bpf.c` 添加匹配函数并注册到 `l7_proto_entries[]`。 |
| 关闭 xDPI 有何影响？ | 不再生成会话事件与协议统计；IP/MAC 基础流量仍可用。 |
| 是否支持 IPv6？ | 支持，连接跟踪/事件/域名处理均适配。 |

---
## 10. 与传统方案对比（概括）
| 方案 | 识别范围 | 成本 | 扩展性 | 域名关联 |
|------|----------|------|--------|----------|
| iptables + conntrack | L3/L4 | 低 | 一般 | 需自建逻辑 |
| 传统重型 DPI | 深度 | 高 | 中 | 视实现 |
| xDPI | 常用轻量 L7 + 域名 | 中低 | 高 (C + eBPF) | 内置 DNS 学习 |

---
## 11. Roadmap 建议
- 域名淘汰策略（LRU / Aging）
- TLS SNI 专用解析优化
- HTTP2 / QUIC / gRPC 识别增强
- Prometheus / gNMI 导出
- 控制面 API（REST/gRPC）统一管理策略与限速
- 协议指纹模块化配置

---
## 12. 快速定位文件
| 功能 | 文件 |
|------|------|
| TC eBPF 主体 | `ebpf/aw-bpf.c` |
| 协议/域名匹配 kfunc | `ebpf/xdpi-bpf.c` |
| DNS 抓取 | `ebpf/dns-bpf.c` |
| DNS 用户态解析 | `src/dns_monitor.c` |
| 会话事件消费 | `ebpf/event_daemon.c` |
| CLI 统计工具 | `ebpf/aw-bpfctl.c` |
| 总览文档 | `ebpf/XDPI_OVERVIEW.md` |

---
## 13. 许可与联系
- 许可证：GPL（详见源码头部）
- 维护者：`liudf0716@gmail.com`
- 建议：提交 Issue / PR 反馈协议识别与扩展需求

---
> 如果需要：我可以再生成英文版或附加“部署排错指南”。欢迎提出下一步优化方向。
