# xDPI 概览 (Extended Deep Packet Inspection)

> 前置说明：什么是 eBPF？
> 
> eBPF（extended Berkeley Packet Filter）是 Linux 内核中的一个安全可验证、事件驱动、可热加载的“内核微程序”运行环境。开发者可以将经过严格验证的字节码加载到内核特定挂载点（如网络栈、套接字、跟踪点、cgroup、调度器等）执行，而无需改内核源码或编写复杂的传统内核模块。其核心价值：
> - 安全：加载前由 Verifier 静态检查（边界、类型、循环、栈使用）
> - 高效：在内核态直接获取上下文，减少用户态/内核态切换与数据复制
> - 可组合：通过 Map（共享存储）、Ring Buffer（事件输出）、Tail Call（程序跳转）、kfunc（调用内核导出函数）快速构建功能流水线
> - 可演进：配合 CO-RE（Compile Once Run Everywhere）减少随内核版本变动的重编译成本
> - 生态成熟：bpftool、libbpf、bcc 提供加载与调试支撑
>
> xDPI 正是利用 eBPF 在 **TC (Traffic Control) ingress/egress** 挂载点对数据包进行轻量解析、协议指纹匹配、会话事件生成与统计聚合；再通过用户态进程进行域名学习与数据消费，从而实现“可扩展 DPI + 域名可观测”的组合能力。


> 面向新用户的功能介绍、价值说明与快速上手指南。本文件聚焦于 apfree-wifidog 中的增强型 DPI 子系统：xDPI。

---
## 1. 什么是 xDPI?
xDPI (Extended Deep Packet Inspection) 是内置于 apfree-wifidog 的一个轻量级、可扩展的七层协议与域名识别/统计框架。它基于 Linux eBPF 与可选的内核 kfunc 扩展，实现以下核心能力：

- L7 协议快速识别 (HTTP / HTTPS / SSH / SCP / MSTSC / DNS / DHCP / NTP / SNMP / TFTP / RTP 等)
- 动态域名识别与自增 SID 分配（运行期从真实 DNS 响应中“自养”特征集合，固定数组上限 256，避免庞大静态签名冗余；后续可扩展 Aging / LRU 回收）
- 连接级会话事件实时输出（环形缓冲区 ring buffer）
- 多维度统计：按协议 SID、IP、MAC 汇总上下行字节 / 包速率
- 支持速率估算 (平滑窗口 RATE_ESTIMATOR=4s)
- 支持基础速率限制（基于令牌桶 EDT 调度）
- 低侵入，可通过编译选项按需开启或关闭 (ENABLE_XDPI_FEATURE)

xDPI 的设计原则：
1. 不修改内核：主体逻辑运行在 eBPF + 进程用户态协同
2. 精准可控：协议识别 + 域名匹配均是显式逻辑，方便调试与扩展
3. 成本可控：对低性能嵌入式设备可禁用以节省内存 / CPU
4. 自适应特征：特征库运行期按需生成并保持常数级上限（256），减少无效匹配开销

---
## 2. 为什么选择 eBPF（基础介绍）
eBPF (extended Berkeley Packet Filter) 是 Linux 内核中的一个安全、可验证、可热插拔的执行环境。它允许在不修改内核源码、不加载传统内核模块的前提下，将受限用户定义逻辑加载到内核并在各种 hook 点运行。xDPI 选择 eBPF 的原因如下：

### 2.1 关键特性
- 安全可验证：加载前经内核 Verifier 静态检查（边界、循环、栈深、类型约束）
- 即插即用：失败可回滚，支持增量调试，不破坏稳定路径
- 高性能：在内核态直接访问包头、上下文，避免用户态频繁拷贝
- 组合式：通过 map、tail call、ring buffer、kfunc 等机制构建微模块架构
- 生态成熟：bpftool / libbpf / CO-RE (Compile Once – Run Everywhere) 逐渐标准化

### 2.2 xDPI 使用的主要 eBPF 能力
| 能力 | 在 xDPI 中的具体使用 |
|------|----------------------|
| TC hook (`clsact` qdisc) | 在 `tc_ingress` / `tc_egress` 中解析二至四层头、连接跟踪、协议匹配、统计更新 |
| BPF Map (HASH) | `mac_map` / `ipv4_map` / `udp_conn_map` / `tcp_conn_map` / `xdpi_l7_map` |
| BPF Map (RINGBUF) | `session_events_map` (会话事件), `dns_ringbuf` (DNS 原始负载) |
| BPF Map (PROG_ARRAY) | `prog_array_map` 用于 tail call 将 egress 流量跳转到 `dns_handler_egress` |
| BPF Map (PERCPU_ARRAY) | `dns_stats_map` 统计 DNS 查询/响应/错误/IP 类型 |
| bpf_timer | 为连接条目（`xdpi_nf_conn`）实现超时回收 (TCP 60s / UDP 30s) |
| kfunc 调用 | 调用内核注册的 `bpf_xdpi_skb_match` 进行协议+域名匹配 |
| Tail Call | 通过 `prog_array_map` 将通用链路拆分（主处理与 DNS 解析）降低执行路径长度 |
| 内核 proc FS 协同 | `/proc/xdpi_domains` 与 `/proc/xdpi_l7_proto` 作为用户态控制面接口 |

### 2.3 与其它路径的对比
| 方案 | 优点 | 局限 | 适用场景 |
|------|------|------|----------|
| Netfilter (iptables/nftables) | 成熟、规则式、生态丰富 | L7 能力弱、自定义解析受限 | 传统防火墙、包过滤 |
| XDP | 更早（驱动层）拦截、极致性能 | 处理复杂 L4/L7 需更多手工代码；不适合需要连接状态的中层统计 | DDoS 防护、快速丢包/转发 |
| 内核模块 (自定义) | 功能自由度最高 | 维护成本高、崩溃风险、升级复杂 | 重度协议栈修改 |
| eBPF (本方案) | 安全验证、快速迭代、适中性能、与内核解耦 | 受 Verifier 限制；循环/复杂解析需优化 | 动态可观测、轻量 DPI、策略试验 |

### 2.4 性能与资源注意点
- Map 尺寸：`tcp/udp_conn_map` 设为 10240 上限，需评估设备 RAM（哈希条目 + 计时器开销）
- 连接定时器：大量短连接爆发时，timer 回调频率提升，建议后续做批式回收或层级轮询优化
- 字符串匹配：HTTP/HTTPS 域名子串扫描当前为 O(N*M) 朴素匹配，可在条目接近上限或域名较长时考虑 Aho-Corasick / BPF 预编译前缀树
- Ring Buffer：`session_events_map` 设为 16MB；高并发下用户态若未及时消费会导致覆盖/丢事件（需监控消费延迟）
- 指纹扩展：新增协议匹配函数时应遵循“最小必要字节判断”，避免过大线性扫描

### 2.5 安全/稳定性实践建议
- 始终使用 GPL 兼容 License，避免 kfunc / helper 限制
- 编写协议匹配函数时限制读取边界：确保 `data_sz` 检查优先于访问
- 严控 map 上限：防止哈希放大造成内存压力
- 当需要引入更复杂字符串算法时，可评估是否迁移到用户态预处理（如生成压缩匹配表后下发 BPF map）
- 利用 bpftool prog/load pin 机制实现原子替换，升级可回滚

### 2.6 未来可演进方向（eBPF 相关）
- CO-RE 重构，移除对固定内核版本的依赖
- 引入 BPF LSM Hook 做更细粒度安全策略（可选）
- 使用 BPF 链接器 (libbpf gen skeleton) 自动生成用户态加载骨架
- 将域名匹配从内核字符串朴素搜索升级为预处理特征表（map 扩展为 trie/prefix 格式）

> 本节为 eBPF 背景补充，帮助非内核/eBPF 背景读者理解 xDPI 的实现取舍。 

---
## 3. 体系结构概览

```
             +----------------------------+
             |        用户态 (Userland)   |
             |                            |
             |  aw-bpfctl  (统计/查询/展示) |
             |  event_daemon (会话事件消费) |
             |  dns_monitor  (DNS响应解析)  |
             +---------------+------------+
                             |  RingBuf / /proc / bpf maps
                    +--------v----------------------------+
                    |          eBPF 平面 (TC hook)        |
Ingress  -----> tc_ingress() --+                          |
                               |  协议识别: bpf_xdpi_skb_match kfunc
Egress   <----- tc_egress() ---+-- tail call --> dns_handler_egress()
                    |          |  连接跟踪: tcp_conn_map / udp_conn_map
                    |          |  统计: mac_map / ipv4_map / ipv6_map / xdpi_l7_map
                    +----------+--------------------------+
                               |
                        Linux 网络数据路径
```

### 关键组件说明
| 组件 | 位置 | 作用 |
|------|------|------|
| `aw-bpf.c` | eBPF TC 入口 | 解析以太网/IP/TCP/UDP，调用协议匹配，维护多类 Map，发出会话事件 |
| `xdpi-bpf.c` | 内核模块 (kfunc) | 提供 `bpf_xdpi_skb_match()` 协议/域名匹配入口（HTTP/HTTPS 域名扫描 + L7 指纹）|
| `dns-bpf.c` | eBPF 程序 | 在 Egress 方向抓取 DNS 响应，复制必要部分到 ring buffer |
| `dns_monitor.c` | 用户态 | 读取 DNS ring buffer，解析域名，筛选有效域名，写入 `/proc/xdpi_domains`（IOCTL 添加）|
| `/proc/xdpi_domains` | 内核模块 ProcFS | 动态写入域名（ADD/DEL/UPDATE），供 kfunc 域名匹配使用 |
| `/proc/xdpi_l7_proto` | ProcFS | 列出内置协议及其 SID |
| `event_daemon.c` | 用户态 | 读取 `session_events_map`，整合位置信息/MAC，供上报或落盘 |
| `aw-bpfctl.c` | 用户态 CLI | 读取各种 map，统计/展示速率，附加域名详情（可对接远程 API）|

---
## 4. 数据流 & 行为路径

### 4.1 协议与连接路径
1. 数据包进入 TC ingress/egress hook。
2. 解析二层/三层/四层头；更新 MAC/IP 统计（`mac_map`, `ipv4_map`, `ipv6_map`）。
3. 若启用 `ENABLE_XDPI_FEATURE`：
   - TCP/UDP 分别构造五元组 `bpf_sock_tuple`
   - 新会话：调用 `bpf_xdpi_skb_match()` -> 返回协议 SID / 域名扩展 SID / -ENOENT
   - 分配/查询 `tcp_conn_map` / `udp_conn_map`，挂接定时器（超时清理：TCP 60s / UDP 30s）
   - 首包或首识别成功时：写入 `session_events_map` ring buffer
   - 更新协议聚合统计：`xdpi_l7_map`
4. 速率限制（若设定 `incoming_rate_limit` / `outgoing_rate_limit`）：调用令牌桶逻辑 `edt_sched_departure()`，决定丢弃或放行。

### 4.2 域名学习扩展
1. Egress 方向 tail call 到 `dns_handler_egress()`（`prog_array_map[0]` 绑定）。
2. 只抓取 DNS Response (port=53, QR=1)。
3. 将截断后的原始 DNS 负载放入 `dns_ringbuf`。
4. 用户态 `dns_monitor` 解析：
   - 过滤反向解析 (`in-addr.arpa`, `ip6.arpa`)
   - 提取主域名（短化：如 `a.b.example.com` -> `example.com` 或 `example.com.cn` 保留三段）
   - 验证有效后缀 → 判断是否需要初次同步 (`/proc/xdpi_domain_num`)
   - 通过 IOCTL `XDPI_IOC_ADD` 写入 `/proc/xdpi_domains`，模块内维护数组 `domains[]`
5. `xdpi-bpf.c` 后续匹配 HTTP(S) 报文时扫描 payload 中是否包含已登记域名子串，命中则返回对应 SID。

### 4.3 动态特征库 vs 传统静态签名集
传统 DPI 常依赖：
- 预置庞大且长期累积的协议/域名特征库
- 需要人工或定期离线更新；对大量“本环境永远不会出现”的特征也逐包匹配
- 在 HTTPS 全面加密 (SNI/ECH) 趋势下，大量旧式 Payload 级特征逐渐失效 → “命中率下降 + 计算仍然发生”

xDPI 通过“运行时自生成 + 环境自适应”策略降低无效匹配成本：
1. 仅对实际出现的 DNS 响应域名进行统计与短化处理（去冗余、合并主域）
2. 按插入顺序自增 SID，域名条目上限固定 (256)，避免无限膨胀
3. 域名匹配只在 HTTP/HTTPS 报文前若干字节范围内做朴素子串扫描，减少深度遍历
4. 不需要离线签名分发，部署后即可“自养”本地最热域名集合
5. 高命中域名优先进入集合 → 实际可见环境命中率显著高于“全球通用大签名”模型
6. 由于条目少 & 热度相关，字符串匹配总体开销保持在 O(热点集合规模) 而非 O(全量历史特征库规模)

收益对比（定性）：
| 维度 | 传统静态特征库 | xDPI 动态自生成 | 效果 |
|------|----------------|----------------|------|
| 维护方式 | 外部发布 / 手工更新 | 运行期自动学习 | 降低运维成本 |
| 库大小 | 易膨胀（数千 ~ 数万） | 固定上限 256 | 常数级可控内存占用 |
| 无效匹配 | 大量无关环境特征仍遍历 | 仅对本网络出现域名 | 减少 CPU 消耗 |
| HTTPS 适配 | 旧式 Payload 特征逐步失效 | 利用 SNI/首包可见域名 | 提升有效命中率 |
| 部署速度 | 依赖签名同步 | 即装即学 | 上线快 |
| 性能退化风险 | 增量特征→线性变慢 | 有上限，无退化曲线 | 稳定 |

> 小结：xDPI 用“按需生长 + 上限控制”的方式替换“大而全静态库”，在 HTTPS 普及背景下更贴近真实可见信号，提高命中率同时节省大量无效计算。

### 4.4 会话事件
- 结构：`session_data_t { sid, ip_version, proto, saddr, daddr, sport, dport }`
- 发出条件：首次识别出带 SID 的 TCP/UDP 会话
- 消费：`event_daemon` 读取 ring buffer → 补充 AP 信息（location_id / ap_device_id / MAC）→ 可扩展上报

---
## 5. 应用场景 / 价值亮点
| 场景 | 价值 |
|------|------|
| 精细化流量识别 | 快速区分常见管理/业务/后台协议，辅助策略控制 |
| 域名级行为分析 | 通过 DNS 自动学习常用域名并关联 HTTP/HTTPS 会话（环境自适应高命中） |
| 安全合规审计 | 记录会话元数据，可扩展写入 SIEM/日志系统 |
| 多维度 QoS 与限速 | 可按 MAC / IP / 协议 / 域名实施速率限制（后续扩展，聚焦热域资源）|
| 边缘节点可观测性 | 低开销可运行于 OpenWrt/小型盒子，实现本地可视化 |
| 自适应特征优化 | 避免全局冗余特征拖累性能，提高真实命中率 |

---
## 6. 与传统方案对比
| 对比项 | iptables + nf_conntrack | 纯 DPI 引擎 | xDPI (本方案) |
|--------|-------------------------|-------------|---------------|
| 协议识别 | 局限于 L3/L4 | 强，但重 | 适度可扩展，轻量 |
| 域名关联 | 需额外解析逻辑 | 取决于实现 | 内置 DNS → 域名学习 |
| 性能 | 中等 | 视实现 | BPF 原生 + 热域小集合匹配 |
| 定制开发 | 中 | 难 | 中（C 代码 + eBPF）|
| 资源占用 | 中 | 高 | 可按需关闭 + 固定域名上限 |
| 签名演进 | 较重（需同步） | 依赖厂商 | 运行期自动自养 |
| HTTPS 适应性 | 依赖旧特征，衰退 | 取决实现 | 利用 DNS/SNI 动态特征 |

---
## 7. FAQ
**Q1: 如何新增自定义协议?**  
在 `xdpi-bpf.c` 中新增匹配函数 + 加入 `l7_proto_entries[]`；重新编译并部署。

**Q2: 域名 SID 如何回收?**  
当前实现为固定数组（上限 256）；可通过 `/proc/xdpi_domains` IOCTL DEL/UPDATE 进行维护（后续可扩展 LRU）。

**Q3: 为什么有些 HTTPS 域名无法匹配?**  
HTTPS 加密，当前仅通过初始 TLS ClientHello Payload 中字符串匹配域名（需域名出现在明文 SNI / HTTP 报文）。若未出现在握手明文或遭加密扩展 (ESNI/ECH) 则无法匹配。

**Q3.1: 动态域名特征机制相比静态库的最大收益是什么?**  
避免加载“与当前网络毫不相关”的海量特征；仅记录真实出现的高频域名 → 减少比较次数、提升有效命中率、显著降低 HTTPS 场景下传统 DPI 逐步失效时的冗余计算浪费。

**Q4: 是否支持 IPv6?**  
是。连接跟踪、会话事件、DNS 解析均考虑 IPv6。域名匹配逻辑与 IPv4 相同。

**Q5: 性能如何?**  
在常规嵌入式硬件（单核~双核 MIPS/ARM）下可满足千兆以下管理流量识别需求；未做大规模 DPI 深度报文重组，因此开销可控。具体 QPS 与 PPS 建议通过内部基准实测。

**Q6: 关闭 xDPI 后影响?**  
`tcp_conn_map/udp_conn_map/xdpi_l7_map` 不再创建；不输出会话事件；仍保留基础流量统计 (IP/MAC)。

---
## 8. 后续规划 (Roadmap 建议)
- [ ] 域名条目溢出策略（LRU / Aging）
- [ ] TLS SNI 专用解析提速（避免全字节扫描）
- [ ] gRPC / QUIC / HTTP2 识别增强
- [ ] 更丰富的导出格式：Prometheus / gNMI
- [ ] eBPF CO-RE 优化与 bpftool 自适应加载
- [ ] 统一控制面 API（REST/gRPC）动态调整限速与策略

---
## 9. 术语速览
| 术语 | 含义 |
|------|------|
| SID | Session / Service Identifier，协议或域名的内部编号 |
| kfunc | 供 eBPF 调用的内核函数（BTF 注册）|
| ring buffer | eBPF 到用户态的高效数据传输结构 |
| tail call | eBPF 程序间快速跳转机制 |
| 五元组 | 源/目地址 + 源/目端口 + 协议 |

---
## 10. 版权与许可
本模块遵循 GPLv2 或更高版本（参考源码头部声明）。

---
## 11. 联系与反馈
若发现缺陷或希望扩展协议，请提交 Issue 或 PR，或联系维护者：`liudf0716@gmail.com`。

---
> 本文档可复制到外部推广材料，若需英文版可在后续追加 `XDPI_OVERVIEW_EN.md`。
