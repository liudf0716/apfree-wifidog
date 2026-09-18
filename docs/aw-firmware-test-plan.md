# aw 设备（chawrt 新固件）验收测试方案

> 适用固件：aw-bpf **1.08.23** + apfree-wifidog **9.09.2938**（chawrt/25.12，含 eBPF captive DNS 抢答、dnsmasq hosts 迁移、firewall4 LAN SYN 豁免）。
> 测试对象：aw 路由器（192.168.8.1，br-lan），oc VPS（43.159.38.154）作为 xkcptun 服务端。
> 状态：**待执行**。按 A → H 顺序执行；B/C/D6/D7 依赖决策点 1。

## 背景与已知现状（测试前须知）

- captive DNS 抢答架构：aw-bpf 在 br-lan TC ingress 抢答 `captive_domain_map` 内域名的 UDP/53 查询（默认假 IP 1.1.1.1，AAAA 回 NODATA），同时 `bpf_clone_redirect` 让原查询照常到 dnsmasq；真实 IP 由 wifidogx dns_snoop 从 WAN 口 XDP 监听学习回 map（`learned=1`）。
- 新版 wifidogx 启动时：自动清除旧机制遗留的 `/etc/aw-captive-domains-hosts` 与 dnsmasq addnhosts 配置；`disable_portal_auth='0'` 时向 map 灌注全部 captive 域名。
- xdns-bpf（pref 1）与 aw-bpf（pref 2）在 br-lan 级联；xdns 将匹配域名的 DNS DNAT 到 `192.168.8.1:5353`、TCP DNAT 到 `192.168.8.1:12345`，由 xkcptun 隧道到 oc 解析/转发。
- **已知问题**：路由器 `xkcptun.ssh_tunnel.target_port='27334'`，但 oc 上 27334 无监听（sshd 仅 :22）——SSH 隧道当前指向死端口，H1 需先修正。
- **已知环境噪音（非缺陷）**：`disable_portal_auth='1'` 时 wifidogx 无 nft 表，ping 周期报 `set_wifidogx_auth_servers` nft 失败；开启 portal auth 后应消失。

## 决策点（执行前确认）

| # | 决策 | 影响 | 建议 |
|---|---|---|---|
| 1 | 是否临时开启 portal auth（`uci set wifidogx.common.disable_portal_auth=0`） | B/C4/D6/D7；开启后未认证客户端流量被拦截，需先把测试机 MAC 加入信任白名单 | 开启，测完恢复 `1` |
| 2 | 离线测试窗口 | C 组需 `eth1` down 约 2~3 分钟，全网断外网 | 择机执行 |
| 3 | 是否修正 `xkcptun.ssh_tunnel.target_port` 27334→22 | H 组；仅影响该隧道 | 修正 |
| 4 | 是否向 xdns 代理列表临时添加 IP 回显域名（如 `ip.sb`，测完删除） | G4 端到端出网证明 | 添加 |

## A. 刷机后基础环境确认

- [ ] **A1** 版本正确：`apk info | grep -E 'aw-bpf|apfree'` 显示 1.08.23 / 9.09.2938；wifidogx 版本串一致
- [ ] **A2** BPF 对象为新版：`md5sum /lib/bpf/aw-bpf.o` 与 1.08.23 构建一致；`strings /lib/bpf/aw-bpf.o | grep captive_domain_map` 命中
- [ ] **A3** 挂载齐全：`tc filter show dev br-lan ingress`（pref1 xdns / pref2 aw-bpf）与 egress 同；`ip link show eth1` 有 `prog/xdp id` name `xdp_dns_monitor`；xdpi 模块已加载
- [ ] **A4** dns_snoop 附着：`logread | grep -E 'DNS consumer|dns_ringbuf_portal'` 出现 "Attached"

## B. DNS 抢答核心功能（依赖决策点 1）

- [ ] **B1** map 灌注：开启 portal auth 重启 wifidogx 后，`aw-captive-seed /sys/fs/bpf/tc/globals/captive_domain_map --dump`（或 bpftool）约 43 条、全部 `learned=0` IP=1.1.1.1；logread 出现 "Seeded N captive domains"
- [ ] **B2** 抢答生效：`dig @192.168.8.1 www.msftconnecttest.com` 返回 1.1.1.1，Query time <10ms，flags `qr rd ra`、ANSWER 1、ADDITIONAL 0
- [ ] **B3** 穿透未断：br-lan 抓包可见同 txid clone 到 dnsmasq、dnsmasq 发出真实应答（客户端取第一份，无重复请求风暴）
- [ ] **B4** 学习闭环：数秒后该域名 `learned=1` 真实 IP；再次 dig 直接返回真实 IP（Query time <10ms）
- [ ] **B5** 持续刷新：间隔查询后 map IP 跟随 CDN 轮换（dump 对比 IP 变化且 `learned=1`）
- [ ] **B6** 旧机制迁移：`/etc/aw-captive-domains-hosts` 不存在；`uci -q get dhcp.@dnsmasq[0].addnhosts` 无该条目；dnsmasq 正常解析

## C. 离线场景（依赖决策点 2）

- [ ] **C1** 离线抢答：`ip link set eth1 down` 后，`learned=0` 的 captive 域名 dig 仍 <10ms 返回 1.1.1.1
- [ ] **C2** 离线不劫持：非 map 域名（baidu.com）dig 正常超时，无假应答
- [ ] **C3** 联网自愈：eth1 恢复后 map 学到真实 IP，后续查询返回真实 IP
- [ ] **C4** 真机检测（可选）：断网时手机连 WiFi 仍能弹 captive 提示；恢复后提示消失

## D. 回归测试

- [ ] **D1** 普通域名：baidu.com 等正常解析，延迟无异常
- [ ] **D2** AAAA：map 内域名返回 NOERROR/0 answer（NODATA），~1ms
- [ ] **D3** 大小写 0x20：`dig @192.168.8.1 WwW.MsFtConnectTest.CoM` 命中抢答
- [ ] **D4** xdns 共存：`xdns-ctl list-domains` 全部 Active；github.com 解析经 5353；抢答不碰 xdns 流量
- [ ] **D5** xkcptun 隧道：经代理域名可正常上网
- [ ] **D6** 认证链路：ping/auth 心跳正常；portal auth 开启后 `set_wifidogx_auth_servers` nft 报错消失
- [ ] **D7** aw-bpf 计量：客户端认证后 `mac_map`/`ipv4_map` 出现条目（bpftool dump 非空）

## E. 稳定性

- [ ] **E1** 整机重启：服务自启动、map 重建、B2/B4 复测通过
- [ ] **E2** 日志健康：长跑 30 分钟 logread 无 ringbuf/verifier/学习新错误

## F. 防火墙 synflood 对 br-lan 豁免

- [ ] **F1** 配置存在：`uci get firewall.lan_syn_exempt.enabled` = 1；`/usr/share/firewall4/lan-syn-exempt.nft` 存在；前提 `uci get firewall.@defaults[0].syn_flood` = 1
- [ ] **F2** 规则位置：`nft list chain inet fw4 input` 中 `iifname "br-lan" tcp flags syn accept`（comment `exempt lan syn`）位于 syn_flood 限速跳转之前，且仅匹配 br-lan
- [ ] **F3** LAN 突发不限速：测试机对网关 200 次快速短连接（循环 `nc -z -w1 192.168.8.1 53`）全部成功，整体耗时应远低于被限 25/s 时的水平（参考：豁免后约 1440 conn/s）
- [ ] **F4** WAN 侧不受影响：规则无 WAN 匹配（F2 审查）；可选从 WAN 侧突发 SYN 验证仍被限速

## G. xkcptun + xdns-bpf 集成（oc 作为服务端）

- [ ] **G1** 链路预检：路由器 xkcp_client 运行中（remote 43.159.38.154:9089）；监听 5353/12345；oc `xkcp_server` 运行中（9089）；`xdns-ctl list-domains` 与 `/etc/xdns/proxy_domains.txt` 一致
- [ ] **G2** DNS 走隧道：dig github.com 正常解析；br-lan 抓包可见查询被 DNAT 到 :5353、应答反向 SNAT
- [ ] **G3** IP 学习：`xdns-ctl list-ips` 出现 github IP 及 TTL
- [ ] **G4** 出网证明（决策点 4）：`xdns-ctl add-domain ip.sb` 后 `curl http://ip.sb` 返回 **43.159.38.154**；测试完 `xdns-ctl del-domain ip.sb`
- [ ] **G5** TCP 会话：多次连接后 `xdns-ctl list-sessions` 有记录；无 RST；经隧道下载 ≥10MB 文件吞吐正常
- [ ] **G6** 域名表互斥：captive 域名不在 xdns 列表、xdns 域名不在 captive map

## H. xkcptun SSH 隧道访问 oc

- [ ] **H1** 修正目标（决策点 3）：`uci set xkcptun.ssh_tunnel.target_port='22' && uci commit xkcptun && /etc/init.d/xkcptun restart`；oc 侧 server 日志无拨号失败
- [ ] **H2** 隧道连通：测试机 `ssh -p 2222 ubuntu@192.168.8.1` 登录成功，`hostname`/`ip addr` 显示 oc（43.159.38.154）
- [ ] **H3** 隧道质量：会话保持 5 分钟不断；scp 传 10MB 文件吞吐正常（fast3 模式）

## 执行记录

### 2026-09-06 第 1 轮（固件 r33196+1，aw-bpf 1.08.23 / wifidogx 9.09.2938）

| 组 | 结果 | 备注 |
|---|---|---|
| A1–A4 | ✅ 全过 | 固件内置 aw-bpf.o md5 与 1.08.23 构建一致；/dev/null 为正常字符设备（旧固件 bug 未复现） |
| B1–B6 | ✅ 全过 | 41 条域名自动灌注；抢答 0ms/1.1.1.1；clone 穿透+dnsmasq 真实应答；学习 learned=1；hosts 文件与 addnhosts 清理干净 |
| C1–C3 | ✅ 全过 | 离线抢答正常；非 map 域名 REFUSED 无劫持；恢复后一跳完成学习。C4 真机检测待手机人工验证 |
| D1–D7 | ✅ 全过 | 观察：trusted MAC 自动同步有 1 次"Update trusted mac … del failed"日志（ee:9b:… 为认证服务器下发条目），机制经手动 `aw-bpfctl mac add` 验证正常 |
| E1 | ✅ | 重启后 /dev/null 健康、41 条重灌、抢答→学习闭环复现 |
| E2 | ✅ | 长跑日志无真实错误（仅有旧实例 nft auth_servers 遗留） |
| F1–F4 | ✅ 全过 | 200 连接/0.86s（≈233 conn/s）不受 25/s 限速；规则仅匹配 br-lan。瑕疵：accept 规则在 nft input 链重复渲染两次（uci 仅一条 include），功能无害待查 |
| G1–G6 | ✅ / ⚠️ | G4 端到端证明：ip.sb→43.159.38.154(oc)，ifconfig.me→106.37.77.64(ISP)；G5 隧道下载 1.6MB 无中断；**G6 发现既有配置冲突**：xdns 列表含 gstatic.com/gstatic.cn，与 captive 表 www.gstatic.com/www.gstatic.cn 双属——离线时 Android 的 gstatic 检测将无应答，建议从 xdns 代理列表移除这两个基域名 |
| H1–H3 | ✅ 全过 | ssh_tunnel target_port 已修 27334→22；SSH 经隧道登录 oc 成功；scp 10MB md5 一致、耗时 20s（≈0.5MB/s，KCP fast3 可调优） |

环境已恢复：portal auth 关闭（disable_portal_auth=1）、ip.sb 已从 xdns 列表删除。
待办：① C4 手机人工验证；② xdns 列表移除 gstatic.com/gstatic.cn；③ chawrt synflood include 重复渲染排查；④ trusted MAC 自动同步失败日志排查。
