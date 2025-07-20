# DNS eBPF监控模块

这个模块提供了一个基于eBPF的DNS流量监控解决方案，能够捕获和分析DNS查询和响应数据包。

## 文件说明

- `dns-bpf.c` - eBPF内核程序，负责捕获DNS数据包并发送到用户空间
- `dns-bpf.h` - 头文件，定义了数据结构和常量
- `dns-monitor.c` - 用户空间程序，读取并显示DNS数据
- `Makefile` - 构建脚本，包含编译和部署规则

## 功能特性

### eBPF内核程序 (dns-bpf.c)
- 支持IPv4和IPv6 DNS流量监控
- 专门捕获DNS响应数据包（源端口53）
- 过滤DNS查询，只关注响应数据
- 提供详细的统计信息
- 使用ring buffer高效传输数据到用户空间
- 挂载在TC ingress点监控入站DNS响应

### 用户空间程序 (dns-monitor.c)
- 实时显示DNS数据包信息
- 解析DNS头部信息
- 显示源/目标IP和端口
- 提供十六进制数据转储
- 定期显示统计信息
- 优雅的信号处理

## 构建和安装

### 编译程序
```bash
# 进入ebpf目录
cd ebpf/

# 编译所有组件
make

# 或者只编译DNS相关组件
make dns-bpf.o dns-monitor
```

### 加载eBPF程序
```bash
# 加载DNS监控eBPF程序到网络接口
sudo make load-dns

# 注意：默认使用eth0接口，如需使用其他接口，请修改Makefile中的接口名
```

### 运行用户空间监控程序
```bash
# 启动DNS监控（需要root权限）
sudo ./dns-monitor
```

### 卸载eBPF程序
```bash
# 卸载DNS监控程序
sudo make unload-dns
```

## 使用示例

1. **启动监控**：
   ```bash
   sudo make load-dns
   sudo ./dns-monitor
   ```

2. **生成DNS流量进行测试**：
   ```bash
   # 在另一个终端中
   nslookup google.com
   dig @8.8.8.8 example.com
   ```

3. **观察输出**：
   ```
   === DNS Packet Captured ===
   Time: 2025-07-20 10:30:45
   IPv4: 192.168.1.100:45678 -> 8.8.8.8:53
   DNS Payload Length: 45 bytes
     DNS Header:
       ID: 0x1234
       Flags: 0x0100 (Query)
       Questions: 1, Answers: 0, Authority: 0, Additional: 0
     Raw DNS Data (first 64 bytes):
       12 34 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f
       67 6c 65 03 63 6f 6d 00 00 01 00 01
   ```

## 配置选项

### 网络接口配置
默认使用`eth0`接口，如需修改，请编辑`Makefile`中的接口名：
```makefile
# 将eth0替换为你的网络接口名
load-dns: dns-bpf.o
    sudo tc qdisc add dev YOUR_INTERFACE clsact 2>/dev/null || true
    sudo tc filter add dev YOUR_INTERFACE ingress bpf da obj dns-bpf.o sec tc/dns/ingress
```

### 只监控DNS响应的设计
该程序专门设计用于监控DNS响应数据：
- 只在**ingress**方向加载（监控入站流量）
- 过滤掉DNS查询，只处理响应（QR位=1）
- 检查源端口为53的UDP数据包（DNS服务器响应）

### 避免与其他eBPF程序冲突
DNS监控程序使用独特的section名称（`tc/dns/ingress`）以避免与项目中其他eBPF程序（如aw-bpf.c）发生冲突。

### Ring Buffer大小
可以在`dns-bpf.c`中修改ring buffer大小：
```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(pinning, 1);
    __uint(max_entries, 256 * 1024); // 修改这个值
} dns_ringbuf SEC(".maps");
```

### DNS负载大小限制
可以在`dns-bpf.h`中修改最大DNS负载大小：
```c
#define MAX_DNS_PAYLOAD_LEN 512  // 修改这个值
```

## 故障排除

### 常见问题

1. **权限不足**：
   - 确保以root权限运行加载和监控命令
   - 检查eBPF相关的内核配置

2. **网络接口不存在**：
   - 使用`ip link show`查看可用接口
   - 修改Makefile中的接口名

3. **Map文件不存在**：
   - 确保eBPF程序已正确加载
   - 检查`/sys/fs/bpf/`目录下的map文件

4. **编译错误**：
   - 确保安装了libbpf开发包
   - 检查clang和llvm版本

### 调试方法

1. **检查TC规则**：
   ```bash
   sudo tc filter show dev eth0
   sudo tc qdisc show dev eth0
   ```

2. **查看内核日志**：
   ```bash
   sudo dmesg | tail -20
   ```

3. **检查BPF maps**：
   ```bash
   ls -la /sys/fs/bpf/
   ```

4. **使用bpftool调试**：
   ```bash
   sudo bpftool prog list
   sudo bpftool map list
   ```

## 性能考虑

- eBPF程序设计为高性能，对网络延迟影响最小
- Ring buffer提供高效的用户空间数据传输
- 统计信息使用per-CPU数组以避免锁竞争
- 可以根据需要调整ring buffer大小以平衡内存使用和性能

## 安全注意事项

- 程序需要root权限运行
- 监控的DNS数据可能包含敏感信息
- 建议在生产环境中谨慎使用，确保符合隐私政策
- 可以通过修改eBPF程序来过滤特定类型的DNS数据

## 扩展功能

可以基于此框架扩展以下功能：
- DNS缓存分析
- 恶意域名检测
- DNS性能监控
- DNS流量统计和报告
- 与外部安全系统集成
