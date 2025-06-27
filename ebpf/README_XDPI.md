# xDPI功能配置说明

## 功能概述
`ENABLE_XDPI_FEATURE` 控制是否启用xDPI协议检测和会话跟踪功能。

## 编译选项

### 使用CMake构建
```bash
# 启用xDPI功能 (默认)
cmake -DENABLE_XDPI_FEATURE=ON ..
make

# 禁用xDPI功能
cmake -DENABLE_XDPI_FEATURE=OFF ..
make
```

### 使用Makefile构建
```bash
# 启用xDPI功能 (默认)
make ENABLE_XDPI_FEATURE=1

# 禁用xDPI功能
make ENABLE_XDPI_FEATURE=0
```

## 功能影响

### 启用xDPI功能时 (ENABLE_XDPI_FEATURE=ON):
- 创建TCP/UDP连接跟踪映射表
- 支持协议检测和会话事件生成
- event_daemon可以接收会话数据
- 需要更多内存资源

### 禁用xDPI功能时 (ENABLE_XDPI_FEATURE=OFF):
- 仅支持基本流量统计
- 不进行协议检测
- 不生成会话事件
- 节省内存和CPU资源

## 检查编译结果
```bash
# 检查是否创建了xDPI相关的BPF映射
ls -la /sys/fs/bpf/tc/globals/tcp_conn_map
ls -la /sys/fs/bpf/tc/globals/udp_conn_map

# 如果启用了xDPI功能，这些文件应该存在
```

## OpenWrt集成
在OpenWrt的Makefile中可以这样配置：
```makefile
# 根据目标平台选择是否启用xDPI
ifeq ($(CONFIG_TARGET_DEVICE_PROFILE),small)
  CMAKE_OPTIONS += -DENABLE_XDPI_FEATURE=OFF
else
  CMAKE_OPTIONS += -DENABLE_XDPI_FEATURE=ON
endif
```
