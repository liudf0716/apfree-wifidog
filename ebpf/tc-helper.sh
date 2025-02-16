#!/bin/sh
#
# tc-helper.sh
#
# 功能：
#   1. 限制指定 IP 的带宽
#   2. 显示指定网卡上 HTB qdisc 的统计信息
#   3. 清除指定网卡上的所有 tc 规则
#
# 用法示例：
#   ./tc-helper.sh limit 192.168.1.100 1000kbit
#   ./tc-helper.sh stats
#   ./tc-helper.sh clear

# 检查是否以 root 身份运行
if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root."
  exit 1
fi

# 默认网卡（可根据实际情况修改）
IFACE="br-lan"

usage() {
  cat <<EOF
Usage: $0 {limit|stats|clear} [options]

Commands:
  limit <ip> <rate>    Limit bandwidth for given IP to <rate> (e.g. 1000kbit)
  stats                Show tc statistics for the HTB qdisc on interface $IFACE
  clear                Clear all tc rules on interface $IFACE

Examples:
  $0 limit 192.168.1.100 1000kbit
  $0 stats
  $0 clear
EOF
  exit 1
}

# 限制指定 IP 的带宽
limit_ip() {
    if [ $# -ne 2 ]; then
        echo "Error: limit requires 2 parameters: <ip> <rate>"
        usage
    fi

    IP="$1"
    RATE="$2"

    echo ">>> Limiting IP $IP with bandwidth $RATE on interface $IFACE ..."

    # 添加根 qdisc（如果不存在）
    tc qdisc add dev "$IFACE" root handle 1: htb default 2 2>/dev/null

    # 添加父类（设置非常高的带宽）
    tc class add dev "$IFACE" parent 1: classid 1:1 htb rate 100gbit ceil 100gbit 2>/dev/null

    # 添加默认类（设置非常高的带宽）
    tc class add dev "$IFACE" parent 1:1 classid 1:2 htb rate 100gbit ceil 100gbit 2>/dev/null

    # 为该 IP 创建一个子类
    CLASSID="1:10"
    tc class replace dev "$IFACE" parent 1:1 classid "$CLASSID" htb rate "$RATE" ceil "$RATE"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add/replace class for IP $IP"
        exit 1
    fi

    # 添加过滤器，将目的 IP 的流量匹配到该 class
    tc filter replace dev "$IFACE" protocol ip parent 1: prio 1 u32 \
            match ip dst "$IP"/32 flowid "$CLASSID"
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add filter for IP $IP"
        exit 1
    fi

    echo ">>> Bandwidth for IP $IP limited to $RATE successfully."
}

# 显示 tc 统计信息
show_stats() {
  echo ">>> TC qdisc statistics on interface $IFACE:"
  tc -s qdisc show dev "$IFACE"
  echo ""
  echo ">>> TC class statistics on interface $IFACE:"
  tc -s class show dev "$IFACE"
}

# 清除所有 tc 规则
clear_tc() {
  echo ">>> Clearing all tc rules on interface $IFACE ..."
  tc qdisc del dev "$IFACE" root 2>/dev/null
  if [ $? -eq 0 ]; then
    echo ">>> Successfully cleared tc rules."
  else
    echo ">>> No tc rules were found or an error occurred."
  fi
}

# 主程序逻辑
if [ $# -lt 1 ]; then
  usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
  limit)
    limit_ip "$@"
    ;;
  stats)
    show_stats
    ;;
  clear)
    clear_tc
    ;;
  *)
    usage
    ;;
esac
