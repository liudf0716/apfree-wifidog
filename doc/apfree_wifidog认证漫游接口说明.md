设备到路由器dhcp获取ip的时候，会触发脚本执行 wdctl add_online_client，该命令会到云端检查设备是否在别的路由器上通过认证，并支持漫游；
如果支持，会把设备自动加到认证列表里面（可通过iptables -t mangle -L -n查看），同时会把另外一台路由器上通过认证的该设备踢下线。

### 漫游请求接口 
GET http://authserv_hostname:port/authserv_path/roam?gw_id=gwid&mac=macaddress&channel_path=cpath

其中macaddress格式如下：

50:7b:9d:19:1b:12

### 返回结果
如果该设备不允许漫游，返回结果如下：
{"roam":"no"}
如果该设备允许漫游，返回结果如下：
{"roam":"yes","client":{"token":"token_value","first_login":"first_login_value"}}
其中token_value为设备第一次通过认证后，服务器端给其分配的token值， first_login为设备第一次通过认证后，其当时的时间戳

#### 注意，要记得通过auth接口将该设备从原来的路由器上替下线

## apfree wifidog的认证漫游功能在坤腾固件上可以开启和关闭
开始漫游

wifidog_roam enable

关闭漫游

wifidog_roam disable


wifidog_roam 脚本如下：

```
#!/bin/sh

[ -x /etc/init.d/wifidog ] || exit 1

[ $# != 1 ] && {
    echo "$0 enable|disable"
    exit
}

case $1 in
enable)
    uci set wifidog.@wifidog[0].roam=1
    uci commit wifidog
    ;;
disable)
    uci set wifidog.@wifidog[0].roam=0
    uci commit wifidog
    ;;
*)
    echo "no valid param $1"
    ;;
esac

```

## 配置dnsmasq，当dhcp server给用户分配ip后会执行相应脚本

需要添加dhcpscript项

配置如下：
```
config dnsmasq
    option domainneeded 1
    option boguspriv    1
    option filterwin2k  0  # enable for dial on demand
    option localise_queries 1
    option rebind_protection 1  # disable if upstream must serve RFC1918 addresses
    option rebind_localhost 1  # enable for RBL checking and similar services
    #list rebind_domain example.lan  # whitelist RFC1918 responses for domains
    option local    '/lan/'
    option domain   'lan'
    option expandhosts  1
    option nonegcache   0
    option authoritative    1
    option readethers   1
    option leasefile    '/tmp/dhcp.leases'
    option resolvfile   '/tmp/resolv.conf.auto'
    #list server        '/mycompany.local/1.2.3.4'
    #option nonwildcard 1
    #list interface     br-lan
    #list notinterface  lo
    #list bogusnxdomain     '64.94.110.11'
    option localservice 1  # disable to allow DNS requests from non-local subnets
    option dhcpscript   '/usr/sbin/roam_check'

```

其中roam_check脚本就是执行“wdctl add_online_client”的地方，如：

```
#!/bin/sh

WDCTL=/usr/bin/wdctl
UCI=/sbin/uci

action=$1

[ $action = "add" -o $action = "old" ] && {
    # For the equipments in landi MAC address block                   
    command -v landi-robot >/dev/null 2>&1 && landi-robot $2

    [ -x $WDCTL ] || exit

    
    roam=`$UCI get wifidog.@wifidog[0].roam 2> /dev/null`
    [ $roam = 1 ] && {
        $WDCTL add_online_client {\"mac\":\"$2\",\"ip\":\"$3\",\"name\":\"$4\"}
    }
    
}

```
