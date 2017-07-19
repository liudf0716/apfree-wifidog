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

## apfree wifidog的认证漫游功能可以开启和关闭
开始漫游

wifidog_roam enable

关闭漫游

wifidog_roam disable
