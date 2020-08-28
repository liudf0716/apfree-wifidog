1.1 上报数据接口定义
authserv_path/auth/?stage=counters_v2
如：
wifidog/auth/?stage=counters_v2
1.2 上报接口数据说明
采用post的方式上传数据，一次性将所有移动端的信息上报，提高上报效率，降低服务器端的压力
数据说明如下：
```
{"gw_id":"gw_id", clients:[
{"id":id,"ip":"ipaddress","mac":"macaddress","token":"tokenvalue","channel_path":channelPath,
"name":"clientname","incoming":incoming,"outgoing":outgoing,"first_login":first_login,
"is_online":is_online,"wired":is_wired_device}, ....]}
 ```
 2.1 返回数据说明
 ```
 {"gw_id":"gw_id","auth_op":[{"id":clt_id,"auth_code":authcode}, ....]}
 ```
