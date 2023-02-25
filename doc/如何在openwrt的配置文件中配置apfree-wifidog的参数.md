在openwrt官方收录的apfree-wifidog package中，提供了一个符合openwrt uci 配置接口的配置文件，该文件如下所示：
```
config wifidog
	option gateway_interface 'br-lan'
	option auth_server_hostname 'auth server domain or ip'
	option auth_server_port 443
	option auth_server_path '/wifidog/'
	option check_interval 60
	option client_timeout 5
	option wired_passed 0
	option disabled 1
  ```
  上面的文件会在apfree-wifidog启动时，先被wifidog.init文件解析成apfree-wifidog能识别的配置文件；
  
  本文档会列出一些用户对apfree wifidog配置的常用的问题
  
  + 希望将apfree wifidog踢用户下线的时间间隔变长应该如何配置？


   apfree-wifidog会根据用户离线时长来决定是否将该用户自动踢下线，该部分功能与服务器端踢用户下线功能不一样：apfree-wifidog会定时检查用户在线的情况，当发现`check_interval * client_timeout` 秒后，
   用户依然没有上线，会将其踢下线，这样用户下次上线的时候会触发认证过程；而服务器端的踢用户下线是根据服务器端配置的时长 client_timeout，当发现用户从认证通过开始，经过client_timeout时长后，
   服务器通知apfree-wifidog将用户踢下线。因此，按照系统的默认配置，如果用户通过认证后，但经过持续5分钟（60 * 5）没有上线（既一直没有流量）后，该客户端会被apfree-wifidog踢下线，要延长该时间，
   可以通过增加`client_timeout`的值来实现。(改完记得重启apfree wifidog)
   
  > 
