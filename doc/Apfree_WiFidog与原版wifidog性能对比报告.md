Apfree_WiFidog与原版wifidog性能对比报告
============
# 测试目的 #
本次测试主要是通过软件发起大量的http请求来测试wifidog处理请求的能力，并且针对<br />
apfree_wifidog与原版wifidog的稳定性做一个对比。
# 测试设计 #
## 测试方法 ##
通过软件发起多个http请求来达到测试wifidog处理请求的能力，也就是其稳定性。查看后台<br />
监控wifidog异常，逐渐增加发送连接请求次数直到wifidog死掉或者重启。
## 测试环境 ##
将刷好的带wifidog认证的路由器接入Internet和测试机（手机或电脑），使用电脑<br />
连接路由器后台，已调试模式运行wifidog，以便随时监控wifidog，运行软件不断发起http请求。
## 测试条件 ##
wifidog启动中，并且没有进行过认证。
## 测试工具 ##
硬件：带apfree_wifidog的路由器一台、带原版wifidog的路由器一台、笔记本电脑一台<br />
软件：Weebench web压力测试工具
## 路由器配置 ##
system type：Qualcomm Atheros QCA9533 ver 2 rev 0  <br />
machine：KUNTENG KT9661<br />
cpu model：MIPS 24Kc V7.4
# 测试结果与分析 #
## 原版wifidog的测试结果与分析 ##
### 测试结果 ###
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
50 clients, running 600 sec.<br />

Speed=752 pages/min, 22274 bytes/sec.<br />
Requests: 6691 susceed, 830 failed.
### 测试结果分析 ###
50 clients, running 600 sec ：并发数50 运行600秒。<br />
每秒钟响应请求数=Speed=752 pages/min，每秒钟传输数据量=22274 bytes/sec。<br />
Requests: 6691 susceed, 830 failed：6691个请求成功，830个失败。
### 测试结果 ###
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1078 pages/min, 30788 bytes/sec.<br />
Requests: 9237 susceed, 1550 failed.
### 测试结果分析 ###
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1078 pages/min，每秒钟传输数据量=30788 bytes/sec。<br />
Requests: 9237 susceed, 1550 failed：9237个请求成功，1550个失败。
### 测试结果 ### 
！[image](https://github.com/heartache1987/images/raw/master/psb.png)
### 测试结果分析 ###
上图是并发数为100 运行6个小时后的结果，很明显测试wifidog已经死掉。
## Apfree_wifidog的测试结果与分析 ##
### 测试结果 ###
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
50 clients, running 600 sec.<br />

Speed=1462 pages/min, 162575 bytes/sec.<br />
Requests: 14618 susceed, 8 failed.
### 测试结果分析 ###
50 clients, running 600 sec ：并发数50 运行600秒。<br />
每秒钟响应请求数=Speed=1462 pages/min，每秒钟传输数据量=162575 bytes/sec。<br />
Requests: 14618 susceed, 8 failed：14618个请求成功，8个失败。
### 测试结果 ###
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1484 pages/min, 163750 bytes/sec.<br />
Requests: 14795 susceed, 48 failed.
### 测试结果分析 ###
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1484 pages/min，每秒钟传输数据量=163750 bytes/sec。<br />
Requests: 14795 susceed, 48 failed：14795个请求成功，48个失败。

# 测试总结 #
同样的环境下apfree_wifidog在50个并发数的情况下每秒响应的http请求为1462,<br />
14618个请求成功，8个失败,成功率99.95%。<br />
在100个并发数的情况下每秒响应的http请求为1484，<br />
14795个请求成功，48个失败，成功率99.68%。<br />
原版wifidog在50个并发数的情况下每秒响应的http请求为752，<br />
6691个请求成功，830个失败，成功率87.60%。<br />
在100个并发数的情况下每秒响应的http请求为1078，<br />
9237个请求成功，1550个失败，成功率83.22%。<br />
对比以上两组数据可以看出，apfree_wifidog处理http请求的能力远远大于原版wifidog。<br />
原版wifidog在并发数为100的情况下运行6小时后死掉，<br />
apfree_wifidog在同样的情况下运行三天后依然正常运行，<br />
由此可以看出apfree_wifidog的稳定性远远强于原版wifidog。

# 补充说明 #
以上测试数据是在无线干扰较大的情况下的测试数据，下面补充一条apfree_wifidog在有线情况下的数据：<br />
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1504 pages/min, 18475 bytes/sec.<br />
Requests: 15043 susceed, 0 failed.

100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1504 pages/min，每秒钟传输数据量=18475 bytes/sec。<br />
Requests: 15043 susceed, 0 failed：15043个请求成功，0个失败。成功率100%。
