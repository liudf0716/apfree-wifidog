apfree_wifidog性能测试报告
========
# 测试目的 #
本次主要针对wifidog在不同线程数以及不同队列数下处理http请求的能力，也就是其稳定性做一个对比测试，
# 测试场景设计 #
## 测试方法 ##
通过软件发起多个http请求来达到测试wifidog处理请求的能力，也就是其稳定性。查看后台<br />
监控wifidog异常，逐渐增加发送连接请求次数直到wifidog死掉或者重启。
## 测试场景 ##
将刷好的带wifidog认证的路由器接入Internet和测试机（手机或电脑），使用电脑<br />
连接路由器后台，以便随时监控wifidog，运行软件不断发起http请求。
### 场景一 ###
wifidog在标准模式下运行，设置http并发数100，运行10分钟
### 场景二 ###
wifidog运行线程池模式下，设置线程数为5，队列数20。设置http并发数100，运行10分钟
### 场景三 ###
wifidog运行线程池模式下，设置线程数为10，队列数20。设置http并发数100，运行10分钟
### 场景四 ###
wifidog运行线程池模式下，设置线程数为20，队列数20。设置http并发数100，运行10分钟
### 场景五 ###
wifidog运行线程池模式下，设置线程数为5，队列数10。设置http并发数100，运行10分钟
### 场景六 ###
wifidog运行线程池模式下，设置线程数为5，队列数30。设置http并发数100，运行10分钟
## 测试条件 ##
wifidog启动中，并且没有进行过认证。
## 测试工具 ##
硬件：带apfree_wifidog的路由器一台、笔记本电脑一台<br />
软件：Weebench web压力测试工具
## 路由器配置 ##
system type：Qualcomm Atheros QCA9533 ver 2 rev 0  <br />
machine：KUNTENG KT9661<br />
cpu model：MIPS 24Kc V7.4
# 测试结果与分析 #
## 场景一测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1440 pages/min, 154622 bytes/sec.<br />
Requests: 14239 susceed, 161 failed.

## 场景一结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1440 pages/min，每秒钟传输数据量=154622 bytes/sec。<br />
Requests: 14239 susceed, 161 failed：14239个请求成功，161个失败。成功率98.87%。
## 场景二测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1467 pages/min, 159190 bytes/sec.<br />
Requests: 14518 susceed, 161 failed.

## 场景二结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1467 pages/min，每秒钟传输数据量=159190 bytes/sec。<br />
Requests: 14518 susceed, 161 failed：14518个请求成功，161个失败。成功率98.89%。
## 场景三测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1437 pages/min, 153698 bytes/sec.<br />
Requests: 14159 susceed, 220 failed.

## 场景三结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1437 pages/min，每秒钟传输数据量=153698 bytes/sec。<br />
Requests: 14159 susceed, 220 failed：14159个请求成功，220个失败。成功率98.45%。
## 场景四测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1421 pages/min, 151708 bytes/sec.<br />
Requests: 13977 susceed, 235 failed.

## 场景四结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1421 pages/min，每秒钟传输数据量=151708 bytes/sec。<br />
Requests: 13977 susceed, 235 failed：13977个请求成功，235个失败。成功率98.32%。
## 场景五测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1410 pages/min, 130405 bytes/sec.<br />
Requests: 13897 susceed, 209 failed.

## 场景五结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1410 pages/min，每秒钟传输数据量=130405 bytes/sec。<br />
Requests: 13897 susceed, 209 failed：13897个请求成功，209个失败。成功率98.50%。
## 场景六测试结果 ##
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1442 pages/min, 153896 bytes/sec.<br />
Requests: 14207 susceed, 213 failed.

## 场景六结果分析 ##
100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1442 pages/min，每秒钟传输数据量=153896 bytes/sec。<br />
Requests: 14207 susceed, 213 failed：14207个请求成功，213个失败。成功率98.50%。
# 测试总结 #
**场景一**<br />
在100个并发数的情况下每秒响应的http请求为1440,<br />
14239个请求成功，161个失败。成功率98.87%。<br />
**场景二**<br />
在100个并发数的情况下每秒响应的http请求为1467,<br />
14518个请求成功，161个失败。成功率98.89%。<br />
**场景三**<br />
在100个并发数的情况下每秒响应的http请求为1437,<br />
14159个请求成功，220个失败。成功率98.45%。<br />
**场景四**<br />
在100个并发数的情况下每秒响应的http请求为1421,<br />
13977个请求成功，235个失败。成功率98.32%。<br />
**场景五**<br />
在100个并发数的情况下每秒响应的http请求为1410,<br />
13897个请求成功，209个失败。成功率98.50%。<br />
**场景六**<br />
在100个并发数的情况下每秒响应的http请求为1442,<br />
14207个请求成功，213个失败。成功率98.50%。<br />

综合以上数据，场景二下wifidog运行最好，但是整体差别不大。

# 补充说明 #
以上测试数据是在无线干扰较大的情况下的测试数据，下面补充一条在有线情况下的数据：<br />
Webbench - Simple Web Benchmark 1.5<br />
Copyright (c) Radim Kolar 1997-2004, GPL Open Source Software.<br />

Benchmarking: GET http://www.taobao.com/<br />
100 clients, running 600 sec.<br />

Speed=1504 pages/min, 18475 bytes/sec.<br />
Requests: 15043 susceed, 0 failed.

100 clients, running 600 sec ：并发数100 运行600秒。<br />
每秒钟响应请求数=Speed=1504 pages/min，每秒钟传输数据量=18475 bytes/sec。<br />
Requests: 15043 susceed, 0 failed：15043个请求成功，0个失败。成功率100%。

