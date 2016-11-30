# ApFree WiFiDog

## 功能描述

ApFree WiFiDog 完全兼容现有的 wifidog 协议，并支持如下功能：

1. 动态添加、删除域名白名单，泛域名白名单

2. 动态添加、删除mac黑名单

3. 动态添加、删除mac免认证名单

4. 动态添加、删除ip白名单

5. 支持无线漫游免认证(需要服务器端扩展)

6. 支持ios弹窗（无需服务器端支持）

7. 支持线程池模式

8. 支持https跳转

----

## 已知bug：

非常频繁调用`wdctl`命令会导致会出现多`wifidog`进程的现象.

原因是: 多线程环境下调用fork导致，后面会想办法解决.


## 感谢如下开源项目提供的思路和帮助：

1， https://github.com/wifidog/wifidog-gateway  

2， https://github.com/ppelleti/https-example

3， https://github.com/sosopop/uvhttp

----

powered by www.kunteng.org

加qq群讨论： 331230369 
