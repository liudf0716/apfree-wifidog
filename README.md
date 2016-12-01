# ApFree WiFiDog
## 编译说明
1，将package中的apfree_wifidog目录拷贝到openwrt&lede的package目录
2，make menuconfig
  进入 ApFree
  选择 apfree_wifidog

注意事项：
如果要支持https劫持跳转，需要修改openwrt&lede的libevent package，将其版本升级到release-2.1.7-rc版本

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

如果决定该项目对您有帮助，烦请点个赞，给作者点鼓励和动力，谢谢！
