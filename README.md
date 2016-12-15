# About ApFree WiFiDog
ApFree WiFiDog 在完全兼容原版WiFiDog的基础上，在功能、性能和稳定性方面做了大量工作、改进及优化，目前在坤腾固件中广泛使用，使用ApFree WiFidog的在线路由器数量达到1万多台且还在继续增长。

由于ApFree WiFiDog完全兼容原有的WiFiDog协议，在将原有WiFiDog迁移到ApFree WiFiDog可以做到无缝切换

# ApFree WiFiDog的优势
1，稳定， 大规模在商业场景下应用，稳定性得到实际场景下的检验
2，持续更新维护，由坤腾固件研发团队维护，保障其可靠运营
3，性能优异 用time curl 命令测试， http的响应时间是0.05s左右, https的响应时间是0.2s左右，用户真实的体验是秒开

## HTTPS跳转演示视频

http://v.qq.com/x/page/f03507zyfvv.html

## 编译说明
1，将package中的apfree_wifidog目录拷贝到openwrt&lede的package目录

2，make menuconfig

  进入 ApFree
  
  选择 apfree_wifidog

注意事项：
##如果要支持https劫持跳转，需要修改openwrt&lede的libevent package，将其版本升级到release-2.1.7-rc版本

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


## 感谢如下开源项目提供的思路和帮助：

1， https://github.com/wifidog/wifidog-gateway  

2， https://github.com/ppelleti/https-example

3， https://github.com/sosopop/uvhttp

4, http://ezxml.sourceforge.net/

----

## powered by 坤腾畅联固件团队 （ www.kunteng.org ）
## 加qq群讨论： 331230369 

## 如果该项目对您有帮助，请点个赞，谢谢！
