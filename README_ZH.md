# About ApFree WiFiDog
ApFree WiFiDog 在完全兼容原版WiFiDog的基础上，在功能、性能和稳定性方面做了大量工作、改进及优化，目前在坤腾固件中广泛使用，使用ApFree WiFidog的在线路由器数量达到2万多台且还在继续增长。

由于ApFree WiFiDog完全兼容原有的WiFiDog协议，在将原有WiFiDog迁移到ApFree WiFiDog可以做到无缝切换

## ApFree WiFiDog的优势
### 1，稳定， 大规模在商业场景下应用，稳定性得到实际场景下的检验
### 2，持续更新维护，由坤腾固件研发测试团队维护，保障其功能持续迭代，紧跟用户场景的需求
### 3，性能优异 用time curl 命令测试， http的响应时间是0.05s左右, https的响应时间是0.2s左右，用户真实的体验是秒开

## HTTPS跳转演示视频

http://v.qq.com/x/page/f03507zyfvv.html

## 编译说明
1，将package中的apfree_wifidog目录拷贝到openwrt&lede的package目录

2，make menuconfig

  进入 ApFree
  
  选择 apfree_wifidog

### 注意事项：

如果要支持https劫持跳转，需要修改openwrt&lede的libevent package，将其版本升级到release-2.1.7-rc版本，最好采用apfree_wifidog项目中的package里面对应项目的替换原openwrt&lede的项目

## 功能描述

ApFree WiFiDog 完全兼容现有的 wifidog 协议，并支持如下功能：

###1. 动态添加、删除域名白名单，泛域名白名单
添加域名白名单

wdctl add_trusted_domains domain1,domain2,domain3....

显示域名白名单

wdctl show_trusted_domains

删除域名白名单

wdctl del_trusted_domains domain1,domain2,domain3...

清空域名白名单

wdctl clear_trusted_domains

对应的泛域名命令分别为

wdctl add_trusted_pdomains|del_trusted_pdomains|clear_trusted_pdomains

泛域名指如baidu.com, sina.com.cn这类的域名，如添加baidu.com泛域名后，所有的如www.baidu.com， img.baidu.com, b1.b2.baidu.com的域名都会在域名白名单中

###2. 动态添加、删除mac黑名单
添加mac黑名单

wdctl add_untrusted_mac mac1,mac2,mac3...   

显示mac黑名单

wdctl show_untrusted_mac

删除mac黑名单

wdctl del_untrusted_mac mac1,mac2,mac3...                  

清空mac黑名单

wdctl clear_untrusted_mac                              


###3. 动态添加、删除mac免认证名单
添加mac免认证名单

wdctl add_trusted_mac mac1,mac2,mac3...  

显示mac免认证名单

wdctl show_trusted_mac

删除mac免认证名单

wdctl del_trusted_mac mac1,mac2,mac3...                           

清空mac免认证名单

wdctl clear_trusted_mac                     
###4. 动态添加、删除ip白名单
添加ip白名单

wdctl add_trusted_iplist ip1,ip2,ip3...

查看ip白名单

ipset list WiFiDog_br-lan_TDomains或者通过wdctl show_trusted_domains

清空ip白名单

wdctl clear_trusted_iplist

###5. 支持无线漫游免认证(需要服务器端扩展)

设备到路由器dhcp获取ip的时候，会触发脚本执行 wdctl add_online_client，该命令会到云端检查设备是否在别的路由器上通过认证，并支持漫游；如果支持，会把设备自动加到认证列表里面（可通过iptables -t mangle -L -n查看），同时会把另外一台路由器上通过认证的该设备踢下线。

开始漫游

wifidog_roam   enable

关闭漫游

wifidog_roam   disable

###6. 支持ios弹窗（无需服务器端支持）

当iphone手机连接路由器，iphone会自动弹出portal页面；

###7. 支持线程池模式

###8. 支持https跳转

首先手机连接路由器，打开手机浏览器，输入带https的地址（例如：https://www.baidu.com/），
手机也可以弹出protal页面；

## 感谢如下开源项目提供的思路和帮助：

- https://github.com/wifidog/wifidog-gateway  

- https://github.com/ppelleti/https-example

- https://github.com/sosopop/uvhttp

- http://ezxml.sourceforge.net/

----

## powered by 坤腾畅联固件研发团队 （ www.kunteng.org ）
## 加qq群讨论： 331230369 

## 如果该项目对您有帮助，请随手star，谢谢！
