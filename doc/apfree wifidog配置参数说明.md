apfree wifidog相比原版的wifidog，添加了许多功能，有些功能是以配置参数的方式来开启或者调节，

以下几个参数是根据实际运营场景得出的比较重要的参数，通过开启或者调节能解决用户的问题

###定时更新域名解析功能(UpdateDomainInterval)
开启该功能后，apfree wifidog会定时解析域名白名单，将解析到的新ip添加到白名单池中，值为0是不开启

###DNS查询域名超时设置(DNSTimeout)
apfree wifidog的域名白名单解析是采用非阻塞的方式实现，因此有超时设置，防止域名解析时间过长造成假死现象，该值默认设置为1s，用户可根据自己的情况来调整

###苹果弹窗本地优化开关(bypassAppleCNA)
开启改功能后，apfree wifidog会处理ios的whisper嗅探流程，保证ios的无线会正常连接到wifi上

###非浏览器HTTP请求过滤开关(jsFilter)
该功能开启后采用js的方式跳转页面，目的是屏蔽非浏览器的http请求，减轻认证服务器端的压力，但缺点会导致app认证可能会失效
关闭后采用正常的307跳转
