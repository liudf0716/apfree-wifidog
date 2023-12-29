1. 调试login页面

GET

http://localhost:8001/wifidog/login?gw_address=192.168.1.1&gw_port=1080&gw_id=ABCDEF112233&channel_path=apfree&ssid=apfree&ip=192.168.1.2&mac=223344556677&url=asdf


2. 调试ping接口

GET

http://localhost:8001/wifidog/ping?gw_id=ABCDEF112233&sys_uptime=1000&sys_memfree=10&sys_load=0.23&nf_conntrack_count=100&cpu_usage=32%&wifidog_uptime=100&online_clients=2&offline_clients=1&ssid=apfree&version=1.23&channel_path=apfree&wired_passed=0

3. 调试counterV2接口

POST

http://localhost:8001/wifidog/auth?stage=counters_v2

PARAM:
{
  "gw_id":"ABCDEF112233",
  "clients":[
    {"id":1,"ip":"192.168.1.10","mac":"aa:bb:cc:11:22:10","token":"asdfssdfeighge10","name":"test10","incomming":1000000,"outgoing":2000000,"first_login":1334588,"online_time":1000,"is_online":true,"wired":false},
   {"id":2,"ip":"192.168.1.11","mac":"aa:bb:cc:11:22:11","token":"asdfssdfeighge11","name":"test11","incomming":1000000,"outgoing":2000000,"first_login":1334588,"online_time":1000,"is_online":true,"wired":false},
   {"id":3,"ip":"192.168.1.12","mac":"aa:bb:cc:11:22:12","token":"asdfssdfeighge12","name":"test12","incomming":1000000,"outgoing":2000000,"first_login":1334588,"online_time":1000,"is_online":true,"wired":false},
   {"id":4,"ip":"192.168.1.13","mac":"aa:bb:cc:11:22:13","token":"asdfssdfeighge13","name":"test13","incomming":1000000,"outgoing":2000000,"first_login":1334588,"online_time":1000,"is_online":true,"wired":false},
   {"id":5,"ip":"192.168.1.14","mac":"aa:bb:cc:11:22:14","token":"asdfssdfeighge14","name":"test10","incomming":1000000,"outgoing":2000000,"first_login":1334588,"online_time":1000,"is_online":true,"wired":false}
  ]
}


6. 
