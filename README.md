![ApFreeWiFiDog](https://github.com/liudf0716/apfree_wifidog/blob/master/logo.png)


[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![OpenWRT][11]][12]
[![KunTeng][13]][14]


[1]: https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic
[2]: https://github.com/liudf0716/apfree_wifidog/blob/master/COPYING
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/liudf0716/apfree_wifidog/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/liudf0716/apfree_wifidog/issues/new
[7]: https://img.shields.io/badge/release-3.11.1716-red.svg?style=plastic
[8]: https://github.com/liudf0716/apfree_wifidog/releases
[11]: https://img.shields.io/badge/Platform-%20OpenWRT%7C%20LEDE%20-brightgreen.svg?style=plastic
[12]: https://github.com/KunTengRom/kunteng-lede-17.01.4
[13]: https://img.shields.io/badge/KunTeng-Inside-blue.svg?style=plastic
[14]: http://rom.kunteng.org.cn
[15]: https://travis-ci.org/liudf0716/apfree_wifidog.svg?branch=master
[16]: https://travis-ci.org/liudf0716/apfree_wifidog

## Apfree WiFiDog: More efficient captive portal solution 

Apfree-WiFidog is an open source captive portal solution for wireless router which with embeddable Linux([LEDE](https://github.com/lede-project/source)/[Openwrt](https://github.com/openwrt/openwrt)). 


**[中文介绍](https://github.com/liudf0716/apfree_wifidog/blob/master/README_ZH.md)**

## Enhancement of apfree-wifidog 

In fact, the title should be why we choose apfree-wifidog, the reason was the following: 

>  Stable

apfree-wifidog was widely used in tens of thousands device, which were running in business scene. In order to improve its stable, we rewrite all iptables rule by api instead of fork call, which will easily cause deadlock in multithread-fork running environment

> Efficent

apfree-wifidog's http request-response is more quick, u can find statistic data in our test document

> More features

apfree-wifidog support https redirect, mac temporary-pass, ip,domain,pan-domain,white-mac,black-mac rule and etc. all these rules can be applied without restarting wifidog

> Compitable with wifidog authentication server

u don't need to modify your wifidog authentication server to adapt apfree-wifidog

----

## How to added apfree-wifidog into Openwrt package 

```
cd your_openwrt_sdk_dir
mkdir -p packages/net/apfree-wifidog
cp -r apfree_wifidog_openwrt/* packages/net/apfree-wifidog
make menuconfig
select apfree-wifidog
```

Please go to [package_apfree_wifidog]()https://github.com/KunTengRom/package_apfree_wifidog


--------

## Getting started

before starting apfree-wifidog, we must know how to configure it. apfree-wifidog use OpenWrt standard uci config system, all your apfree-wifidog configure information stored in `/etc/confg/wifidogx`, which will be parsed by  `/etc/init.d/wifidogx` to /tmp/wifidog.conf, apfree-wifidog's real configure file is `/tmp/wifidog.conf`

The default apfree-wifidog UCI configuration file like this:

```
config wifidog
    option  gateway_interface   'br-lan'
    option  auth_server_hostname    'wifidog.kunteng.org.cn'
    option  auth_server_port    443
    option  auth_server_path    '/wifidog/'
    option  check_interval      60
    option  client_timeout      5
    option  apple_cna           1
    option  thread_number       5
    option  wired_passed        0
    option  enable      0
```

> auth_server_hostname was apfree-wifidog auth server, it can be domain or ip; wifidog.kunteng.org.cn is a free auth server we provided, it was also [open source](https://github.com/wificoin-project/wwas) 

> apple_cna 1 apple captive detect deceive; 2 apple captive detect deceive to  disallow portal page appear

> wired_passed means whether LAN access devices need to auth or not, value 1 means no need to auth 

> enable means whether start apfree-wifidog when we executed `/etc/init.d/wifidogx start`, if u wanted to start apfree-wifidog, you must set enable to 1 before executing `/etc/init.d/wifidogx start`

### How to support https redirect

In order to support https redirect, apfree-wifidog need x509 pem cert and private key, u can generate youself like this:

```
PX5G_BIN="/usr/sbin/px5g"
OPENSSL_BIN="/usr/bin/openssl"
APFREE_CERT="/etc/apfree.crt"
APFREE_KEY="/etc/apfree.key"

generate_keys() {
    local days bits country state location commonname

    # Prefer px5g for certificate generation (existence evaluated last)
    local GENKEY_CMD=""
    local UNIQUEID=$(dd if=/dev/urandom bs=1 count=4 | hexdump -e '1/1 "%02x"')
    [ -x "$OPENSSL_BIN" ] && GENKEY_CMD="$OPENSSL_BIN req -x509 -sha256 -outform pem -nodes"
    [ -x "$PX5G_BIN" ] && GENKEY_CMD="$PX5G_BIN selfsigned -pem"
    [ -n "$GENKEY_CMD" ] && {
        $GENKEY_CMD \
            -days ${days:-730} -newkey rsa:${bits:-2048} -keyout "${APFREE_KEY}.new" -out "${APFREE_CERT}.new" \
            -subj /C="${country:-CN}"/ST="${state:-localhost}"/L="${location:-Unknown}"/O="${commonname:-ApFreeWiFidog}$UNIQUEID"/CN="${commonname:-ApFreeWiFidog}"
        sync
        mv "${APFREE_KEY}.new" "${APFREE_KEY}"
        mv "${APFREE_CERT}.new" "${APFREE_CERT}"
    }
}

```

or when u start `/etc/init.d/wifidogx start`, it will generate it automatically

### Attention! when apfree-wifidog redirect https request, u will receive certificate file is illegal warning, no need to panic, it's normal response

### apfree-wifidog Auth server open source project

apfree wifidog's official auth server is [wwas](https://github.com/wificoin-project/wificoin-wifidog-auth-server), which support wfc pay and weixin auth-mode and more auth-way will be support.

### demo video

http://www.iqiyi.com/w_19s09zie6t.html

**More auth server please read [AUTHSERVER.md](https://github.com/liudf0716/apfree_wifidog/blob/master/AUTHSERVER.md)**


### How To Contribute

Feel free to create issues or pull-requests if you have any problems.

**Please read [CONTRIBUTING.md](https://github.com/liudf0716/apfree_wifidog/blob/master/CONTRIBUTING.md) before pushing any changes.**


### contact us 

QQ group： [331230369](https://jq.qq.com/?_wv=1027&k=4ADDSev)
telegram:  [apfreewifidog](https://t.me/joinchat/H6i5BEY5fUyltcVah1WlNg)

## donate
### wfc: [weiKbu9DYg26gH2zucSHJHgH5KsuuZd3wW](https://wfc.xyblock.net/#/wifiPortal/donate)


---
