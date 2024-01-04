#!/bin/bash

echo "#################"
echo " add trusted domains "
./wdctlx add_trusted_domains captive.apple.com,www.baidu.com,www.qq.com,www.alibaba.com,aaa,bbb
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
sleep 1
echo "del trusted domains aaa"
./wdctlx del_trusted_domains aaa
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
sleep 1
echo "del trusted domains www.baidu.com,www.qq.com"
./wdctlx del_trusted_domains www.baidu.com,www.qq.com
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "clear trusted domains"
sleep 1
./wdctlx clear_trusted_domains
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "#################"