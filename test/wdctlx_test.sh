#!/bin/bash

echo "#################"
echo " add trusted iplist "
./wdctlx add_trusted_iplist 192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "add trusted iplist 192.1168.1.6"
./wdctlx add_trusted_iplist 192.168.1.6
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "del trusted iplist 192.1168.1.6"
./wdctlx del_trusted_iplist 192.168.1.6
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "del trusted iplist 192.1168.1.3,192.1168.1.5"
./wdctlx del_trusted_iplist 192.168.1.3,192.168.1.5
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains
echo "clear trusted iplist"
./wdctlx clear_trusted_iplist
./wdctlx show_trusted_domains
nft list set inet fw4 set_wifidogx_trust_domains

echo "#################"
echo " add trusted mac "
./wdctlx add_trusted_mac aa:bb:cc:11:22:33,11:22:33:aa:bb:cc,22.22.22:aa:aa:aa,33:33:33:33:33:ab,44:44:44:44:44:44,55:55:55:55:55:55
./wdctlx show_trusted_mac
nft list set inet fw4 set_wifidogx_trust_clients
echo "del trusted mac 11:22:33:aa:bb:cc"
./wdctlx del_trusted_mac 11:22:33:aa:bb:cc
./wdctlx show_trusted_mac
nft list set inet fw4 set_wifidogx_trust_clients
echo "del trusted mac 55:55:55:55:55:55,33:33:33:33:33:ab"
./wdctlx del_trusted_mac 55:55:55:55:55:55,33:33:33:33:33:ab
./wdctlx show_trusted_mac
nft list set inet fw4 set_wifidogx_trust_clients
echo "clear trusted mac"
./wdctlx clear_trusted_mac
./wdctlx show_trusted_mac
nft list set inet fw4 set_wifidogx_trust_clients

