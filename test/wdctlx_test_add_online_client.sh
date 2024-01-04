#!/bin/bash

echo "#################"
echo " add roam client "
./wdctlx add_online_client "{\"ip\":\"192.168.1.211\",\"mac\":\"aa:bb:cc:dd:ee:ff\",\"name\":\"apfree\"}"
./wdctlx status