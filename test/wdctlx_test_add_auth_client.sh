#!/bin/bash

echo "#################"
echo " add_auth_client "
./wdctlx add_auth_client "{\"ip\":\"192.168.1.212\",\"mac\":\"aa:bb:cc:dd:ee:1f\",\"name\":\"apfree2\"}"
./wdctlx status