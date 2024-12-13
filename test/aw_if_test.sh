#!/bin/bash

curl http://127.0.0.1:2060/cgi-bin/cgi-device?client_ip=192.168.1.1
curl -k https://127.0.0.1:8443/cgi-bin/cgi-device?client_ip=192.168.1.2