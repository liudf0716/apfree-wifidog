#!/bin/bash

echo "=== Testing MQTT Interface ==="

# Test 1: Show IP list
echo "Test 1: Show trusted IP list"
mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/request/1001" -m '{"op":"show_trusted","type":"ip"}'
sleep 1

# Test 2: Add IP
echo "Test 2: Add trusted IP"
mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/request/1002" -m '{"op":"set_trusted","type":"ip","value":"192.168.1.100"}'
sleep 1

# Test 3: Show domains
echo "Test 3: Show trusted domains"
mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/request/1003" -m '{"op":"show_trusted","type":"domain"}'
sleep 1

# Test 4: Add domain
echo "Test 4: Add trusted domain"
mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/request/1004" -m '{"op":"set_trusted","type":"domain","value":"example.com"}'
sleep 1

# Test 5: Save rules
echo "Test 5: Save rules"
mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/request/1005" -m '{"op":"save_rule"}'
sleep 1

echo "=== Checking responses ==="
timeout 2 mosquitto_sub -h 127.0.0.1 -p 1883 -u apfree -P apfree -t "wifidogx/AW110101100551/response/+" 2>/dev/null || true
