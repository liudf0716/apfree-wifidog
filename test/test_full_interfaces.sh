#!/bin/bash

# Test all 21 MQTT operations

echo "=== Testing All 21 MQTT Operations ==="
echo "Time: $(date)"

# MQTT broker details
BROKER="127.0.0.1"
PORT="1883"
USERNAME="apfree"
PASSWORD="apfree"

# Test counter
declare -i test_count=0

# Function to publish MQTT message
test_operation() {
    local op_name=$1
    local operation_type=$2
    local req_id=$3
    local payload=${4:-'{}'}
    
    ((test_count++))
    
    echo ""
    echo "Test $test_count: $op_name (req_id=$req_id)"
    
    # Publish the operation request
    mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
        -t "device/AA00FF001122/operation/$operation_type" \
        -m "{\"request_id\": $req_id, $payload}" 2>/dev/null
    
    # Small delay to allow processing
    sleep 0.5
}

# Clear the log before testing
truncate -s 0 /home/ubuntu/apfree-wifidog/test/wifidogx.log

echo "Starting fresh tests..."
sleep 1

# Test all 21 operations from documentation
test_operation "show_trusted"                      "show_trusted"                      2001 '"ip":"192.168.1.100"'
test_operation "set_trusted"                       "set_trusted"                       2002 '"ip":"192.168.1.101"'
test_operation "del_trusted"                       "del_trusted"                       2003 '"type":"ip","ip":"192.168.1.101"'
test_operation "clear_trusted"                     "clear_trusted"                     2004 '"type":"ip"'
test_operation "get_status"                        "get_status"                        2005 ''
test_operation "reboot"                            "reboot"                            2006 ''
test_operation "reset"                             "reset"                             2007 ''
test_operation "save_rule"                         "save_rule"                         2008 ''
test_operation "set_auth_serv"                     "set_auth_serv"                     2009 '"server":"127.0.0.1:8001"'
test_operation "get_trusted_domains"               "get_trusted_domains"               3001 ''
test_operation "sync_trusted_wildcard_domains"     "sync_trusted_wildcard_domains"     3002 '"domains":["example.com","test.com"]'
test_operation "auth"                              "auth"                              3003 '"client_mac":"AA:BB:CC:DD:EE:FF"'
test_operation "kickoff"                           "kickoff"                           3004 '"client_mac":"AA:BB:CC:DD:EE:FF"'
test_operation "tmp_pass"                          "tmp_pass"                          3005 '"client_mac":"AA:BB:CC:DD:EE:FF","duration":3600'
test_operation "get_client_info"                   "get_client_info"                   3006 '"client_mac":"AA:BB:CC:DD:EE:FF"'
test_operation "get_firmware_info"                 "get_firmware_info"                 3007 ''
test_operation "get_wifi_info"                     "get_wifi_info"                     3008 ''
test_operation "set_wifi_info"                     "set_wifi_info"                     3009 '"ssid":"MyWiFi"'
test_operation "get_sys_info"                      "get_sys_info"                      3010 ''
test_operation "update_device_info"                "update_device_info"                3011 '"name":"Gateway1"'
test_operation "get_clients"                       "get_clients"                       3012 ''

# Wait for all messages to be processed
sleep 3

echo ""
echo "=== All tests sent! ==="
echo ""
echo "Checking results..."
sleep 1

