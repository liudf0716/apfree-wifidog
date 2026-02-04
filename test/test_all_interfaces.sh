#!/bin/bash

echo "=== Testing All MQTT Interfaces ==="
echo ""

# Array to track test results
declare -a tests
declare -a results

test_count=0

# Function to test MQTT operation
test_mqtt_op() {
    local op_name="$1"
    local req_id="$2"
    local json_payload="$3"
    
    test_count=$((test_count + 1))
    tests+=("$test_count. $op_name")
    
    # Send request
    mosquitto_pub -h 127.0.0.1 -p 1883 -u apfree -P apfree \
        -t "wifidogx/AW110101100551/request/$req_id" \
        -m "$json_payload" 2>/dev/null
    
    sleep 0.5
}

# Test existing operations
test_mqtt_op "show_trusted (IP)" "2001" '{"op":"show_trusted","type":"ip"}'
test_mqtt_op "set_trusted (IP)" "2002" '{"op":"set_trusted","type":"ip","value":"10.0.0.1"}'
test_mqtt_op "get_status" "2003" '{"op":"get_status"}'

# Test NEW operations from document
test_mqtt_op "get_trusted_domains" "3001" '{"op":"get_trusted_domains"}'
test_mqtt_op "sync_trusted_wildcard_domains" "3002" '{"op":"sync_trusted_wildcard_domains","domains":[".example.com"]}'
test_mqtt_op "auth" "3003" '{"op":"auth","token":"test_token","client_mac":"aa:bb:cc:dd:ee:ff","client_ip":"192.168.1.100"}'
test_mqtt_op "kickoff" "3004" '{"op":"kickoff","client_mac":"aa:bb:cc:dd:ee:ff","client_ip":"192.168.1.100"}'
test_mqtt_op "tmp_pass" "3005" '{"op":"tmp_pass","client_mac":"aa:bb:cc:dd:ee:ff","timeout":300}'
test_mqtt_op "get_client_info" "3006" '{"op":"get_client_info","mac":"aa:bb:cc:dd:ee:ff"}'
test_mqtt_op "get_firmware_info" "3007" '{"op":"get_firmware_info"}'
test_mqtt_op "get_wifi_info" "3008" '{"op":"get_wifi_info"}'
test_mqtt_op "set_wifi_info" "3009" '{"op":"set_wifi_info","interfaces":[]}'
test_mqtt_op "get_sys_info" "3010" '{"op":"get_sys_info"}'
test_mqtt_op "update_device_info" "3011" '{"op":"update_device_info","device_name":"test"}'
test_mqtt_op "get_clients" "3012" '{"op":"get_clients"}'

echo "Sent $test_count test requests"
sleep 2

echo ""
echo "=== Checking Responses ==="
for i in "${!tests[@]}"; do
    echo "${tests[$i]}"
done

echo ""
echo "=== Verifying in Logs ==="
cd /home/ubuntu/apfree-wifidog/test
grep "Processing MQTT\|Found operation" wifidogx.log | tail -$((test_count * 2))
