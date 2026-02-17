#!/bin/bash

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== MQTT Interface Verification Report ==="
echo "Timestamp: $(date)"
echo

# Define all operations from documentation
operations=(
    "get_trusted_domains"
    "sync_trusted_domain"
    "del_trusted"
    "clear_trusted"
    "get_status"
    "reboot"
    "reset"
    "save_rule"
    "set_auth_serv"
    "get_trusted_domains"
    "sync_trusted_wildcard_domains"
    "auth"
    "kickoff"
    "tmp_pass"
    "get_client_info"
    "get_firmware_info"
    "get_wifi_info"
    "set_wifi_info"
    "get_sys_info"
    "update_device_info"
    "get_clients"
)

echo "Documented Operations: ${#operations[@]}"
echo "List: ${operations[@]}"
echo

# Check which operations are implemented by looking for "Found operation" in logs
echo "=== Implementation Status ==="
implemented_count=0
for op in "${operations[@]}"; do
    if grep -q "Found operation $op" /home/ubuntu/apfree-wifidog/test/wifidogx.log; then
        echo -e "${GREEN}✓${NC} $op - Found in logs"
        ((implemented_count++))
    else
        echo -e "${RED}✗${NC} $op - NOT found in logs"
    fi
done

echo
echo "Implementation Status: $implemented_count/${#operations[@]} operations tested"

# Check error handling
echo
echo "=== Error Handling Check ==="
error_count=$(grep -c "error\|Error\|ERROR" /home/ubuntu/apfree-wifidog/test/wifidogx.log)
echo "Error log entries: $error_count"

# Get response counts
echo
echo "=== Response Handling ==="
response_count=$(grep -c "send_mqtt_response\|Sending response" /home/ubuntu/apfree-wifidog/test/wifidogx.log)
echo "Total response operations: $response_count"

# Summary
echo
echo "=== Summary ==="
if [ $implemented_count -eq ${#operations[@]} ]; then
    echo -e "${GREEN}SUCCESS: All $implemented_count documented operations are implemented!${NC}"
else
    echo -e "${YELLOW}PARTIAL: $implemented_count/${#operations[@]} operations implemented${NC}"
fi

