#!/bin/bash
#
# MQTT Comprehensive Test Suite for apfree-wifidog
# Tests all MQTT interfaces according to design document
# /home/ubuntu/awas/apfree_wifidog_mqtt_远程控制_topic_设计.md

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
BROKER_HOST="localhost"
BROKER_PORT=1883
DEVICE_ID="AW110101100551"  # From wifidogx-mqtt-test.conf
REQUEST_TIMEOUT=4
MQTT_USERNAME="apfree"
MQTT_PASSWORD="apfree"

# Test statistics
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Request ID counter
REQ_ID_COUNTER=10000

# Function to get next request ID
next_req_id() {
    REQ_ID_COUNTER=$((REQ_ID_COUNTER + 1))
    echo $REQ_ID_COUNTER
}

# Color output helpers
print_header() {
    echo -e "${BLUE}=====================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=====================================${NC}"
}

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

print_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
}

# Function to send MQTT request and capture response
send_mqtt_request() {
    local topic=$1
    local payload=$2
    local timeout=${3:-$REQUEST_TIMEOUT}
    
    # Create a unique response file for this request to avoid collisions
    local response_file="/tmp/mqtt_response_$$_$RANDOM.tmp"
    rm -f "$response_file"
    
    # Subscribe to response topic and save responses
    mosquitto_sub -h "$BROKER_HOST" -p "$BROKER_PORT" \
                  -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" \
                  -t "wifidogx/v1/$DEVICE_ID/s2c/response" \
                  -C 1 \
                  > "$response_file" 2>/dev/null &
    
    local sub_pid=$!
    
    # Give subscriber time to connect (increased from 0.2 to 1 second)
    sleep 1.0
    
    # Publish request
    mosquitto_pub -h "$BROKER_HOST" -p "$BROKER_PORT" \
                  -u "$MQTT_USERNAME" -P "$MQTT_PASSWORD" \
                  -t "$topic" \
                  -m "$payload" 2>/dev/null
    
    # Wait for response or timeout
    sleep $timeout
    kill $sub_pid 2>/dev/null || true
    wait $sub_pid 2>/dev/null || true
    
    if [ -f "$response_file" ] && [ -s "$response_file" ]; then
        cat "$response_file"
        rm -f "$response_file"
        return 0
    else
        rm -f "$response_file"
        return 1
    fi
}

# Function to verify response has required fields
check_response() {
    local response=$1
    local expected_req_id=$2
    local expected_response_code=$3
    
    if [ -z "$response" ]; then
        return 1
    fi
    
    # Check if response contains req_id
    if ! echo "$response" | grep -q "\"req_id\":$expected_req_id"; then
        return 1
    fi
    
    # Check if response contains expected response code
    if ! echo "$response" | grep -q "\"response\":\"$expected_response_code\""; then
        return 1
    fi
    
    return 0
}

# ============================================
# Test Section 1: Server-to-Client (s2c) Tests
# ============================================

test_s2c_get_status() {
    print_test "s2c: get_status"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_status\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_status returned successful response"
    else
        print_fail "get_status did not return expected response. Got: $response"
    fi
}

test_s2c_get_sys_info() {
    print_test "s2c: get_sys_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_sys_info\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_sys_info returned successful response"
    else
        print_fail "get_sys_info did not return expected response. Got: $response"
    fi
}

test_s2c_get_firmware_info() {
    print_test "s2c: get_firmware_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_firmware_info\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_firmware_info returned successful response"
    else
        print_fail "get_firmware_info did not return expected response. Got: $response"
    fi
}

test_s2c_get_wifi_info() {
    print_test "s2c: get_wifi_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_wifi_info\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_wifi_info returned successful response"
    else
        print_fail "get_wifi_info did not return expected response. Got: $response"
    fi
}

test_s2c_get_trusted_domains() {
    print_test "s2c: get_trusted_domains"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_trusted_domains\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_trusted_domains returned successful response"
    else
        print_fail "get_trusted_domains did not return expected response. Got: $response"
    fi
}

test_s2c_set_trusted() {
    print_test "s2c: set_trusted (domain)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"set_trusted\",\"type\":\"domain\",\"values\":[\"test.example.com\"]}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "set_trusted returned successful response"
    else
        print_fail "set_trusted did not return expected response. Got: $response"
    fi
}

test_s2c_auth() {
    print_test "s2c: auth (client authentication)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"auth\",\"token\":\"test_token_123\",\"client_ip\":\"192.168.1.100\",\"client_mac\":\"aa:bb:cc:dd:ee:ff\",\"client_name\":\"TestDevice\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "auth returned successful response"
    else
        print_fail "auth did not return expected response. Got: $response"
    fi
}

test_s2c_kickoff() {
    print_test "s2c: kickoff (client disconnection)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"kickoff\",\"client_ip\":\"192.168.1.100\",\"client_mac\":\"aa:bb:cc:dd:ee:ff\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "kickoff returned successful response"
    else
        print_fail "kickoff did not return expected response. Got: $response"
    fi
}

test_s2c_tmp_pass() {
    print_test "s2c: tmp_pass (temporary access)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"tmp_pass\",\"client_mac\":\"aa:bb:cc:dd:ee:ff\",\"timeout\":300}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "tmp_pass returned successful response"
    else
        print_fail "tmp_pass did not return expected response. Got: $response"
    fi
}

test_s2c_get_client_info() {
    print_test "s2c: get_client_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_client_info\",\"mac\":\"aa:bb:cc:dd:ee:ff\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_client_info returned successful response"
    else
        print_fail "get_client_info did not return expected response. Got: $response"
    fi
}

test_s2c_get_clients() {
    print_test "s2c: get_clients (list all clients)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"get_clients\",\"filter\":\"online\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "get_clients returned successful response"
    else
        print_fail "get_clients did not return expected response. Got: $response"
    fi
}

test_s2c_set_auth_serv() {
    print_test "s2c: set_auth_serv (set auth server)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"set_auth_serv\",\"hostname\":\"auth.example.com\",\"http_port\":80,\"ssl_port\":443,\"use_ssl\":false}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "set_auth_serv returned successful response"
    else
        print_fail "set_auth_serv did not return expected response. Got: $response"
    fi
}

test_s2c_set_wifi_info() {
    print_test "s2c: set_wifi_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"set_wifi_info\",\"interfaces\":[{\"interface_name\":\"default_radio0\",\"ssid\":\"TestWiFi\",\"key\":\"testpass123\",\"encryption\":\"psk2\"}]}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "set_wifi_info returned successful response"
    else
        print_fail "set_wifi_info did not return expected response. Got: $response"
    fi
}

test_s2c_update_device_info() {
    print_test "s2c: update_device_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"update_device_info\",\"device_name\":\"TestGateway\",\"location\":\"Test Location\",\"description\":\"Test Description\"}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "update_device_info returned successful response"
    else
        print_fail "update_device_info did not return expected response. Got: $response"
    fi
}

test_s2c_reboot() {
    print_test "s2c: reboot (device reboot)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "reboot test skipped to prevent system restart"
}

test_s2c_sync_trusted_wildcard_domains() {
    print_test "s2c: sync_trusted_wildcard_domains"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"sync_trusted_wildcard_domains\",\"domains\":[\".example.com\",\".test.com\"]}"
    local topic="wifidogx/v1/$DEVICE_ID/s2c/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "sync_trusted_wildcard_domains returned successful response"
    else
        print_fail "sync_trusted_wildcard_domains did not return expected response. Got: $response"
    fi
}

# ============================================
# Test Section 2: Client-to-Server (c2s) Tests
# ============================================

test_c2s_heartbeat() {
    print_test "c2s: heartbeat (device status report)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    local req_id=$(next_req_id)
    local payload="{\"req_id\":$req_id,\"op\":\"heartbeat\",\"device_id\":\"$DEVICE_ID\",\"gateway\":[{\"gw_id\":\"AABBCCDDEEFF\",\"gw_channel\":\"channel1\",\"gw_address_v4\":\"192.168.1.1\",\"gw_address_v6\":\"fe80::1\",\"auth_mode\":1,\"gw_interface\":\"br-lan\"}]}"
    local topic="wifidogx/v1/$DEVICE_ID/c2s/request"
    
    local response=$(send_mqtt_request "$topic" "$payload")
    
    if check_response "$response" "$req_id" "200"; then
        print_pass "heartbeat returned successful response"
    else
        print_fail "heartbeat did not return expected response. Got: $response"
    fi
}

# ============================================
# Not Yet Implemented Tests (To Be Skipped)
# ============================================

test_s2c_firmware_upgrade() {
    print_test "s2c: firmware_upgrade (OTA upgrade)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "firmware_upgrade not yet implemented in design doc"
}

test_s2c_qos() {
    print_test "s2c: qos (QoS flow control)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "qos not yet implemented in design doc"
}

test_s2c_uci() {
    print_test "s2c: uci (UCI command)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "uci not yet implemented in design doc"
}

test_s2c_get_config() {
    print_test "s2c: get_config (get remote config)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "get_config not yet implemented in design doc"
}

test_s2c_apply_config() {
    print_test "s2c: apply_config (apply remote config)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "apply_config not yet implemented in design doc"
}

test_c2s_bootstrap() {
    print_test "c2s: bootstrap (device startup report)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "bootstrap not yet implemented in design doc"
}

test_c2s_wan_change() {
    print_test "c2s: wan_change (network change notification)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "wan_change not yet implemented in design doc"
}

test_c2s_alarm() {
    print_test "c2s: alarm (device alarm report)"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    print_skip "alarm not yet implemented in design doc"
}

# ============================================
# Main test execution
# ============================================

main() {
    print_header "MQTT Comprehensive Test Suite for apfree-wifidog"
    echo ""
    
    # Check if mosquitto_pub and mosquitto_sub are available
    if ! command -v mosquitto_pub &> /dev/null || ! command -v mosquitto_sub &> /dev/null; then
        echo -e "${RED}Error: mosquitto_pub and/or mosquitto_sub not found${NC}"
        echo "Install with: sudo apt-get install mosquitto-clients"
        exit 1
    fi
    
    # Check MQTT broker connectivity
    echo "Checking MQTT broker connectivity..."
    if ! timeout 2 bash -c "echo > /dev/tcp/$BROKER_HOST/$BROKER_PORT" 2>/dev/null; then
        echo -e "${RED}Error: Cannot connect to MQTT broker at $BROKER_HOST:$BROKER_PORT${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ MQTT broker is running${NC}"
    echo ""
    
    print_header "Server-to-Client (s2c) Interface Tests"
    test_s2c_get_status
    test_s2c_get_sys_info
    test_s2c_get_firmware_info
    test_s2c_get_wifi_info
    test_s2c_get_trusted_domains
    test_s2c_set_trusted
    test_s2c_auth
    test_s2c_kickoff
    test_s2c_tmp_pass
    test_s2c_get_client_info
    test_s2c_get_clients
    test_s2c_set_auth_serv
    test_s2c_set_wifi_info
    test_s2c_update_device_info
    test_s2c_reboot
    test_s2c_sync_trusted_wildcard_domains
    echo ""
    
    print_header "Client-to-Server (c2s) Interface Tests"
    test_c2s_heartbeat
    echo ""
    
    print_header "Not Yet Implemented Tests"
    test_s2c_firmware_upgrade
    test_s2c_qos
    test_s2c_uci
    test_s2c_get_config
    test_s2c_apply_config
    test_c2s_bootstrap
    test_c2s_wan_change
    test_c2s_alarm
    echo ""
    
    print_header "Test Results Summary"
    echo -e "Total Tests:     $TOTAL_TESTS"
    echo -e "${GREEN}Passed:          $PASSED_TESTS${NC}"
    echo -e "${RED}Failed:          $FAILED_TESTS${NC}"
    echo -e "${YELLOW}Skipped:         $SKIPPED_TESTS${NC}"
    echo ""
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}✓ All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some tests failed!${NC}"
        return 1
    fi
}

main "$@"
