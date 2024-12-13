#!/bin/bash

# Path to the wdctlx executable
WDCtlx="../build/src/wdctlx"

# Check if wdctlx exists and is executable
if [[ ! -x "$WDCtlx" ]]; then
    echo "Error: wdctlx not found or not executable at $WDCtlx"
    exit 1
fi

# Function to test wdctlx help command
test_help() {
    echo "Testing: wdctlx help"
    "$WDCtlx" help
    echo "--------------------------------------------------"
}

# Function to test wdctlx show commands
test_show() {
    echo "Testing: wdctlx show domain"
    "$WDCtlx" show domain
    echo "--------------------------------------------------"

    echo "Testing: wdctlx show wildcard_domain"
    "$WDCtlx" show wildcard_domain
    echo "--------------------------------------------------"

    echo "Testing: wdctlx show mac"
    "$WDCtlx" show mac
    echo "--------------------------------------------------"
}

# Function to test wdctlx add commands
test_add() {
    echo "Testing: wdctlx add domain example.com,example.org"
    "$WDCtlx" add domain "example.com,example.org"
    echo "--------------------------------------------------"

    echo "Testing: wdctlx add wildcard_domain .example.com,.example.org"
    "$WDCtlx" add wildcard_domain ".example.com,.example.org"
    echo "--------------------------------------------------"

    echo "Testing: wdctlx add mac 00:11:22:33:44:55,66:77:88:99:AA:BB"
    "$WDCtlx" add mac "00:11:22:33:44:55,66:77:88:99:AA:BB"
    echo "--------------------------------------------------"
}

# Function to test wdctlx del commands
test_del() {
    echo "Testing: wdctlx del mac 00:11:22:33:44:55"
    "$WDCtlx" del mac "00:11:22:33:44:55"
    echo "--------------------------------------------------"

    echo "Testing: wdctlx del mac 66:77:88:99:AA:BB"
    "$WDCtlx" del mac "66:77:88:99:AA:BB"
    echo "--------------------------------------------------"
}

# Function to test wdctlx clear commands
test_clear() {
    echo "Testing: wdctlx clear domain"
    "$WDCtlx" clear domain
    echo "--------------------------------------------------"

    echo "Testing: wdctlx clear wildcard_domain"
    "$WDCtlx" clear wildcard_domain
    echo "--------------------------------------------------"

    echo "Testing: wdctlx clear mac"
    "$WDCtlx" clear mac
    echo "--------------------------------------------------"
}

# Function to test wdctlx stop command
test_stop() {
    echo "Testing: wdctlx stop"
    "$WDCtlx" stop
    echo "--------------------------------------------------"
}

# Function to test wdctlx reset command
test_reset() {
    echo "Testing: wdctlx reset value"
    "$WDCtlx" reset value
    echo "--------------------------------------------------"
}

# Function to test wdctlx status commands
test_status() {
    echo "Testing: wdctlx status client"
    "$WDCtlx" status client
    echo "--------------------------------------------------"

    echo "Testing: wdctlx status auth"
    "$WDCtlx" status auth
    echo "--------------------------------------------------"

    echo "Testing: wdctlx status wifidogx"
    "$WDCtlx" status wifidogx
    echo "--------------------------------------------------"

    echo "Testing: wdctlx status"
    "$WDCtlx" status
    echo "--------------------------------------------------"
}

# Function to test wdctlx refresh command
test_refresh() {
    echo "Testing: wdctlx refresh"
    "$WDCtlx" refresh
    echo "--------------------------------------------------"
}

# Function to test wdctlx apfree commands
test_apfree() {
    echo "Testing: wdctlx apfree user_list"
    "$WDCtlx" apfree user_list
    echo "--------------------------------------------------"

    echo "Testing: wdctlx apfree user_info"
    "$WDCtlx" apfree user_info
    echo "--------------------------------------------------"

    echo "Testing: wdctlx apfree user_auth"
    "$WDCtlx" apfree user_auth
    echo "--------------------------------------------------"
}

# Execute all test functions
test_help
test_show
test_add
test_show
test_del
test_show
test_clear
test_show
test_apfree
test_reset
test_status
test_refresh
test_stop


echo "All tests completed."