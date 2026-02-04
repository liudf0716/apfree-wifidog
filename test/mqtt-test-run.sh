#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/../build/src/wifidogx"
CONFIG="${SCRIPT_DIR}/wifidogx-mqtt-test.conf"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
check_mosquitto_running() {
    echo -e "${YELLOW}Checking mosquitto broker...${NC}"
    
    # Try port 1883 first
    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/1883" 2>/dev/null; then
        echo -e "${GREEN}✓ mosquitto running on port 1883${NC}"
        return 0
    fi
    
    # Try port 8883
    if timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/8883" 2>/dev/null; then
        echo -e "${GREEN}✓ mosquitto running on port 8883 (SSL)${NC}"
        return 0
    fi
    
    echo -e "${RED}✗ mosquitto not running!${NC}"
    echo "  Start mosquitto with Docker: docker run -d -p 1883:1883 eclipse-mosquitto"
    return 1
}

check_binary() {
    echo -e "${YELLOW}Checking wifidogx binary...${NC}"
    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}✗ Binary not found: $BINARY${NC}"
        echo "  Build with: cd ../; cmake -B build && make -C build"
        return 1
    fi
    echo -e "${GREEN}✓ Binary found: $BINARY${NC}"
}

check_config() {
    echo -e "${YELLOW}Checking configuration file...${NC}"
    if [ ! -f "$CONFIG" ]; then
        echo -e "${RED}✗ Config not found: $CONFIG${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ Config found: $CONFIG${NC}"
}

setup_library_paths() {
    echo -e "${YELLOW}Setting up library paths...${NC}"
    export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
    if command -v ldconfig &> /dev/null; then
        sudo ldconfig 2>/dev/null || true
    fi
    echo -e "${GREEN}✓ Library paths configured${NC}"
}

show_config_summary() {
    echo -e "${YELLOW}Configuration Summary:${NC}"
    echo "  MQTT Broker:     127.0.0.1:1883"
    echo "  Gateway Mode:    Bypass (no firewall rules)"
    echo "  Portal Auth:     Disabled"
    echo "  External Iface:  lo (loopback)"
    echo ""
}

# Main execution
echo -e "${GREEN}ApFree WiFiDog MQTT Test Environment${NC}"
echo "======================================"
echo ""

# Pre-flight checks
check_mosquitto_running || exit 1
check_binary || exit 1
check_config || exit 1
setup_library_paths
show_config_summary

# Start wifidogx
echo -e "${YELLOW}Starting wifidogx...${NC}"
echo "Command: sudo -E $BINARY -c $CONFIG -f"
echo ""

export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
sudo -E "$BINARY" -c "$CONFIG" -f
