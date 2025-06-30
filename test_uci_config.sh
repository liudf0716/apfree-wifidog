#!/bin/sh
# Test script to simulate UCI configuration

# Create a simple UCI configuration file for testing
cat > /tmp/test_wifidogx_uci.conf << 'EOF'
config wifidog 'wifidog'
    option ap_device_id 'AW17701125CC7D742A338'
    option ap_mac_address '5C-C7-D7-42-A3-38'
    option ap_longitude '116.395000'
    option ap_latitude '039.911000'
    option location_id '11010110055155'
EOF

echo "Created test UCI configuration at /tmp/test_wifidogx_uci.conf"
echo "Content:"
cat /tmp/test_wifidogx_uci.conf
