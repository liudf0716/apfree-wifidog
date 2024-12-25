#!/bin/bash

# Create the network namespace if it does not exist
ip netns list | grep -q aw
if [ $? -ne 0 ]; then
    echo "Creating network namespace 'aw'"
    sudo ip netns add aw
else
    echo "Network namespace 'aw' already exists"
fi

# Create dummy interface in aw namespace
echo "Creating dummy0 interface in 'aw' namespace"
ip netns exec aw ip link show dummy0 > /dev/null 2>&1; then
    echo "Interface 'dummy0' exists in 'aw' namespace"
    echo "Deleting 'dummy0' interface in 'aw' namespace"
    sudo ip netns exec aw ip link del dummy0
fi
sudo ip netns exec aw ip link add dummy0 type dummy
sudo ip netns exec aw ip addr add 192.168.1.1/24 dev dummy0
sudo ip netns exec aw ip link set dummy0 up

# Check if the interface tap0 exists
if ip link show tap0 > /dev/null 2>&1; then
    echo "Interface 'tap0' exists"

    # Move the interface tap0 to the aw namespace
    echo "Moving 'tap0' to the 'aw' namespace"
    sudo ip link set tap0 netns aw

    # Set the IP address of tap0 within the aw namespace
    echo "Setting IP address of 'tap0' to 100.100.100.2 in 'aw' namespace"
    sudo ip netns exec aw ip addr add 100.100.100.2/30 dev tap0

    # Bring up the tap0 interface within the aw namespace
    sudo ip netns exec aw ip link set tap0 up

    # Bring up the loopback interface within the aw namespace
    sudo ip netns exec aw ip link set lo up

    sudo ip netns exec aw ip route add 0.0.0.0/0 via 100.100.100.1

    echo "Configuration of 'tap0' in 'aw' namespace completed"
else
    echo "Interface 'tap0' does not exist"
fi

sudo ip route add 100.100.100.0/24 via 172.19.100.80