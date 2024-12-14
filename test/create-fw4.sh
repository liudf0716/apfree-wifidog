#!/bin/bash

# Delete the existing 'fw4' table in 'inet' family, if it exists
nft list table inet fw4 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    nft delete table inet fw4
fi

# Create the 'fw4' table in 'inet' family
nft add table inet fw4

# Create chains in 'inet fw4' table without using drop policy
nft add chain inet fw4 input '{ type filter hook input priority filter; }'
nft add chain inet fw4 forward '{ type filter hook forward priority filter; }'
nft add chain inet fw4 output '{ type filter hook output priority filter; }'
nft add chain inet fw4 prerouting '{ type filter hook prerouting priority filter; }'
nft add chain inet fw4 handle_reject
nft add chain inet fw4 syn_flood
nft add chain inet fw4 input_lan
nft add chain inet fw4 output_lan
nft add chain inet fw4 forward_lan
nft add chain inet fw4 helper_lan
nft add chain inet fw4 accept_from_lan
nft add chain inet fw4 accept_to_lan
nft add chain inet fw4 input_wan
nft add chain inet fw4 output_wan
nft add chain inet fw4 forward_wan
nft add chain inet fw4 accept_to_wan
nft add chain inet fw4 reject_from_wan
nft add chain inet fw4 reject_to_wan
nft add chain inet fw4 input_vpn
nft add chain inet fw4 output_vpn
nft add chain inet fw4 forward_vpn
nft add chain inet fw4 helper_vpn
nft add chain inet fw4 accept_from_vpn
nft add chain inet fw4 accept_to_vpn
nft add chain inet fw4 raw_prerouting '{ type filter hook prerouting priority raw; }'
nft add chain inet fw4 raw_output '{ type filter hook output priority raw; }'
nft add chain inet fw4 mangle_prerouting '{ type filter hook prerouting priority mangle; }'
nft add chain inet fw4 mangle_postrouting '{ type filter hook postrouting priority mangle; }'
nft add chain inet fw4 mangle_input '{ type filter hook input priority mangle; }'
nft add chain inet fw4 mangle_output '{ type route hook output priority mangle; }'
nft add chain inet fw4 mangle_forward '{ type filter hook forward priority mangle; }'

echo "fw4 table and chains created successfully!"
