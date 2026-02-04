#!/bin/bash
BROKER="127.0.0.1"
PORT="1883"
USERNAME="apfree"
PASSWORD="apfree"

# Test del_trusted
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/del_trusted" \
    -m '{"request_id": 2003, "type":"ip","ip":"192.168.1.101"}'

sleep 1

# Test clear_trusted
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/clear_trusted" \
    -m '{"request_id": 2004, "type":"ip"}'

sleep 1

# Test reboot
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/reboot" \
    -m '{"request_id": 2006}'

sleep 1

# Test reset
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/reset" \
    -m '{"request_id": 2007}'

sleep 1

# Test save_rule
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/save_rule" \
    -m '{"request_id": 2008}'

sleep 1

# Test set_auth_serv
mosquitto_pub -h "$BROKER" -p "$PORT" -u "$USERNAME" -P "$PASSWORD" \
    -t "device/AA00FF001122/operation/set_auth_serv" \
    -m '{"request_id": 2009, "server":"127.0.0.1:8001"}'

sleep 3

echo "Tests completed"
