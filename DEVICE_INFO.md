# Device Info Configuration for WiFiDogX

## Overview

The WiFiDogX project now supports device information configuration through traditional configuration files. This feature enables the system to store and access device-specific information including device ID, MAC address, location coordinates, and location ID.

## Device Info Structure

The device info structure (`t_device_info`) contains the following fields:

- **ap_device_id**: Access Point Device ID (mandatory)
- **ap_mac_address**: Access Point MAC Address (mandatory) 
- **ap_longitude**: Access Point Longitude coordinate (optional)
- **ap_latitude**: Access Point Latitude coordinate (optional)
- **location_id**: Location ID (mandatory, max 14 bytes)

## Configuration Method

### Configuration File

Add a `DeviceInfo` section to your wifidog.conf file:

```
DeviceInfo {
    ApDeviceId 'AW17701125CC7D742A338'
    ApMacAddress '5C-C7-D7-42-A3-38'
    ApLongitude '116.395000'
    ApLatitude '039.911000'
    LocationId '11010110055155'
}
```

## API Functions

### Accessing Device Info

```c
#include "conf.h"

// Get device info structure
t_device_info *device_info = get_device_info();

if (device_info) {
    printf("Device ID: %s\n", device_info->ap_device_id);
    printf("MAC Address: %s\n", device_info->ap_mac_address);
    printf("Location ID: %s\n", device_info->location_id);
    
    // Optional fields (may be NULL)
    if (device_info->ap_longitude) {
        printf("Longitude: %s\n", device_info->ap_longitude);
    }
    if (device_info->ap_latitude) {
        printf("Latitude: %s\n", device_info->ap_latitude);
    }
}
```

## Integration Points

The device info is automatically integrated into:

1. **Event Daemon**: Session logging includes location_id and other device info
2. **WebSocket Communication**: Device identification in WebSocket messages
3. **MQTT Reporting**: Device info included in MQTT message payloads
4. **General Logging**: Available for inclusion in system logs

## Validation Rules

- **ap_device_id**: Required, non-empty string
- **ap_mac_address**: Required, non-empty string (format: XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX)
- **location_id**: Required, non-empty string, maximum 14 characters
- **ap_longitude**: Optional, numeric string (GPS coordinate)
- **ap_latitude**: Optional, numeric string (GPS coordinate)

## Error Handling

- If mandatory fields are missing, device info will not be loaded
- Debug messages are logged during configuration parsing
- Memory allocation failures are handled with appropriate cleanup

## Example Usage

### Configuration File Example

```
# /etc/wifidog.conf
DeviceInfo {
    ApDeviceId 'AW17701125CC7D742A338'
    ApMacAddress '5C-C7-D7-42-A3-38'
    ApLongitude '116.395000'
    ApLatitude '039.911000'
    LocationId '11010110055155'
}

GatewaySetting {
    GatewayID 'gw001'
    GatewayInterface 'br-lan'
    GatewayChannel 'main'
    GatewaySubnetV4 '192.168.1.0/24'
}
```

### Runtime Access Example

```c
// In your application code
t_device_info *info = get_device_info();
if (info && info->location_id) {
    // Use location_id for session tracking
    char session_id[64];
    snprintf(session_id, sizeof(session_id), "%s_%s_%ld", 
             info->location_id, normalized_mac, timestamp);
}
```

## Debugging

Enable debug logging to see device info loading:

```bash
# Set debug level to see device info parsing
wifidogx -d 7
```

Look for log messages like:
- "Adding device info: ap_device_id=..."
- "Device info parsed successfully"

## Build Requirements

The device info feature requires:
- Standard C library
- JSON-C library (for structured data handling)

Compilation automatically includes device info support when building the project.
