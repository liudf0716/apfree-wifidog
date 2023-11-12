#ifndef _DCHP_CPI_H_
#define _DCHP_CPI_H_

#define MIN_BOOTP_SIZE  300
#define DHCPOPT_CPI     114

#pragma pack(2)
struct UDPHeader
{
	uint16_t sourcePort;
	uint16_t destPort;
	uint16_t length;
	uint16_t checksum;
};
#pragma pack()

enum MangleResult
{
    Mangle_OK = 0,
    Mangle_mallocFail,
    Mangle_optExists,
};

/* Somewhat arbitrary, feel free to change */
#define MAX_PACKET_SIZE 2048

void thread_dhcp_cpi(const void *arg);

#endif