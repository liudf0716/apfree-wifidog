/* 
 * Copyright © 2015–2019 Andreas Misje
 *
 * This file is part of dhcpoptinj.
 *
 * dhcpoptinj is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.  
 *
 * dhcpoptinj is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with dhcpoptinj. If not, see <http://www.gnu.org/licenses/>.
 */

#include "dhcp.h"

const char *dhcp_msgTypeString(uint8_t msgType)
{
	switch (msgType)
	{
		case 1:
			return "DHCPDISCOVER";
		case 2:
			return "DHCPOFFER";
		case 3:
			return "DHCPREQUEST";
		case 4:
			return "DHCPDECLINE";
		case 5:
			return "DHCPACK";
		case 6:
			return "DHCPNAK";
		case 7:
			return "DHCPRELEASE";
		case 8:
			return "DHCPINFORM";
		default:
			return "??";
	}
}

const char *dhcp_optionString(uint8_t option)
{
	// From https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
	static const char * const names[] =
	{
		[0]   = "Pad",
		[1]   = "Subnet Mask",
		[2]   = "Time Offset",
		[3]   = "Router",
		[4]   = "Time Server",
		[5]   = "Name Server",
		[6]   = "Domain Server",
		[7]   = "Log Server",
		[8]   = "Quotes Server",
		[9]   = "LPR Server",
		[10]  = "Impress Server",
		[11]  = "RLP Server",
		[12]  = "Hostname",
		[13]  = "Boot File Size",
		[14]  = "Merit Dump File",
		[15]  = "Domain Name",
		[16]  = "Swap Server",
		[17]  = "Root Path",
		[18]  = "Extension File",
		[19]  = "Forward On/Off",
		[20]  = "SrcRte On/Off",
		[21]  = "Policy Filter",
		[22]  = "Max DG Assembly",
		[23]  = "Default IP TTL",
		[24]  = "MTU Timeout",
		[25]  = "MTU Plateau",
		[26]  = "MTU Interface",
		[27]  = "MTU Subnet",
		[28]  = "Broadcast Address",
		[29]  = "Mask Discovery",
		[30]  = "Mask Supplier",
		[31]  = "Router Discovery",
		[32]  = "Router Request",
		[33]  = "Static Route",
		[34]  = "Trailers",
		[35]  = "ARP Timeout",
		[36]  = "Ethernet",
		[37]  = "Default TCP TTL",
		[38]  = "Keepalive Time",
		[39]  = "Keepalive Data",
		[40]  = "NIS Domain",
		[41]  = "NIS Servers",
		[42]  = "NTP Servers",
		[43]  = "Vendor Specific",
		[44]  = "NETBIOS Name Srv",
		[45]  = "NETBIOS Dist Srv",
		[46]  = "NETBIOS Node Type",
		[47]  = "NETBIOS Scope",
		[48]  = "X Window Font",
		[49]  = "X Window Manager",
		[50]  = "Address Request",
		[51]  = "Address Time",
		[52]  = "Overload",
		[53]  = "DHCP Msg Type",
		[54]  = "DHCP Server Id",
		[55]  = "Parameter List",
		[56]  = "DHCP Message",
		[57]  = "DHCP Max Msg Size",
		[58]  = "Renewal Time",
		[59]  = "Rebinding Time",
		[60]  = "Class Id",
		[61]  = "Client Id",
		[62]  = "NetWare/IP Domain",
		[63]  = "NetWare/IP Option",
		[64]  = "NIS-Domain-Name",
		[65]  = "NIS-Server-Addr",
		[66]  = "Server-Name",
		[67]  = "Bootfile-Name",
		[68]  = "Home-Agent-Addrs",
		[69]  = "SMTP-Server",
		[70]  = "POP3-Server",
		[71]  = "NNTP-Server",
		[72]  = "WWW-Server",
		[73]  = "Finger-Server",
		[74]  = "IRC-Server",
		[75]  = "StreetTalk-Server",
		[76]  = "STDA-Server",
		[77]  = "User-Class",
		[78]  = "Directory Agent",
		[79]  = "Service Scope",
		[80]  = "Rapid Commit",
		[81]  = "Client FQDN",
		[82]  = "Relay Agent Information",
		[83]  = "iSNS",
		// 84 removed/unassigned
		[85]  = "NDS Servers",
		[86]  = "NDS Tree Name",
		[87]  = "NDS Context",
		[88]  = "BCMCS Controller Domain Name list",
		[89]  = "BCMCS Controller IPv4 address option",
		[90]  = "Authentication",
		[91]  = "client-last-transaction-time option",
		[92]  = "associated-ip option",
		[93]  = "Client System",
		[94]  = "Client NDI",
		[95]  = "LDAP",
		// 96 removed/unassigned
		[97]  = "UUID/GUID",
		[98]  = "User-Auth",
		[99]  = "GEOCONF_CIVIC",
		[100] = "PCode",
		[101] = "TCode",
		// 102–108 removed/unassigned
		[109] = "OPTION_DHCP4O6_S46_SADDR",
		// 110 removed/unassigned
		// 111 removed/unassigned
		[112] = "Netinfo Address",
		[113] = "Netinfo Tag",
		[114] = "URL",
		// 115 removed/unassigned
		[116] = "Auto-Config",
		[117] = "Name Service Search",
		[118] = "Subnet Selection Option",
		[119] = "Domain Search",
		[120] = "SIP Servers DHCP Option",
		[121] = "Classless Static Route Option",
		[122] = "CCC",
		[123] = "GeoConf Option",
		[124] = "V-I Vendor Class",
		[125] = "V-I Vendor-Specific Information",
		// 126 removed/unassigned
		// 127 removed/unassigned
		[128] = "PXE / Etherboot signature",
		[129] = "PXE / Kernel options / Call Server IP address",
		[130] = "PXE / Ethernet interface / Discrimination string",
		[131] = "PXE / Remote statistics server IP address",
		[132] = "PXE",
		[133] = "PXE",
		[134] = "PXE",
		[135] = "PXE / HTTP Proxy for phone-specific applications",
		[136] = "OPTION_PANA_AGENT",
		[137] = "OPTION_V4_LOST",
		[138] = "OPTION_CAPWAP_AC_V4",
		[139] = "OPTION-IPv4_Address-MoS",
		[140] = "OPTION-IPv4_FQDN-MoS",
		[141] = "SIP UA Configuration Service Domains",
		[142] = "OPTION-IPv4_Address-ANDSF",
		[143] = "OPTION_V4_SZTP_REDIRECT",
		[144] = "GeoLoc",
		[145] = "FORCERENEW_NONCE_CAPABLE",
		[146] = "RDNSS Selection",
		// 147–149 unassigned
		[150] = "TFTP server address / Etherboot / GRUB configuration path name",
		[151] = "status-code",
		[152] = "base-time",
		[153] = "start-time-of-state",
		[154] = "query-start-time",
		[155] = "query-end-time",
		[156] = "dhcp-state",
		[157] = "data-source",
		[158] = "OPTION_V4_PCP_SERVER",
		[159] = "OPTION_V4_PORTPARAMS",
		[160] = "DHCP Captive-Portal",
		[161] = "OPTION_MUD_URL_V4",
		// 162–174 unassigned
		[175] = "Etherboot",
		[176] = "IP Telephone",
		[177] = "Etherboot / PacketCable and CableHome",
		// 178–207 unassigned
		[208] = "PXELINUX Magic",
		[209] = "Configuration File",
		[210] = "Path Prefix",
		[211] = "Reboot Time",
		[212] = "OPTION_6RD",
		[213] = "OPTION_V4_ACCESS_DOMAIN",
		// 214–219 unassigned
		[220] = "Subnet Allocation Option",
		[221] = "Virtual Subnet Selection (VSS) Option",
		// 222–223 unassigned
		// 224–254 reserved
		[255] = "End",
	};

	return names[option] ? names[option] : "(unassigned/reserved)";
}
