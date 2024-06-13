/*
 * GNU GPL v3.0
 *
 *  This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 */
#include "common.h"

#include <sys/socket.h>
#include <stdint.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "debug.h"
#include "conf.h"
#include "ipv4.h"
#include "dhcp.h"
#include "options.h"
#include "dhcp_cpi.h"

#pragma pack(1)
struct Packet
{
    struct IPv4Header ipHeader;
    struct UDPHeader udpHeader;
    struct BootP bootp;
};
#pragma pack()

static int inspectPacket(struct nfq_q_handle *queue, struct nfgenmsg *pktInfo, 
		struct nfq_data *pktData, void *userData);
static bool packetIsComplete(const uint8_t *data, size_t size);
static bool packetIsDHCP(const uint8_t *data);
/* Inject DHCP options into DHCP packet */
static enum MangleResult manglePacket(const uint8_t *origData, size_t origDataSize,
		uint8_t **newData, size_t *newDataSize);
static enum MangleResult mangleOptions(const uint8_t *origData, size_t origDataSize,
		uint8_t *newData, size_t *newDataSize);

static int
inspectPacket(struct nfq_q_handle *queue, struct nfgenmsg *pktInfo,
              struct nfq_data *pktData, void *userData)
{
    (void)pktInfo;
    (void)userData;
    
    debug (LOG_DEBUG, "inspectPacket called");

    uint8_t *packet;
    ssize_t size = nfq_get_payload(pktData, &packet);
    if (size < 0)
    {
        debug(LOG_INFO, "Failed to retrieve packet from queue: %s\n",
              strerror(errno));
        return 1;
    }

    struct nfqnl_msg_packet_hdr *metaHeader = nfq_get_msg_packet_hdr(pktData);
    if (!packetIsComplete(packet, (size_t)size))
    {
        debug(LOG_INFO, "Dropping the packet because it is incomplete\n");
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
    }

    if (!packetIsDHCP(packet))
    {
        debug(LOG_DEBUG, "Ignoring non-DHCP packet\n");
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 0, NULL);
    }
    /* We do not have the logic needed to support fragmented packets: */
    if (ipv4_packetFragmented(&((const struct Packet *)packet)->ipHeader))
    {
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 0, NULL);
    }

    debug(LOG_INFO, "Mangling packet\n");

    uint8_t *mangledData = NULL;
    size_t mangledDataSize = 0;
    enum MangleResult result = manglePacket(packet, (size_t)size, &mangledData,
                                            &mangledDataSize);
    if (result == Mangle_mallocFail)
    {
        debug(LOG_ERR, "Failed to allocate memory for mangled packet\n");
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
    }
    else if (result == Mangle_optExists)
    {
        debug(LOG_INFO, "Dropping the packet because option already exists\n");
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
    }
    else if (result != Mangle_OK)
    {
        debug(LOG_ERR, "Internal error: unexpected return value from manglePacket(): %d\n",
              result);
        return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
    }

    int res = nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT,
                              mangledDataSize, mangledData);
    free(mangledData);
    return res;
}

static bool
packetIsComplete(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct IPv4Header))
        return false;

    const struct Packet *packet = (const struct Packet *)data;
    return packet->ipHeader.totalLen >= sizeof(*packet);
}

static bool
packetIsDHCP(const uint8_t *data)
{
    const struct Packet *packet = (const struct Packet *)data;

    if (packet->ipHeader.protocol != IPPROTO_UDP)
        return false;

    uint16_t destPort = ntohs(packet->udpHeader.destPort);
    if (!(destPort == 67 || destPort == 68))
        return false;
    if (packet->udpHeader.length < sizeof(struct UDPHeader) + sizeof(struct BootP))
        return false;

    const struct BootP *dhcp = &packet->bootp;
    if (ntohl(dhcp->cookie) != DHCP_MAGIC_COOKIE)
        return false;

    return true;
}

/*
    according to rfc 8910 : https://datatracker.ietf.org/doc/html/rfc8910
    The format of the IPv4 Captive-Portal DHCP option is shown below.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Code          | Len           | URI (variable length) ...     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                   ...URI continued...                         .
   |                              ...                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Figure 1: Captive-Portal DHCPv4 Option Format
*/
static enum MangleResult
manglePacket(const uint8_t *origData, size_t origDataSize,
             uint8_t **newData, size_t *newDataSize)
{
    s_config *config = config_get_config();
    const struct Packet *origPacket = (const struct Packet *)origData;
    size_t ipHdrSize = ipv4_headerLen(&origPacket->ipHeader);
    size_t udpHdrSize = sizeof(struct UDPHeader);
    size_t headersSize = ipHdrSize + udpHdrSize + sizeof(struct BootP);
    /* Allocate size for a new packet, slightly larger than needed in order to
     * avoid reallocation.: */
    *newDataSize = origDataSize + 2 + strlen(config->dhcp_cpi_uri)  + 1; /* room for padding */
    size_t newPayloadSize = *newDataSize - ipHdrSize - udpHdrSize;
    /* Ensure that the DHCP packet (the BOOTP header and payload) is at least
     * MIN_BOOTP_SIZE bytes long (as per the RFC 1542 requirement): */
    if (newPayloadSize < MIN_BOOTP_SIZE)
        *newDataSize += MIN_BOOTP_SIZE - newPayloadSize;

    *newData = malloc(*newDataSize);
    if (!*newData)
        return Mangle_mallocFail;

    /* Copy 'static' data (everything but the DHCP options) from original
     * packet: */
    memcpy(*newData, origPacket, headersSize);
    enum MangleResult result = mangleOptions(origData, origDataSize, *newData,
                                             newDataSize);
    if (result != Mangle_OK)
    {
        free(*newData);
        return result;
    }

    /* Recalculate actual size (and potential padding) after mangling options
     * (the initially calculated size is possibly slightly too large, since it
     * could not forsee how many bytes of DHCP options that was going to be
     * removed; however, the header size fields need to be correct): */
    newPayloadSize = *newDataSize - ipHdrSize - udpHdrSize;
    size_t padding = (2 - (newPayloadSize % 2)) % 2;
    if (newPayloadSize < MIN_BOOTP_SIZE)
        padding = MIN_BOOTP_SIZE - newPayloadSize;

    newPayloadSize += padding;
    *newDataSize = ipHdrSize + udpHdrSize + newPayloadSize;

    struct Packet *newPacket = (struct Packet *)*newData;
    struct IPv4Header *ipHeader = &newPacket->ipHeader;
    ipHeader->totalLen = htons(*newDataSize);
    ipHeader->checksum = 0;
    ipHeader->checksum = ipv4_checksum(ipHeader);

    struct UDPHeader *udpHeader = &newPacket->udpHeader;
    udpHeader->length = htons(udpHdrSize + newPayloadSize);
    udpHeader->checksum = 0;

    /* Pad to (at least) MIN_BOOTP_SIZE bytes: */
    for (size_t i = *newDataSize - padding; i < *newDataSize; ++i)
        (*newData)[i] = DHCPOPT_PAD;

    return Mangle_OK;
}

static enum MangleResult mangleOptions(const uint8_t *origData, size_t origDataSize,
                                       uint8_t *newData, size_t *newDataSize)
{
    /* Start with position of the first DHCP option: */
    size_t origOffset = offsetof(struct Packet, bootp) + sizeof(struct BootP);
    size_t newOffset = origOffset;
    s_config *config = config_get_config();

    while (origOffset < origDataSize)
    {
        const struct DHCPOption *option = (const struct DHCPOption *)(origData + origOffset);
        size_t optSize =
            option->code == DHCPOPT_PAD || option->code == DHCPOPT_END ? 1
                                                                       : sizeof(struct DHCPOption) + option->length;


        if (option->code == DHCPOPT_END)
            break;
        else {
            memcpy(newData + newOffset, option, optSize);
            newOffset += optSize;
        }
        origOffset += optSize;
    }

    /* Inject DHCP CPI options: */
    newData[newOffset++] = DHCPOPT_CPI;
    newData[newOffset++] = strlen(config->dhcp_cpi_uri);
    memcpy(newData + newOffset, config->dhcp_cpi_uri, strlen(config->dhcp_cpi_uri));
    newOffset += strlen(config->dhcp_cpi_uri);

    /* Finally insert the END option: */
    newData[newOffset++] = DHCPOPT_END;
    /* Update (reduce) packet size: */
    *newDataSize = newOffset;
    return Mangle_OK;
}

void thread_dhcp_cpi(const void *arg)
{
    struct nfq_handle *nfq = nfq_open();
    if (!nfq) {
        debug(LOG_ERR, "nfq_open() failed");
        return;
    }

    if (nfq_unbind_pf(nfq, AF_INET) < 0) {
        debug (LOG_ERR, " nfq_unbind_pf failed: %s", strerror(errno));
        nfq_close(nfq);
        return;
    }

    if (nfq_bind_pf(nfq, AF_INET) < 0) {
        debug (LOG_ERR, "nfq_bind_pf failed");
        nfq_close(nfq);
        return;
    }

    struct nfq_q_handle *qh = nfq_create_queue(nfq, 1024, &inspectPacket, NULL);
    if (!qh) {
        debug(LOG_ERR, "nfq_create_queue() failed");
        nfq_close(nfq);
        return;
    }
    
    debug(LOG_DEBUG, "start dhcp cpi thread");
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    int fd = nfq_fd(nfq);
    char buf[4096] __attribute__((aligned));
    while (1)
    {
        memset (buf, 0, sizeof(buf));
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv < 0)
        {
            debug(LOG_ERR, "recv() failed");
            continue;
        }
        nfq_handle_packet(nfq, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(nfq);
}