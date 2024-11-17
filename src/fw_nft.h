
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _FW_NFT_H
#define _FW_NFT_H

#include <stdint.h>

int nft_fw_init(void);
int nft_fw_destroy(void);
int nft_fw_reload_client(void);
/**
 * @brief Enum to specify the type of firewall access.
 * 
 * The fw_access_t enum is used by the nft_fw_access function to determine
 * whether a client should be granted or denied access. It helps in managing
 * firewall rules based on the type of access required.
 */
int nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);
int nft_fw_access_host(fw_access_t type, const char *ip);
void nft_statistical_outgoing(char **outgoing, uint32_t *outgoing_len);
void nft_statistical_incoming(char **incoming, uint32_t *incoming_len);
void nft_add_gw();
void nft_del_gw();
void nft_reload_gw();
int nft_fw_counters_update();
int nft_fw_auth_unreachable(int tag);
int nft_fw_auth_reachable();
void nft_fw_clear_authservers();
void nft_fw_set_authservers();
void nft_fw_refresh_inner_domains_trusted();
void nft_fw_clear_inner_domains_trusted();
/**
 * @brief Set a MAC address as temporary.
 * 
 * @param mac The MAC address to set.
 * @param which An integer indicating the specific use or context for the temporary MAC address.
 */
void nft_fw_set_mac_temporary(const char *mac, int which);
void nft_fw_set_user_domains_trusted();
void nft_fw_clear_user_domains_trusted();
void nft_fw_refresh_user_domains_trusted();
void nft_fw_set_trusted_maclist();
void nft_fw_clear_trusted_maclist();

void nft_fw_set_inner_domains_trusted();

#endif