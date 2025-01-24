
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _FW_NFT_H
#define _FW_NFT_H

#include <stdint.h>

/**
 * @brief nftables operations
 */
int nft_fw_init(void);
int nft_fw_destroy(void);

/**
 * @brief nftables operations
 */
int nft_fw_counters_update();
int nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);
int nft_fw_access_host(fw_access_t type, const char *ip);
int nft_fw_reload_client(void);
int nft_fw_reload_trusted_maclist(void);
void nft_reload_gw();


/**
 * @brief auth server operations
 */
int nft_fw_auth_unreachable(int tag);
int nft_fw_auth_reachable();
void nft_fw_clear_authservers();
void nft_fw_set_authservers();

/**
 * @brief user domains trusted operations
 */
void nft_fw_set_user_domains_trusted();
void nft_fw_clear_user_domains_trusted();
void nft_fw_refresh_user_domains_trusted();

/**
 * @brief inner domains trusted operations
 */
void nft_fw_set_inner_domains_trusted();
void nft_fw_refresh_inner_domains_trusted();
void nft_fw_clear_inner_domains_trusted();

/**
 * @brief trusted temporary mac operations
 */
void nft_fw_set_mac_temporary(const char *mac, int which);

/**
 * @brief trusted mac operations
 */
void nft_fw_set_trusted_maclist();
void nft_fw_clear_trusted_maclist();
void nft_fw_refresh_trusted_maclist();
void nft_fw_add_trusted_mac(const char *mac, int timeout);
void nft_fw_del_trusted_mac(const char *mac);
void nft_fw_update_trusted_mac(const char *mac, int timeout);

/**
 * @brief anti nat permit operations
 */
void nft_fw_add_anti_nat_permit(const char *mac);
void nft_fw_del_anti_nat_permit(const char *mac);
void nft_fw_set_anti_nat_permit();

void nft_fw_conntrack_flush();

#endif