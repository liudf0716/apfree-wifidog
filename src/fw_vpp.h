// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _FW_VPP_H_
#define _FW_VPP_H_

int vpp_fw_counters_update();
int vpp_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);

#endif /* _FW_VPP_H_ */