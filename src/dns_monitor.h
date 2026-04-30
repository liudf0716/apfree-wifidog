// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#ifndef _DNS_MONITOR_H_
#define _DNS_MONITOR_H_

/**
 * @brief DNS监控线程入口函数（也是实际的长驻工作线程）
 *
 * 由 gateway.c 通过 create_detached_thread() 直接创建，是真正执行
 * DNS 监控工作循环的线程。tid_dns_monitor 即对应该线程。
 *
 * @param arg 线程参数（当前未使用）
 * @return NULL
 */
void *thread_dns_monitor(void *arg);

/**
 * @brief 查询DNS监控线程是否已在运行（保留API兼容性）
 *
 * DNS监控线程由 gateway.c 通过 thread_dns_monitor 创建和管理，
 * 该函数仅用于查询当前运行状态。
 *
 * @return 1 正在运行, 0 未运行
 */
int dns_monitor_start(void);

/**
 * @brief 请求停止DNS监控线程
 *
 * 仅设置停止标志；实际工作线程（thread_dns_monitor）检测到标志后
 * 会自然退出，无需额外同步。
 */
void dns_monitor_stop(void);

/**
 * @brief 检查DNS监控是否正在运行
 *
 * @return 1 正在运行, 0 未运行
 */
int dns_monitor_is_running(void);

#endif /* _DNS_MONITOR_H_ */
