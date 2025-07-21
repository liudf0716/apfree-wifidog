// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#ifndef _DNS_MONITOR_H_
#define _DNS_MONITOR_H_

/**
 * @brief DNS监控线程入口函数
 * 
 * 用于在gateway.c中创建DNS监控线程的入口函数。
 * 
 * @param arg 线程参数（当前未使用）
 * @return NULL
 */
void *thread_dns_monitor(void *arg);

/**
 * @brief 启动DNS监控线程
 * 
 * 启动一个独立的线程来监控DNS eBPF程序传递的DNS响应数据。
 * 该线程会持续监听ring buffer中的DNS事件并进行解析处理。
 * 
 * @return 1 成功启动, 0 启动失败
 */
int dns_monitor_start(void);

/**
 * @brief 停止DNS监控线程
 * 
 * 优雅地停止DNS监控线程，等待线程完成当前处理并退出。
 */
void dns_monitor_stop(void);

/**
 * @brief 检查DNS监控是否正在运行
 * 
 * @return 1 正在运行, 0 未运行
 */
int dns_monitor_is_running(void);

#endif /* _DNS_MONITOR_H_ */
