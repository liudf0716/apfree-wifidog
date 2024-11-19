
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _SAFE_H_
#define _SAFE_H_

#include <sys/types.h>
#include <stdarg.h>
#include <stddef.h>

/**
 * @brief Sets a cleanup function to be called during program termination
 * 
 * This function allows registering a cleanup callback function that will be
 * executed when the program exits. The cleanup function can be used to perform
 * any necessary cleanup operations like freeing resources.
 *
 * @param func Function pointer to the cleanup function that takes no arguments
 *             and returns void
 */
void safe_set_cleanup_func(void (*func)(void));

/**
 * @brief Register a file descriptor for automatic cleanup when forking
 * @param fd File descriptor to register
 */
void register_fd_cleanup_on_fork(const int fd);

/**
 * @brief Allocate memory with error checking
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory
 */
void *safe_malloc(size_t size);

/**
 * @brief Reallocate memory with error checking
 * @param ptr Pointer to memory block to reallocate
 * @param size New size in bytes
 * @return Pointer to reallocated memory
 */
void *safe_realloc(void *ptr, size_t size);

/**
 * @brief Duplicate a string with error checking
 * @param str String to duplicate
 * @return Pointer to new string
 */
char *safe_strdup(const char *str);

/**
 * @brief Format and write to allocated string with error checking
 * @param strp Pointer to string pointer
 * @param fmt Format string
 * @return Number of bytes written
 */
int safe_asprintf(char **strp, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/**
 * @brief Format and write to allocated string with va_list
 * @param strp Pointer to string pointer
 * @param fmt Format string
 * @param ap Variable argument list
 * @return Number of bytes written
 */
int safe_vasprintf(char **strp, const char *fmt, va_list ap);

/**
 * @brief Fork process with error checking
 * @return PID of child process or 0 in child
 */
pid_t safe_fork(void);

#endif                          /* _SAFE_H_ */
