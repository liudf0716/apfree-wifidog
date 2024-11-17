
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _SAFE_H_
#define _SAFE_H_

#include <stdarg.h>             /* For va_list */
#include <sys/types.h>          /* For fork */
#include <unistd.h>             /* For fork */

/** Register an fd for auto-cleanup on fork() */
void register_fd_cleanup_on_fork(const int);

/** @brief Safe version of malloc */
void *safe_malloc(size_t);

/** @brief Safe version of realloc */
void *safe_realloc(void *, size_t);

/* @brief Safe version of strdup */
char *safe_strdup(const char *);

/* @brief Safe version of asprintf */
int safe_asprintf(char **, const char *, ...);

/* @brief Safe version of vasprintf */
int safe_vasprintf(char **, const char *, va_list);

/* @brief Safe version of fork */
pid_t safe_fork(void);

#endif                          /* _SAFE_H_ */
