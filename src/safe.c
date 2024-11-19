
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE
#include "common.h"
#include "safe.h"
#include "debug.h"
#include "firewall.h"

/**
 * @file safe.c
 * @brief Safe memory and process management functions
 *
 * This module provides safe versions of common memory allocation and process
 * management functions. These functions perform error checking and handle
 * failures appropriately.
 */

/** @brief List of file descriptors to be closed on fork */
typedef struct _fd_list {
    int fd;                 /**< File descriptor to be closed */
    struct _fd_list *next;  /**< Pointer to next entry in list */
} fd_list_t;

/** @brief Head of the file descriptor cleanup list */
static fd_list_t *fd_list = NULL;

/** @brief Function pointer for custom cleanup handler */
static void (*cleanup_func)(void) = NULL;

/**
 * @brief Set a custom cleanup function to be called on exit
 * @param func Pointer to cleanup function
 * 
 * Allows setting a custom cleanup function that will be called
 * when the program exits. This can be used to perform additional
 * cleanup tasks beyond the standard file descriptor cleanup.
 */
void
safe_set_cleanup_func(void (*func)(void))
{
    cleanup_func = func;
}

/**
 * @brief Cleanup registered file descriptors
 * 
 * Closes all registered file descriptors and frees the list.
 * This should only be called by child processes after fork.
 */
static void
cleanup_fds(void)
{
    fd_list_t *entry;
    while (NULL != (entry = fd_list)) {
        close(entry->fd);
        fd_list = entry->next;
        free(entry);
    }
}

/**
 * @brief Register a file descriptor for cleanup on fork
 * @param fd File descriptor to register
 */
void
register_fd_cleanup_on_fork(const int fd)
{
    fd_list_t *entry = safe_malloc(sizeof(fd_list_t));
    entry->fd = fd;
    entry->next = fd_list;
    fd_list = entry;
}

/**
 * @brief Allocate and zero-initialize memory
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory
 * @note Exits program on allocation failure
 */
void *
safe_malloc(size_t size)
{
    void *retval = malloc(size);
    if (!retval) {
        if (cleanup_func) {
            cleanup_func();
        }
        debug(LOG_CRIT, "Failed to malloc %zu bytes: %s", size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(retval, 0, size);
    return retval;
}

/**
 * @brief Safely reallocate memory
 * @param ptr Pointer to existing allocation
 * @param newsize New size in bytes
 * @return Pointer to reallocated memory
 * @note Original pointer becomes invalid after call
 */
void *
safe_realloc(void *ptr, size_t newsize)
{
    void *retval = realloc(ptr, newsize);
    if (!retval) {
        if (cleanup_func) {
            cleanup_func();
        }
        debug(LOG_CRIT, "Failed to realloc to %zu bytes: %s", newsize, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return retval;
}

/**
 * @brief Safely duplicate a string
 * @param s String to duplicate
 * @return Pointer to new string
 * @note Exits program on NULL input or allocation failure
 */
char *
safe_strdup(const char *s)
{
    if (!s) {
        if (cleanup_func) {
            cleanup_func();
        }
        debug(LOG_CRIT, "safe_strdup called with NULL input");
        exit(EXIT_FAILURE);
    }
    char *retval = strdup(s);
    if (!retval) {
        if (cleanup_func) {
            cleanup_func();
        }
        debug(LOG_CRIT, "Failed to strdup: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return retval;
}

/**
 * @brief Format string into newly allocated buffer
 * @param strp Pointer to store result
 * @param fmt Printf-style format string
 * @return Number of bytes written
 */
int
safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int retval = safe_vasprintf(strp, fmt, ap);
    va_end(ap);
    return retval;
}

/**
 * @brief Format string with va_list into newly allocated buffer
 * @param strp Pointer to store result
 * @param fmt Printf-style format string
 * @param ap Variable argument list
 * @return Number of bytes written
 */
int
safe_vasprintf(char **strp, const char *fmt, va_list ap)
{
    int retval = vasprintf(strp, fmt, ap);
    if (retval == -1) {
        if (cleanup_func) {
            cleanup_func();
        }
        debug(LOG_CRIT, "Failed to vasprintf: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return retval;
}

/**
 * @brief Safely fork process and cleanup file descriptors in child
 * @return 0 in child, child's PID in parent
 * @note Exits program on fork failure
 */
pid_t
safe_fork(void)
{
    pid_t result = fork();
    if (result == -1) {
        debug(LOG_CRIT, "Failed to fork: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (result == 0) {
        cleanup_fds();
    }
    return result;
}
