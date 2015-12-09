/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/**
  @file safe.c
  @brief Safe versions of stdlib/string functions that error out and exit if memory allocation fails
  @author Copyright (C) 2005 Mina Naguib <mina@ilesansfil.org>
 */

/* Enable vasprintf */
#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include "safe.h"
#include "debug.h"

/** @brief Clean up all the registered fds. */
static void cleanup_fds(void);

/** List of fd's to close on fork. */
typedef struct _fd_list {
    int fd;                 /**< @brief file descriptor */
    struct _fd_list *next;  /**< @brief linked list pointer */
} fd_list_t;

static fd_list_t *fd_list = NULL;

/** Clean up all the registered fds. Frees the list as it goes.
 * XXX This should only be run by CHILD processes.
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

/** Register an fd for auto-cleanup on fork()
 * @param fd A file descriptor.
 */
void
register_fd_cleanup_on_fork(const int fd)
{
    fd_list_t *entry = safe_malloc(sizeof(fd_list_t));

    entry->fd = fd;
    entry->next = fd_list;
    fd_list = entry;
}

/** Allocate zero-filled ram or die.
 * @param size Number of bytes to allocate
 * @return void * pointer to the zero'd bytes.
 */
void *
safe_malloc(size_t size)
{
    void *retval = NULL;
    retval = malloc(size);
    if (!retval) {
        debug(LOG_CRIT, "Failed to malloc %d bytes of memory: %s.  Bailing out", size, strerror(errno));
        exit(1);
    }
    memset(retval, 0, size);
    return (retval);
}

/** Re-allocates memory to a new larger allocation.
 * DOES NOT ZERO the added RAM
 * Original pointer is INVALID after call
 * Dies on allocation failures.
 * @param ptr A pointer to a current allocation from safe_malloc()
 * @param newsize What size it should now be in bytes
 * @return pointer to newly allocation ram
 */
void *
safe_realloc(void *ptr, size_t newsize)
{
    void *retval = NULL;
    retval = realloc(ptr, newsize);
    if (NULL == retval) {
        debug(LOG_CRIT, "Failed to realloc buffer to %d bytes of memory: %s. Bailing out", newsize, strerror(errno));
        exit(1);
    }
    return retval;
}

/** Duplicates a string or die if memory cannot be allocated
 * @param s String to duplicate
 * @return A string in a newly allocated chunk of heap.
 */
char *
safe_strdup(const char *s)
{
    char *retval = NULL;
    if (!s) {
        debug(LOG_CRIT, "safe_strdup called with NULL which would have crashed strdup. Bailing out");
        exit(1);
    }
    retval = strdup(s);
    if (!retval) {
        debug(LOG_CRIT, "Failed to duplicate a string: %s.  Bailing out", strerror(errno));
        exit(1);
    }
    return (retval);
}

/** Sprintf into a newly allocated buffer
 * Memory MUST be freed. Dies if memory cannot be allocated.
 * @param strp Pointer to a pointer that will be set to the newly allocated string
 * @param fmt Format string like sprintf
 * @param ... Variable number of arguments for format string
 * @return int Size of allocated string.
 */
int
safe_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int retval;

    va_start(ap, fmt);
    retval = safe_vasprintf(strp, fmt, ap);
    va_end(ap);

    return (retval);
}

/** Sprintf into a newly allocated buffer
 * Memory MUST be freed. Dies if memory cannot be allocted.
 * @param strp Pointer to a pointer that will be set to the newly allocated string
 * @param fmt Format string like sprintf
 * @param ap pre-digested va_list of arguments.
 * @return int Size of allocated string.
 */
int
safe_vasprintf(char **strp, const char *fmt, va_list ap)
{
    int retval;

    retval = vasprintf(strp, fmt, ap);

    if (retval == -1) {
        debug(LOG_CRIT, "Failed to vasprintf: %s.  Bailing out", strerror(errno));
        exit(1);
    }
    return (retval);
}

/** Fork and then close any registered fille descriptors.
 * If fork() fails, we die.
 * @return pid_t 0 for child, pid of child for parent
 */
pid_t
safe_fork(void)
{
    pid_t result;
    result = fork();

    if (result == -1) {
        debug(LOG_CRIT, "Failed to fork: %s.  Bailing out", strerror(errno));
        exit(1);
    } else if (result == 0) {
        /* I'm the child - do some cleanup */
        cleanup_fds();
    }

    return result;
}
