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

/** @file pstring.h
    @brief Simple pascal string like strings
    @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#include <string.h>
#include <stdlib.h>

#include "safe.h"
#include "pstring.h"
#include "common.h"

static void _pstr_grow(pstr_t *);

/**
 * Create a new pascal-string like pstr struct and allocate initial buffer.
 * @param None.
 * @return A pointer to an opaque pstr_t string, think java StringBuilder
 */
pstr_t *
pstr_new(void)
{
    pstr_t *new;

    new = (pstr_t *)safe_malloc(sizeof(pstr_t));
    new->len = 0;
    new->size = MAX_BUF;
    new->buf = (char *)safe_malloc(MAX_BUF);

    return new;
}

/**
 * Convert the pstr_t pointer to a char * pointer, freeing the pstr_t in the
 * process. Note that the char * is the buffer of the pstr_t and must be freed
 * by the called.
 * @param pstr A pointer to a pstr_t struct.
 * @return A char * pointer
 */
char *
pstr_to_string(pstr_t *pstr)
{
    char *ret = pstr->buf;
    free(pstr);
    return ret;
}

/**
 * Grow a pstr_t's buffer by MAX_BUF chars in length.
 * Program terminates if realloc() fails.
 * @param pstr A pointer to a pstr_t struct.
 * @return void
 */
static void
_pstr_grow(pstr_t *pstr)
{
    pstr->buf = (char *)safe_realloc((void *)pstr->buf, (pstr->size + MAX_BUF));
    pstr->size += MAX_BUF;
}

/**
 * Append a char string to pstr_t, allocating more memory if needed.
 * If allocation is needed but fails, program terminates.
 * @param pstr A pointer to a pstr_t struct.
 * @param string A pointer to char string to append.
 */
void
pstr_cat(pstr_t *pstr, const char *string)
{
    size_t inlen = strlen(string);
    while ((pstr->len + inlen + 1) > pstr->size) {
        _pstr_grow(pstr);
    }
    strncat((pstr->buf + pstr->len), string, (pstr->size - pstr->len - 1));
    pstr->len += inlen;
}

/**
 * Append a printf-like formatted char string to a pstr_t string.
 * If allocation fails, program terminates.
 * @param pstr A pointer to a pstr_t struct.
 * @param fmt A char string specifying the format.
 * @param ... A va_arg list of argument, like for printf/sprintf.
 * @return int Number of bytes added.
 */
int
pstr_append_sprintf(pstr_t *pstr, const char *fmt, ...)
{
    va_list ap;
    char *str;
    int retval;

    va_start(ap, fmt);
    retval = safe_vasprintf(&str, fmt, ap);
    va_end(ap);

    if (retval >= 0) {
        pstr_cat(pstr, str);
        free(str);
    }

    return retval;
}
