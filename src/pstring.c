
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "pstring.h"

static void _pstr_grow(pstr_t *);

// liudf added 20160114
void
pstr_free(pstr_t *pstr)
{
	if(pstr != NULL) {
		free(pstr->buf);
		free(pstr);
	}
}

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
    char *str = NULL;
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
