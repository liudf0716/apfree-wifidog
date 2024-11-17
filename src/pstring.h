
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _PSTRING_H_
#define _PSTRING_H_

#include <stddef.h>
#include <stdarg.h> /* For va_list */

/**
 * Structure to represent a pascal-like string.
 */
struct pstr {
    char *buf;   /**< @brief Buffer used to hold string. Pointer subject to change. */
    size_t len;  /**< @brief Current length of the string. */
    size_t size; /**< @brief Current maximum size of the buffer. */
};

typedef struct pstr pstr_t;  /**< @brief pstr_t is a type for a struct pstr. */

// liudf added 20160114
void pstr_free(pstr_t *); /**< @brief free pstr */
pstr_t *pstr_new(void);  /**< @brief Create a new pstr */
char * pstr_to_string(pstr_t *);  /**< @brief Convert pstr to a char *, freeing pstr. */
void pstr_cat(pstr_t *, const char *);  /**< @brief Appends a string to a pstr_t */
int pstr_append_sprintf(pstr_t *, const char *, ...);  /**< @brief Appends formatted string to a pstr_t. */

#endif /* defined(_PSTRING_H_) */
