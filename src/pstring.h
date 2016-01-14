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
