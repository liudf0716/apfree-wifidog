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

/* $Id$ */
/** @file wdctl.h
    @brief WiFiDog monitoring client
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#ifndef _WDCTL_H_
#define _WDCTL_H_

#define DEFAULT_SOCK	"/tmp/wdctl.sock"

#define WDCTL_UNDEF		0
#define WDCTL_STATUS	1
#define WDCTL_STOP		2
#define WDCTL_KILL		3
#define WDCTL_RESTART	4
//>>>> liudf added 20151225
#define WDCTL_ADD_TRUSTED_DOMAINS		5
#define	WDCTL_REPARSE_TRUSTED_DOMAINS	6
#define	WDCTL_CLEAR_TRUSTED_DOMAINS		7
#define	WDCTL_SHOW_TRUSTED_DOMAINS		8
#define	WDCTL_ADD_DOMAIN_IP				9
#define	WDCTL_ADD_ROAM_MACLIST			10
#define	WDCTL_CLEAR_ROAM_MACLIST		11
#define	WDCTL_SHOW_ROAM_MACLIST			12
#define	WDCTL_ADD_UNTRUSTED_MACLIST		13
#define	WDCTL_CLEAR_UNTRUSTED_MACLIST	14
#define	WDCTL_SHOW_UNTRUSTED_MACLIST	15
#define	WDCTL_ADD_TRUSTED_MACLIST		16
#define	WDCTL_CLEAR_TRUSTED_MACLIST		17
#define	WDCTL_SHOW_TRUSTED_MACLIST		18
#define	WDCTL_USER_CFG_SAVE				19
#define	WDCTL_ADD_WILDCARD_DOMAIN		20
#define	WDCTL_ADD_TRUSTED_IPLIST		21
#define	WDCTL_ADD_ONLINE_CLIENT			22
#define WDCTL_DEL_TRUSTED_DOMAINS		23
#define	WDCTL_CLEAR_TRUSTED_IPLIST		24
#define	WDCTL_DEL_TRUSTED_IPLIST		25
#define WDCTL_DEL_TRUSTED_MACLIST		26
#define	WDCTL_DEL_UNTRUSTED_MACLIST		27
#define	WDCTL_ADD_TRUSTED_PAN_DOMAINS	28
#define	WDCTL_DEL_TRUSTED_PAN_DOMAINS	29
#define	WDCTL_CLEAR_TRUSTED_PAN_DOMAINS	30
#define	WDCTL_SHOW_TRUSTED_PAN_DOMAINS	31
#define	WDCTL_ADD_TRUSTED_LOCAL_MACLIST			32
#define	WDCTL_DEL_TRUSTED_LOCAL_MACLIST			33
#define	WDCTL_SHOW_TRUSTED_LOCAL_MACLIST		34
#define	WDCTL_CLEAR_TRUSTED_LOCAL_MACLIST		35
//<<<< liudf added end

typedef struct {
    char *socket;
    int command;
    char *param;
} wdctl_config;
#endif
