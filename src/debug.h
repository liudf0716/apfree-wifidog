
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#pragma once

/* Debug configuration structure */
typedef struct _debug_conf {
    int debuglevel;      /* Debug verbosity level (0-7) */
    int log_stderr;      /* Enable logging to stderr (0/1) */
    int log_syslog;      /* Enable logging to syslog (0/1) */
    int syslog_facility; /* Syslog facility number */
} debugconf_t;

/* Global debug configuration instance */
extern debugconf_t debugconf;

extern char *program_argv0;

/* Extract filename from full path */
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/**
 * Debug message output macro
 * @param level Debug level (0-7)
 * @param format Printf-style format string
 * 
 * Messages include filename, line number and are sent to configured outputs
 */
#define debug(level, format...) _debug(__FILENAME__, __LINE__, level, format)

/**
 * Internal debug function - do not call directly, use debug() macro instead
 * @param filename Source file name
 * @param line Line number
 * @param level Debug level
 * @param format Printf-style format string
 */
void _debug(const char *filename, int line, int level, const char *format, ...);

