
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "debug.h"

/**
 * Global debug configuration structure
 */
debugconf_t debugconf = {
    .debuglevel = LOG_INFO,     /* Default debug level */
    .log_stderr = 1,            /* Enable stderr logging by default */
    .log_syslog = 0,           /* Disable syslog by default */
    .syslog_facility = 0        /* Default syslog facility */
};

/**
 * Internal debug function that handles log message formatting and output
 * 
 * @param filename  Source file where debug is called
 * @param line      Line number where debug is called
 * @param level     Debug level of the message
 * @param format    Format string for the message
 * @param ...       Variable arguments for format string
 * 
 * @note Do not use directly, use the debug macro instead
 */
void
_debug(const char *filename, int line, int level, const char *format, ...)
{
    char timestamp[28] = {0};
    va_list vlist;
    time_t ts;
    sigset_t block_chld;

    /* Check if we should log this message based on debug level */
    if (debugconf.debuglevel < level)
        return;

    time(&ts);
    
    /* Block SIGCHLD during logging */
    sigemptyset(&block_chld);
    sigaddset(&block_chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block_chld, NULL);

    /* Format common log prefix */
    const char *time_str = ctime_r(&ts, timestamp);
    
    /* Log to stderr if it's a warning/error or if stderr logging is enabled */
    if (level <= LOG_WARNING || debugconf.log_stderr) {
        fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", 
                level, time_str, getpid(), filename, line);
        va_start(vlist, format);
        vfprintf(stderr, format, vlist);
        va_end(vlist);
        fputc('\n', stderr);
        fflush(stderr);
    }

    /* Log to syslog if enabled */
        if (debugconf.log_syslog) {
            const char *program_name = strrchr(program_argv0, '/');
            program_name = program_name ? program_name + 1 : program_argv0;
            openlog(program_name, LOG_PID, debugconf.syslog_facility);
            va_start(vlist, format);
            vsyslog(level, format, vlist);
            va_end(vlist);
            closelog();
        }
    
    /* Unblock SIGCHLD */
    sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
}
