
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _COMMANDLINE_H_
#define _COMMANDLINE_H_

/*
 * Holds an argv that could be passed to exec*() if we restart ourselves
 */
extern char **restartargv;

/**
 * A flag to denote whether we were restarted via a parent wifidog, or started normally
 * 0 means normally, otherwise it will be populated by the PID of the parent
 */
extern pid_t restart_orig_pid;

/** @brief Parses the command line and set the config accordingly */
void parse_commandline(int, char **);

#endif                          /* _COMMANDLINE_H_ */
