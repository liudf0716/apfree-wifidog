
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stddef.h>

#include "gateway.h"

char *program_argv0 = NULL;

int
main(int argc, char **argv)
{
    program_argv0 = argv[0];
    return gw_main(argc, argv);
}
