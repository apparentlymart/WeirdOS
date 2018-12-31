#ifndef DEBUGLOG_H
#define DEBUGLOG_H

#ifdef DEBUG
#include <stdio.h>
#define DEBUG_LOG(fmt, ...)                                                    \
    (fprintf(                                                                  \
        stderr,                                                                \
        "[DEBUG] %16s:%03d: " fmt "\n",                                        \
        __FILE__,                                                              \
        __LINE__,                                                              \
        __VA_ARGS__))
#else
#define DEBUG_LOG(fmt, ...) (0)
#endif

#endif
