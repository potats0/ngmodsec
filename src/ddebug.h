

// From:
// https://raw.githubusercontent.com/openresty/lua-nginx-module/master/src/ddebug.h

/*
 * Copyright (C) Yichun Zhang (agentzh)
 */

#ifndef _DDEBUG_H_INCLUDED_
#define _DDEBUG_H_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>

/*
 * #undef DDEBUG
 * #define DDEBUG 1
 */

/*
 * Setting MODSECURITY_SANITY_CHECKS will help you in the debug process. By
 * defining MODSECURITY_SANITY_CHECKS a set of functions will be executed in
 * order to make sure the well behavior of ModSecurity, letting you know (via
 * debug_logs) if something unexpected happens.
 *
 * If performance is not a concern, it is safe to keep it set.
 *
 */
#ifndef DDEBUG
#define DDEBUG 0
#endif

#if defined(DDEBUG) && (DDEBUG)

#if (NGX_HAVE_VARIADIC_MACROS)

#define dd(...)                                                                \
  fprintf(stderr, "waf rule *** %s: ", __func__);                              \
  fprintf(stderr, __VA_ARGS__);                                                \
  fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char *fmt, ...) {}

static void ddlog(const char *fmt, ...) {}

#endif

#else

#if (NGX_HAVE_VARIADIC_MACROS)

#define dd(...)

#else

#include <stdarg.h>

static void dd(const char *fmt, ...) {}

#endif

#endif

#if defined(DDEBUG) && (DDEBUG)

#define dd_check_read_event_handler(r)                                         \
  dd("r->read_event_handler = %s",                                             \
     r->read_event_handler == ngx_http_block_reading                           \
         ? "ngx_http_block_reading"                                            \
     : r->read_event_handler == ngx_http_test_reading                          \
         ? "ngx_http_test_reading"                                             \
     : r->read_event_handler == ngx_http_request_empty_handler                 \
         ? "ngx_http_request_empty_handler"                                    \
         : "UNKNOWN")

#define dd_check_write_event_handler(r)                                        \
  dd("r->write_event_handler = %s",                                            \
     r->write_event_handler == ngx_http_handler ? "ngx_http_handler"           \
     : r->write_event_handler == ngx_http_core_run_phases                      \
         ? "ngx_http_core_run_phases"                                          \
     : r->write_event_handler == ngx_http_request_empty_handler                \
         ? "ngx_http_request_empty_handler"                                    \
         : "UNKNOWN")

#else

#define dd_check_read_event_handler(r)
#define dd_check_write_event_handler(r)

#endif

#ifdef NGX_DEBUG
#define MLOG(ngx_cycle->log, level, fmt, ...)                                  \
  ngx_log_error(level, logger, 0, "[%s:%d] " fmt, __FILE__, __LINE__,          \
                ##__VA_ARGS__)
#else
#define MLOG(logger, level, fmt, ...)                                          \
  ngx_log_error(level, logger, 0, fmt, ##__VA_ARGS__)
#endif

#define MLOGE(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_ERR, fmt, ##__VA_ARGS__)
#define MLOGW(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_WARN, fmt, ##__VA_ARGS__)
#define MLOGN(fmt, ...) MLOG(ngx_cycle->log, NGX_LOG_NOTICE, fmt, ##__VA_ARGS__)

#ifdef NGX_DEBUG
#define LOGD(fmt, ...) MLOG(NGX_LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#define LOGD(lfmt, ...) ((void)0)
#endif

#endif /* _DDEBUG_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */