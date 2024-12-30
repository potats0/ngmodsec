#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_vs_modsec_runtime.h"

ngx_array_t *parse_get_args(ngx_str_t *queryString, ngx_pool_t *pool) {
    if (queryString == NULL || queryString->len == 0) {
        MLOGD("No queruy string found");
        return NULL;
    }
    MLOGD("parameters found Starting to process args");

    // 创建数组
    ngx_array_t *args = ngx_array_create(pool, 4, sizeof(ngx_http_arg_t));
    if (args == NULL) {
        return NULL;
    }

    u_char *start = queryString->data;
    u_char *end = queryString->data + queryString->len;
    u_char *p = start;
    u_char *key_start, *key_end, *value_start, *value_end;

    while (p < end) {
        key_start = p;
        while (p < end && *p != '=' && *p != '&') p++;
        key_end = p;

        if (p < end && *p == '=') {
            p++;
            value_start = p;
            while (p < end && *p != '&') p++;
            value_end = p;
        } else {
            value_start = value_end = p;
        }

        if (p < end && *p == '&') {
            p++;
        } else if (p == end) {
            p = end;
        }

        if (key_end > key_start) {
            ngx_http_arg_t *arg = ngx_array_push(args);
            if (arg == NULL) {
                return args; // 返回已解析的参数
            }

            arg->key.data = key_start;
            arg->key.len = key_end - key_start;
            arg->value.data = value_start;
            arg->value.len = value_end - value_start;

            // URL decode value
            arg->decoded.data = ngx_pnalloc(pool, arg->value.len);
            if (arg->decoded.data == NULL) {
                MLOGD("Failed to decode param: [%V]=[%V]", &arg->key, &arg->value);
                continue;
            }

            u_char *dst = arg->decoded.data;
            u_char *src = arg->value.data;
            ngx_memcpy(dst, src, arg->value.len);
            ngx_unescape_uri(&dst, &src, arg->value.len, 0);
            arg->decoded.len = dst - arg->decoded.data;

            MLOGD("GET param: %V = %V decoded: %V", &arg->key, &arg->value, &arg->decoded);
        }
    }

    MLOGD("Exiting to process args");
    return args;
}