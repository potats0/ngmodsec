#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_vs_modsec_runtime.h"

static const unsigned char hex_table[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00-0x0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10-0x1F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x20-0x2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30-0x3F */
    0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x40-0x4F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x50-0x5F */
    0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x60-0x6F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x70-0x7F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x80-0x8F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x90-0x9F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xA0-0xAF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xB0-0xBF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xC0-0xCF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xD0-0xDF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xE0-0xEF */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  /* 0xF0-0xFF */
};

/* 判断是否包含 URL 编码 */
ngx_flag_t has_url_encoding(u_char *data, size_t len) {
        if (data == NULL || len == 0) {
                return 0;
        }

        for (size_t i = 0; i < len; i++) {
                if (data[i] == '%') {
                        // 检查是否有合法的两位十六进制字符
                        if (i + 2 < len && hex_table[data[i + 1]] &&
                            hex_table[data[i + 2]]) {
                                return 1; // 存在 URL 编码
                        }
                }
        }
        return 0; // 不存在 URL 编码
}

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
                                MLOGD("Failed to decode param: [%V]=[%V]",
                                      &arg->key, &arg->value);
                                continue;
                        }

                        u_char *dst = arg->decoded.data;
                        u_char *src = arg->value.data;

                        if (has_url_encoding(src, arg->value.len)) {
                                // 存在 URL 编码，需要解码
                                ngx_memcpy(dst, src, arg->value.len);
                                ngx_unescape_uri(&dst, &src, arg->value.len, 0);
                                arg->decoded.len = dst - arg->decoded.data;
                                MLOGD(
                                    "detect url endocoding param: %V = %V "
                                    "decoded: %V (URL encoded)",
                                    &arg->key, &arg->value, &arg->decoded);
                        } else {
                                // 不存在 URL 编码，直接修改指针
                                arg->decoded.data = arg->value.data;
                                arg->decoded.len = arg->value.len;
                                MLOGD(
                                    "could not detect url encoding param: %V = "
                                    "%V (no URL encoding)",
                                    &arg->key, &arg->value);
                        }
                }
        }

        MLOGD("Exiting to process args");
        return args;
}