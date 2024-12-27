#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_vs_modsec_runtime.h"

static ngx_str_t url_decode(ngx_pool_t *pool, const ngx_str_t *src) {
    ngx_str_t dst = ngx_null_string;

    if (src->len == 0) {
        return dst;
    }

    u_char *decoded = ngx_pnalloc(pool, src->len);
    if (decoded == NULL) {
        return dst;
    }

    u_char *d = decoded;
    u_char *s = src->data;
    u_char *end = s + src->len;
    u_char ch, c;

    while (s < end) {
        ch = *s++;
        if (ch == '%' && s + 2 <= end) {
            c = *s++;
            if (c >= '0' && c <= '9') {
                ch = c - '0';
            } else if (c >= 'a' && c <= 'f') {
                ch = c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                ch = c - 'A' + 10;
            } else {
                *d++ = '%';
                *d++ = *(s - 1);
                continue;
            }
            ch = (ch << 4);

            c = *s++;
            if (c >= '0' && c <= '9') {
                ch |= c - '0';
            } else if (c >= 'a' && c <= 'f') {
                ch |= c - 'a' + 10;
            } else if (c >= 'A' && c <= 'F') {
                ch |= c - 'A' + 10;
            } else {
                *d++ = '%';
                *d++ = *(s - 2);
                *d++ = *(s - 1);
                continue;
            }
            *d++ = ch;  // 直接保持 NULL 字符
        } else if (ch == '+') {
            *d++ = ' ';
        } else {
            *d++ = ch;
        }
    }

    dst.data = decoded;
    dst.len = d - decoded;
    return dst;
}

void parse_get_args(ngx_http_request_t *r) {
    if (r->args.len == 0) {
        MLOGD("No GET parameters found");
        return;
    }
    MLOGD("GET parameters found Starting to process uri args");

    u_char *start = r->args.data;
    u_char *end = r->args.data + r->args.len;
    u_char *p = start;
    u_char *key_start, *key_end, *value_start, *value_end;
    ngx_vs_modsec_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);

    while (p < end) {
        // Find key start and end
        key_start = p;
        while (p < end && *p != '=' && *p != '&') p++;
        key_end = p;

        // Find value start and end
        if (p < end && *p == '=') {
            p++; // Skip '='
            value_start = p;
            while (p < end && *p != '&') p++;
            value_end = p;
        } else {
            // Handle cases like "?param&" or "?param"
            value_start = value_end = p;
        }

        if (p < end && *p == '&') {
            p++; // Skip '&'
        } else if (p == end) {
            // Last parameter
            p = end;
        }

        if (key_end > key_start) {
            // Create temporary ngx_str_t for key and value
            ngx_str_t key = {.data = key_start, .len = key_end - key_start};
            ngx_str_t value = {.data = value_start, .len = value_end - value_start};

            // URL decode value
            ngx_str_t decoded = url_decode(r->pool, &value);
            if (!decoded.data) {
                MLOGD("Failed to decode GET param: [%V] = [%V]", &key, &value);
                continue;
            }

            MLOGD("GET param: %V = %V decoded: %V", &key, &value, &decoded);

            // 对于 GET 参数
            CHECK_HTTP_PARAM_MATCH(key, decoded, sign_rule_mg->get_match_context, ctx);

            // 对于不定参数，全都送检
            DO_CHECK_VARS(decoded, HTTP_VAR_ALL_GET_VALUE);

            // 对于name部分也送检
            DO_CHECK_VARS(key, HTTP_VAR_ALL_GET_NAME);
        }
    }

    MLOGD("Exiting to process uri args");
}