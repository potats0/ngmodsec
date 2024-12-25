#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_vs_modsec_runtime.h"

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

            MLOGD("GET param: %V = %V", &key, &value);

            // 对于 GET 参数
            CHECK_HTTP_PARAM_MATCH(key, value, sign_rule_mg->get_match_context, ctx);

            // 对于不定参数，全都送检
            DO_CHECK_VARS(value, HTTP_VAR_ALL_GET_ARGS);

            // 对于name部分也送检
            DO_CHECK_VARS(key, HTTP_VAR_ALL_GET_NAME);
        }
    }

    MLOGD("Exiting to process uri args");
}