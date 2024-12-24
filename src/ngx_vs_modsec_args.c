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
        value_start = (p < end && *p == '=') ? p + 1 : p;
        while (p < end && *p != '&') p++;
        value_end = p;
        p++; // Skip & or reach end

        if (key_end > key_start) {
            // Create temporary ngx_str_t for key and value
            ngx_str_t key = {.data = key_start, .len = key_end - key_start};
            ngx_str_t value = {.data = value_start, .len = value_end - value_start};

            // 对于 GET 参数
            CHECK_HTTP_PARAM_MATCH(key, value, sign_rule_mg->get_match_context, ctx);
        }
    }

    MLOGD("Exiting to process uri args");
}