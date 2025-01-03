#include "ngx_vs_modsec_runtime.h"

int on_match(unsigned int id, unsigned long long from, unsigned long long to,
             unsigned int flags, void *context) {
        ngx_vs_modsec_ctx_t *ctx = (ngx_vs_modsec_ctx_t *)context;
        string_match_context_t *match_ctx = ctx->match_context;
        ngx_rbtree_t *tree = ctx->rule_hit_rbtree;
        ngx_http_request_t *r = ctx->request;

        MLOGD("Matched rule ID: %d (from: %llu, to: %llu)", id, from, to);
        MLOGD("Matched pattern: %s",
              match_ctx->string_patterns_list[id].string_pattern);
        MLOGD("Matched relation count : %d",
              match_ctx->string_patterns_list[id].relation_count);

        for (uint32_t i = 0;
             i < match_ctx->string_patterns_list[id].relation_count; i++) {
                rule_relation_t relation =
                    match_ctx->string_patterns_list[id].relations[i];

                u_int32_t threat_id = relation.threat_id >> 8;
                u_int32_t sub_id = relation.threat_id & 0xFF;
                // 当前子规则下，如果触发该条件后，设置位图的掩码
                uint32_t and_bit = relation.and_bit;
                MLOGD("Matched threat_id: %d sub_id: %d and_bit: %d", threat_id,
                      sub_id, and_bit);

                MLOGD("current request method: %d", r->method);

                insert_rule_hit_node(tree, r->pool, relation.threat_id,
                                     relation.and_bit, r->method);
        }
        return 0; // Continue matching
}