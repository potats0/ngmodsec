#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "waf_rule_types.h"
#include "ngx_http_waf_rule_runtime.h"

void log_rule_mg_status(ngx_conf_t *cf, sign_rule_mg_t *rule_mg) {
  if (!rule_mg) {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "rule_mg is NULL");
    return;
  }

  ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                     "rule_mg status: max_rules=%d, rules_count=%d",
                     rule_mg->max_rules, rule_mg->rules_count);

  // Print added rule IDs
  if (rule_mg->rules_count > 0) {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "rule IDs:");
    for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
      uint32_t rule_id = rule_mg->rule_ids[i];
      ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "  [%d] rule_id=%d", i,
                         rule_id);

      // Print rule mask information
      rule_mask_array_t *masks = &rule_mg->rule_masks[rule_id];
      ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    sub_rules_count=%d",
                         masks->sub_rules_count);

      // Print rule-related AndBits
      if (rule_mg->string_match_context_array) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    Rule AndBits:");
        for (int ctx_idx = HTTP_VAR_UNKNOWN + 1; ctx_idx < HTTP_VAR_MAX;
             ctx_idx++) {
          string_match_context_t *ctx =
              rule_mg->string_match_context_array[ctx_idx];
          if (!ctx || !ctx->string_patterns_list ||
              ctx->string_patterns_num <= 0) {
            continue;
          }

          for (int pat_idx = 0; pat_idx < ctx->string_patterns_num; pat_idx++) {
            string_pattern_t *pattern = &ctx->string_patterns_list[pat_idx];
            if (!pattern || !pattern->string_pattern) {
              continue;
            }

            if (!pattern->relations || pattern->relation_count <= 0) {
              continue;
            }

            for (int rel_idx = 0; rel_idx < pattern->relation_count;
                 rel_idx++) {
              rule_relation_t *rel = &pattern->relations[rel_idx];
              if (!rel) {
                continue;
              }

              if ((rel->threat_id >> 8) == rule_id) {
                char threat_id_str[32];
                char pattern_id_str[32];
                snprintf(threat_id_str, sizeof(threat_id_str), "%u",
                         rel->threat_id);
                snprintf(pattern_id_str, sizeof(pattern_id_str), "%u",
                         rel->pattern_id);

                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      Threat ID: %s",
                                   threat_id_str);
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                                   "      Pattern ID: %s", pattern_id_str);
              }
            }
          }
        }
      }

      // Print sub-rule mask information
      for (uint8_t sub_id = 0; sub_id < masks->sub_rules_count; sub_id++) {
        char and_mask_str[32];
        char not_mask_str[32];
        snprintf(and_mask_str, sizeof(and_mask_str), "0x%04x",
                 masks->and_masks[sub_id]);
        snprintf(not_mask_str, sizeof(not_mask_str), "0x%04x",
                 masks->not_masks[sub_id]);

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    Sub-rule %u:", sub_id);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      AND mask: %s",
                           and_mask_str);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      NOT mask: %s",
                           not_mask_str);
      }
    }
  }

  // Print all match context information
  if (rule_mg->string_match_context_array) {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "String Match Contexts:");
    for (int i = HTTP_VAR_UNKNOWN + 1; i < HTTP_VAR_MAX; i++) {
      string_match_context_t *ctx = rule_mg->string_match_context_array[i];
      if (!ctx) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "Match Context %d: <empty>",
                           i);
        continue;
      }

      if (!ctx->string_patterns_list) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                           "Match Context %d: <invalid - no patterns list>", i);
        continue;
      }

      ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "Match Context %d:", i);
      ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "  Pattern Count: %d",
                         ctx->string_patterns_num);

      for (int j = 0; j < ctx->string_patterns_num; j++) {
        string_pattern_t *pattern = &ctx->string_patterns_list[j];
        if (!pattern || !pattern->string_pattern) {
          ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "  Pattern %d: <invalid>",
                             j);
          continue;
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "  Pattern %d:", j);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    Content: %s",
                           pattern->string_pattern);

        char hs_flags_str[32];
        snprintf(hs_flags_str, sizeof(hs_flags_str), "0x%04x",
                 pattern->hs_flags);
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    HS Flags: %s",
                           hs_flags_str);

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "    Relations Count: %d",
                           pattern->relation_count);

        if (pattern->relations) {
          for (int k = 0; k < pattern->relation_count; k++) {
            rule_relation_t *rel = &pattern->relations[k];
            char and_bit_str[32];
            snprintf(and_bit_str, sizeof(and_bit_str), "%u", rel->and_bit);

            char threat_id_str[32];
            char pattern_id_str[32];
            snprintf(threat_id_str, sizeof(threat_id_str), "%u",
                     rel->threat_id);
            snprintf(pattern_id_str, sizeof(pattern_id_str), "%u",
                     rel->pattern_id);

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      Threat ID: %s",
                               threat_id_str);
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      Pattern ID: %s",
                               pattern_id_str);
            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "      And bit: %s",
                               and_bit_str);
          }
        }
      }
    }
  } else {
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                       "No string match contexts available");
  }
}
