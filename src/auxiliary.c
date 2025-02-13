/* 
 * This file is part of [ngmodsec].
 *
 * [ngmodsec] is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * [ngmodsec] is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with [ngmodsec]. If not, see <https://www.gnu.org/licenses/>.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_vs_modsec_runtime.h"
#include "ruleset_types.h"

void log_rule_mg_status(sign_rule_mg_t *rule_mg) {
        if (!rule_mg) {
                MLOGN("rule_mg is NULL");
                return;
        }

        MLOGN("rule_mg status: max_rules=%d, rules_count=%d",
              rule_mg->max_rules, rule_mg->rules_count);

        // Print added rule IDs
        if (rule_mg->rules_count > 0) {
                MLOGN("rule IDs:");
                for (uint32_t i = 0; i < rule_mg->rules_count; i++) {
                        uint32_t rule_id = rule_mg->rule_ids[i];
                        MLOGN("  [%d] rule_id=%d", i, rule_id);

                        // Print rule mask information
                        rule_mask_array_t *masks =
                            &rule_mg->rule_masks[rule_id];
                        MLOGN("    sub_rules_count=%d", masks->sub_rules_count);

                        // Print rule-related AndBits
                        if (rule_mg->string_match_context_array) {
                                MLOGN("    Rule AndBits:");
                                for (int ctx_idx = HTTP_VAR_UNKNOWN + 1;
                                     ctx_idx < HTTP_VAR_MAX; ctx_idx++) {
                                        string_match_context_t *ctx =
                                            rule_mg->string_match_context_array
                                                [ctx_idx];
                                        if (!ctx ||
                                            !ctx->string_patterns_list ||
                                            ctx->string_patterns_num <= 0) {
                                                continue;
                                        }

                                        for (uint32_t pat_idx = 0;
                                             pat_idx < ctx->string_patterns_num;
                                             pat_idx++) {
                                                string_pattern_t *pattern =
                                                    &ctx->string_patterns_list
                                                         [pat_idx];
                                                if (!pattern ||
                                                    !pattern->string_pattern) {
                                                        continue;
                                                }

                                                if (!pattern->relations ||
                                                    pattern->relation_count <=
                                                        0) {
                                                        continue;
                                                }

                                                for (uint32_t rel_idx = 0;
                                                     rel_idx <
                                                     pattern->relation_count;
                                                     rel_idx++) {
                                                        rule_relation_t *rel =
                                                            &pattern->relations
                                                                 [rel_idx];
                                                        if (!rel) {
                                                                continue;
                                                        }

                                                        if ((rel->threat_id >>
                                                             8) == rule_id) {
                                                                char threat_id_str
                                                                    [32];
                                                                char pattern_id_str
                                                                    [32];
                                                                snprintf(
                                                                    threat_id_str,
                                                                    sizeof(
                                                                        threat_id_str),
                                                                    "%u",
                                                                    rel->threat_id);
                                                                snprintf(
                                                                    pattern_id_str,
                                                                    sizeof(
                                                                        pattern_id_str),
                                                                    "%u",
                                                                    rel->pattern_id);

                                                                MLOGN(
                                                                    "      "
                                                                    "Threat "
                                                                    "ID: % s ",
                                                                    threat_id_str);
                                                                MLOGN(
                                                                    "      "
                                                                    "Pattern "
                                                                    "ID: %s ",
                                                                    pattern_id_str);
                                                        }
                                                }
                                        }
                                }
                        }

                        // Print sub-rule mask information
                        for (uint8_t sub_id = 0;
                             sub_id < masks->sub_rules_count; sub_id++) {
                                char and_mask_str[32];
                                char not_mask_str[32];
                                snprintf(and_mask_str, sizeof(and_mask_str),
                                         "0x%04x", masks->and_masks[sub_id]);
                                snprintf(not_mask_str, sizeof(not_mask_str),
                                         "0x%04x", masks->not_masks[sub_id]);

                                MLOGN("    Sub-rule %u:", sub_id);
                                MLOGN("      AND mask: %s ", and_mask_str);
                                MLOGN("      NOT mask: %s", not_mask_str);
                        }
                }
        }

        // Print all match context information
        if (rule_mg->string_match_context_array) {
                MLOGN("String Match Contexts:");
                for (int i = HTTP_VAR_UNKNOWN + 1; i < HTTP_VAR_MAX; i++) {
                        string_match_context_t *ctx =
                            rule_mg->string_match_context_array[i];
                        if (!ctx) {
                                MLOGN("Match Context %d: <empty> ", i);
                                continue;
                        }

                        if (!ctx->string_patterns_list) {
                                MLOGN(
                                    "Match Context %d: <invalid - no patterns "
                                    "list>",
                                    i);
                                continue;
                        }

                        MLOGN("Match Context %d:", i);
                        MLOGN("  Pattern Count: %d", ctx->string_patterns_num);

                        for (uint32_t j = 0; j < ctx->string_patterns_num;
                             j++) {
                                string_pattern_t *pattern =
                                    &ctx->string_patterns_list[j];
                                if (!pattern || !pattern->string_pattern) {
                                        MLOGN("  Pattern %d: <invalid> ", j);
                                        continue;
                                }

                                MLOGN("  Pattern %d:", j);
                                MLOGN("    Content: %s",
                                      pattern->string_pattern);

                                char hs_flags_str[32];
                                snprintf(hs_flags_str, sizeof(hs_flags_str),
                                         "0x%04x", pattern->hs_flags);
                                MLOGN("    HS Flags: %s", hs_flags_str);

                                MLOGN("    Relations Count: %d",
                                      pattern->relation_count);

                                if (pattern->relations) {
                                        for (uint32_t k = 0;
                                             k < pattern->relation_count; k++) {
                                                rule_relation_t *rel =
                                                    &pattern->relations[k];
                                                char and_bit_str[32];
                                                snprintf(and_bit_str,
                                                         sizeof(and_bit_str),
                                                         "%u", rel->and_bit);

                                                char threat_id_str[32];
                                                char pattern_id_str[32];
                                                snprintf(threat_id_str,
                                                         sizeof(threat_id_str),
                                                         "%u", rel->threat_id);
                                                snprintf(pattern_id_str,
                                                         sizeof(pattern_id_str),
                                                         "%u", rel->pattern_id);

                                                MLOGN("      Threat ID: %s",
                                                      threat_id_str);
                                                MLOGN("      Pattern ID: %s",
                                                      pattern_id_str);
                                                MLOGN("      And bit: %s",
                                                      and_bit_str);
                                        }
                                }
                        }
                }
        } else {
                MLOGN("No string match contexts available");
        }
}
