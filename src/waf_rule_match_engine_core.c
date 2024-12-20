#include "ddebug.h"
#include "ngx_http_waf_rule_runtime.h"
#ifdef WAF
#include "conf1_virtual_site_module.h"
#include "ngx_detect_log_module.h"
#include "ngx_http_anti_crawler_module.h"
#include "ngx_http_whitelist_module.h"
#include "vs_sign_conf.h"

static void insert_log_unit(rule_hit_unit_t *unit, rule_log_unit_t *log_unit) {
  if (log_unit == NULL) {
    return;
  }

  rule_log_unit_t **u = ngx_array_push(&(unit->rule_log_array));
  if (!u) {
    return;
  }
  *u = log_unit;
}

void fill_event_info(ngx_http_request_t *r, ngx_uint_t rule_id,
                     rule_log_unit_t *log_unit, ngx_array_t *rule_log_array) {
  lua_fill_log_t event;
  waf_sign_node_t *rule = NULL;
  waf_sign_info_t *rule_info = NULL;
  ngx_http_detect_log_ctx_t *ctx = NULL;
  ngx_http_core_srv_conf_t *cscf =
      ngx_http_get_module_srv_conf(r, ngx_http_core_module);
  ngx_uint_t server_id = cscf->server_conf_id;
  char type_str[16] = {0};

  rule =
      (waf_sign_node_t *)wafconf_rule_conf_get_by_server_id(server_id, rule_id);
  if (rule == NULL) {
    MLOGN("Error: get rule by server id %lu failed", server_id);
    return NGX_ERROR;
  }

  // build_log_uuid(&event);

  rule_info = (waf_sign_info_t *)wafconf_conf_get_by_index(CONF1_PRE_SIGN_LIST,
                                                           rule_id);
  if (rule_info == NULL) {
    MLOGN("Error: get rule by index %lu failed", rule_id);
    return NGX_ERROR;
  }

  ngx_memzero(&event, sizeof(lua_fill_log_t));
  event.api_flag = 0;
  event.event_id = rule_id;
  event.log_location = 0;
  event.owasp_id = rule_info->owasp_id;
  event.module_type = RULE_DETECT_MODULE;
  event.configure_action = (uint32_t)rule->action;
  event.threat_level = (uint32_t)rule_info->level;

  log_2_content(r, rule_id, log_unit, rule_log_array, event.content);

  ngx_memzero(event.policy_name, MAX_POLICY_NAME_LEN),
      ngx_memcpy(event.policy_name, "rule", MAX_POLICY_NAME_LEN);

  ngx_memzero(event.event_name, MAX_EVENT_NAME_LEN);
  ngx_memcpy(event.event_name, rule_info->name, MAX_EVENT_NAME_LEN);

  ngx_memzero(event.event_group_name, 32);
  ngx_sprintf((u_char *)type_str, "%d", rule_info->type);
  ngx_memcpy(event.event_group_name, type_str, 32);
  fill_detect_info(r, &event);
}

#endif
/*
 *@name Threat_find_func
 *@brief 合入命中子式bit位 ，查看是否所有子式条件全部命中
 *@param [in] unit ：        已保存该规则命中单元
 *@param [in] relation_node: 当前命中子式的逻辑关系节点
 */
int Threat_find_func(rule_hit_unit_t *unit, rule_relation_t *relation_node,
                     hs_search_userdata_t *hs_usrdata) {

  MLOGN("find tmp threat_id %d\n ", relation_node->threat_id);
  // 攻击特征
  unit->save_and_bit |= relation_node->and_bit;

  // // 判断攻击特征是否全部命中
  // if (1 << (relation_node->sum_and_bit) == (unit->save_and_bit) + 1) {
  //   // 判断流属性是否命中
  //   unsigned int save_attr = hs_usrdata->rule_hit_context.save_attribute;
  //   unsigned int sum_attr = relation_node->sum_attribute_bit;
  //   if ((save_attr & sum_attr) != sum_attr) {
  //     return 0;
  //   }
  // 特征全部命中
  unit->threat_id = relation_node->threat_id >> 8;
  MLOGN("RULE  MATCHED  threat 222 %d !!! \n", unit->threat_id);

#ifdef WAF
  if (unit->threat_id >= ANTI_CRAWLER_ID_MIN &&
      unit->threat_id <= ANTI_CRAWLER_ID_MAX) {
    ngx_anti_crawler_process(hs_usrdata->r, unit->threat_id);
    unit->save_and_bit = 0;
    return 0;
  }

  if (ngx_http_white_check_event(hs_usrdata->r, unit->threat_id, 0) != NGX_OK) {
    fill_event_info(hs_usrdata->r, unit->threat_id, NULL,
                    &unit->rule_log_array);
    set_protovar_int(hs_usrdata->r, NGX_VAR_THREAT_ID, unit->threat_id);
  }
#endif
  //   unit->save_and_bit = 0;
  // }
  return 0;
}

/*
 *@name Threat_insert_func
 *@brief 命中子式，添加该规则的逻辑单元于hs_usrdata
 */
rule_hit_unit_t *Threat_insert_func(rule_hit_context_t *context,
                                    rule_relation_t *relation_node,
                                    hs_search_userdata_t *hs_usrdata) {
  unsigned int *hit_count_p = &(context->hit_count);
  if (*hit_count_p > MAX_HIT_RESULT_NUM) {
    MLOGN("insert context int totul %d  exceed MAX_HIT_RESULT_NUM  \n",
          *hit_count_p);
    return NULL;
  }

  rule_hit_unit_t *unit =
      ngx_pcalloc(hs_usrdata->r->pool, sizeof(rule_hit_unit_t));
  if (unit == NULL) {
    MLOGN("Can't alloc hit unit mem  count %d !", *hit_count_p);
    return NULL;
  }
  unit->threat_id = relation_node->threat_id;
  // unit->sum_and_bit = relation_node->sum_and_bit;
  // unit->save_and_bit |= relation_node->and_bit;
  (*hit_count_p)++;

  ngx_array_init(&(unit->rule_log_array), hs_usrdata->r->pool, 8,
                 sizeof(rule_log_unit_t *));

  MLOGN("Insert hit context int %d   %p threat id %d \n", *hit_count_p, unit,
        relation_node->threat_id);
  return unit;
}

/*
 *@name rbtree_search_insert
 *@brief 遍历查找命中记录红黑树，若无则插入，
 *@param [in] relation_node  当前命中子式所关联的逻辑关系
 */
int rbtree_search_insert(rule_relation_t *relation_node,
                         hs_search_userdata_t *hs_usrdata,
                         rule_log_unit_t *log_unit) {
  rule_hit_context_t *hit_ctx = &(hs_usrdata->rule_hit_context);
  struct rb_root *root = &(hit_ctx->rule_hit_root);
  struct rb_node **tmp = &(root->rb_node), *parent = NULL;
  /* Only add flow attribute sign */
  // if (relation_node->attribute_bit) {
  //   hs_usrdata->rule_hit_context.save_attribute |=
  //   relation_node->attribute_bit; return 0;
  //   // TODO  为了性能考虑 如果特征在属性之前拼凑齐 那么会漏报。
  //   // 等做完dolog_list 告警中心 就可以解决了。
  // }

  while (*tmp) {
    rule_hit_unit_t *unit = container_of(*tmp, rule_hit_unit_t, node);

    parent = *tmp;
    if (relation_node->threat_id < unit->threat_id) {
      tmp = &((*tmp)->rb_left);
    } else if (relation_node->threat_id > unit->threat_id) {
      tmp = &((*tmp)->rb_right);
    } else {
#ifdef WAF
      insert_log_unit(unit, log_unit);
#endif
      /* Find a threat has insert before,  some condition hit. */
      Threat_find_func(unit, relation_node, hs_usrdata);
      return 0;
    }
  }

  /* Single condition Threat ,  dolog,  dont insert into rbtree. */
  // if (relation_node->sum_and_bit == 1 &&
  //     relation_node->sum_attribute_bit == 0) {
  //   MLOGN("RULE  MATCHED  threat 111 %d !!! \n", relation_node->threat_id);

#ifdef WAF
  if (relation_node->threat_id >> 8 >= ANTI_CRAWLER_ID_MIN &&
      relation_node->threat_id >> 8 <= ANTI_CRAWLER_ID_MAX) {
    ngx_anti_crawler_process(hs_usrdata->r, relation_node->threat_id >> 8);
    return 0;
  }

  if (ngx_http_white_check_event(hs_usrdata->r, relation_node->threat_id >> 8,
                                 0) != NGX_OK) {
    fill_event_info(hs_usrdata->r, relation_node->threat_id >> 8, log_unit,
                    NULL);
    set_protovar_int(hs_usrdata->r, NGX_VAR_THREAT_ID,
                     relation_node->threat_id >> 8);
  }

  return 0;

#endif
  // }
  /* Add new node into rbtree and rebalance tree. */
  rule_hit_unit_t *unit =
      Threat_insert_func(hit_ctx, relation_node, hs_usrdata);
  if (unit != NULL) {
#ifdef WAF
    insert_log_unit(unit, log_unit);
#endif
    rb_link_node(&unit->node, parent, tmp);
    rb_insert_color(&unit->node, root);
  }

  return 0;
}

int eventHandler(unsigned int id, unsigned long long from,
                 unsigned long long to, unsigned int flags, void *ctx) {
  int ret = 0;
  hs_search_userdata_t *hs_usrdata = (hs_search_userdata_t *)ctx;
  // rule_hit_context_t *hit_context = &hs_usrdata->rule_hit_context;
  sign_rule_mg_t *mg = sign_rule_mg;

  MLOGN("-------------------------success----------------------\n");
  MLOGN("Match for pattern %30s at from %llu to  %llu\n",
        mg->string_match_context_array[hs_usrdata->proto_var_id]
            ->string_patterns_list[id]
            .string_pattern,
        from, to);

  string_pattern_t *pattern =
      &(mg->string_match_context_array[hs_usrdata->proto_var_id]
            ->string_patterns_list[id]);

  if (pattern->relation_count <= 0) {
    return ret;
  }

  // 每次匹配中特征串 记录 用于日志高亮显示
  rule_log_unit_t *log_unit =
      ngx_pcalloc(hs_usrdata->r->pool, sizeof(rule_log_unit_t));
  if (log_unit) {
    log_unit->proto_var_id = hs_usrdata->proto_var_id;
    log_unit->begin = from;
    log_unit->end = to;
  }

#ifdef WAF
  rule_relation_t *rr_node = NULL;
  struct list_head *head_pos = NULL;
  // 遍历当前模式串关联的逻辑关系节点
  list_for_each(head_pos, &(pattern->relation_list)) {
    rr_node = list_entry(head_pos, rule_relation_t, list);
    if (rr_node == NULL) {
      break;
    }
    rbtree_search_insert(rr_node, hs_usrdata, log_unit);
  }
#endif
  return ret;
}

int new_string_check(void *inputData, unsigned int inputLen,
                     hs_search_userdata_t *usrdata) {
  unsigned int pro_var_id = usrdata->proto_var_id;
  sign_rule_mg_t *mg = sign_rule_mg;

  if (mg == NULL || inputData == NULL || inputLen == 0 || inputLen > 4096) {
    MLOGN("---ERROR mg %p new sign scan data len %d ", mg, inputLen);
    return -1;
  }

  string_match_context_t **sm_ctx_array =
      (string_match_context_t **)mg->string_match_context_array;

  if (sm_ctx_array[pro_var_id] == NULL ||
      sm_ctx_array[pro_var_id]->db == NULL) {
    MLOGN("--ERROR hyperscan scan proto id %d  is NULL \n", pro_var_id);
    return -1;
  }

  // hs_error_t err =
  //     hs_scan(sm_ctx_array[pro_var_id]->db, (const char *)inputData,
  //     inputLen,
  //             0, scratch[pro_var_id], eventHandler, usrdata);
  // if (HS_SUCCESS != err && HS_SCAN_TERMINATED != err) {
  //   return err;
  // }

  // MLOGN("--%s:%d: hyperscan scan error %d \n", __FUNCTION__, __LINE__, err);

  return 0;
}

void __attribute__((unused))
new_sign_engin_scan(void *inputData, unsigned int inputLen,
                    hs_search_userdata_t *usrdata) {
  new_string_check(inputData, inputLen, usrdata);
}
