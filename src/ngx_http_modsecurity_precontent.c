#include "ddebug.h"
#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_http_modsecurity_runtime.h"

// 红黑树节点插入函数
static void rule_hit_insert_value(ngx_rbtree_node_t *temp,
                                  ngx_rbtree_node_t *node,
                                  ngx_rbtree_node_t *sentinel) {
  rule_hit_node_t *n, *t;
  ngx_rbtree_node_t **p;

  for (;;) {
    n = (rule_hit_node_t *)node;
    t = (rule_hit_node_t *)temp;

    if (node->key != temp->key) {
      p = (node->key < temp->key) ? &temp->left : &temp->right;
    } else {
      // 如果key相同，比较完整的threat_id
      p = (n->threat_id < t->threat_id) ? &temp->left : &temp->right;
    }

    if (*p == sentinel) {
      break;
    }

    temp = *p;
  }

  *p = node;
  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;
  ngx_rbt_red(node);
}

// 查找节点的函数
static rule_hit_node_t *find_rule_hit_node(ngx_rbtree_t *tree, int threat_id) {
  ngx_rbtree_node_t *node = tree->root;
  ngx_rbtree_node_t *sentinel = tree->sentinel;

  while (node != sentinel) {
    rule_hit_node_t *current = (rule_hit_node_t *)node;

    if (threat_id < current->threat_id) {
      node = node->left;
    } else if (threat_id > current->threat_id) {
      node = node->right;
    } else {
      return current; // 找到匹配的节点
    }
  }
  return NULL; // 未找到节点
}

// 创建并插入新节点的辅助函数
static ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool,
                                      int threat_id, uint32_t rule_bit_mask,
                                      uint32_t combined_rule_mask) {
  // 先查找是否已存在相同threat_id的节点
  rule_hit_node_t *existing = find_rule_hit_node(tree, threat_id);
  if (existing != NULL) {
    // 如果找到现有节点，执行OR操作
    existing->rule_bit_mask |= rule_bit_mask;
    return NGX_OK;
  }

  // 如果不存在，创建新节点
  rule_hit_node_t *node;

  // 分配新节点内存
  node = ngx_palloc(pool, sizeof(rule_hit_node_t));
  if (node == NULL) {
    return NGX_ERROR;
  }

  // 初始化节点数据
  node->node.key = threat_id >> 8; // 使用rule_id作为key
  node->threat_id = threat_id;
  node->rule_bit_mask = rule_bit_mask;
  node->combined_rule_mask = combined_rule_mask;

  // 插入节点到红黑树
  ngx_rbtree_insert(tree, &node->node);

  return NGX_OK;
}

static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *context) {
  ngx_http_modsecurity_ctx_t *ctx = (ngx_http_modsecurity_ctx_t *)context;
  string_match_context_t *match_ctx = ctx->match_context;
  ngx_rbtree_t *tree = ctx->rule_hit_context;
  ngx_http_request_t *r = ctx->r;

  MLOGN("Matched rule ID: %d (from: %llu, to: %llu)", id, from, to);
  MLOGN("Matched pattern: %s",
        match_ctx->string_patterns_list[id].string_pattern);
  MLOGN("Matched relation count : %d",
        match_ctx->string_patterns_list[id].relation_count);

  for (int i = 0; i < match_ctx->string_patterns_list[id].relation_count; i++) {
    rule_relation_t relation = match_ctx->string_patterns_list[id].relations[i];

    MLOGN("Matched threat_id: %d sub_id: %d and_bit: %d",
          relation.threat_id >> 8, relation.threat_id & 0xFF, relation.and_bit);
    uint32_t rule_bit_mask = sign_rule_mg->rule_masks[relation.threat_id >> 8]
                                 .and_masks[(relation.threat_id & 0xFF) - 1];
    insert_rule_hit_node(tree, r->pool, relation.threat_id, relation.and_bit,
                         rule_bit_mask);
  }
  return 0; // Continue matching
}

// 递归遍历红黑树的辅助函数
static void traverse_rule_hit_tree(ngx_rbtree_node_t *node,
                                   ngx_rbtree_node_t *sentinel) {
  if (node == sentinel) {
    return;
  }

  // 先遍历左子树
  traverse_rule_hit_tree(node->left, sentinel);

  // 处理当前节点
  rule_hit_node_t *current = (rule_hit_node_t *)node;
  MLOGN(" tree Rule ID: %d, Sub ID: %d, BitMask: 0x%d, CombinedMask: 0x%d",
        current->threat_id >> 8, current->threat_id & 0xFF,
        current->rule_bit_mask, current->combined_rule_mask);

  // 再遍历右子树
  traverse_rule_hit_tree(node->right, sentinel);
}

// 开始遍历的函数
static void traverse_rule_hits(ngx_rbtree_t *tree) {
  if (tree == NULL || tree->root == tree->sentinel) {
    MLOGN("Empty rule hit tree");
    return;
  }

  MLOGN("Traversing rule hits:");
  traverse_rule_hit_tree(tree->root, tree->sentinel);
}

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r) {
  MLOGD("Entering precontent phase handler");
  ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
  if (ctx == NULL) {
    // 内存耗尽，相当于Bypass
    return NGX_DECLINED;
  }
  ctx->r = r;

  ngx_rbtree_t *tree = ngx_palloc(r->pool, sizeof(ngx_rbtree_t));
  ngx_rbtree_node_t *sentinel = ngx_palloc(r->pool, sizeof(ngx_rbtree_node_t));
  if (tree == NULL || sentinel == NULL) {
    return NGX_DECLINED;
  }
  ngx_rbtree_init(tree, sentinel, rule_hit_insert_value);

  string_match_context_t *match_ctx =
      sign_rule_mg->string_match_context_array[HTTP_VAR_URI];
  ctx->rule_hit_context = tree;
  ctx->match_context = match_ctx;
  if (match_ctx && match_ctx->db && scratch[HTTP_VAR_URI]) {
    hs_scan(match_ctx->db, (const char *)r->uri.data, r->uri.len, 0,
            scratch[HTTP_VAR_URI], on_match, ctx);
  }

  traverse_rule_hits(tree);
  MLOGD("Exiting precontent phase handler");
  return NGX_DECLINED;
}

ngx_int_t ngx_http_modsecurity_precontent_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  /* 注册 precontent phase handler */
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }
  *h = ngx_http_modsecurity_precontent_handler;
  return NGX_OK;
}