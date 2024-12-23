#include "ddebug.h"
#include "ngx_config.h"
#include "ngx_http_modsecurity_runtime.h"

// 红黑树节点插入函数
void rule_hit_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
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
rule_hit_node_t *find_rule_hit_node(ngx_rbtree_t *tree, u_int32_t threat_id) {
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
ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool,
                               u_int32_t threat_id, uint32_t rule_bit_mask,
                               uint32_t combined_rule_mask,
                               uint32_t not_rule_mask) {
  // 先查找是否已存在相同threat_id的节点
  rule_hit_node_t *existing = find_rule_hit_node(tree, threat_id);
  if (existing != NULL) {
    // 如果找到现有节点
    MLOGD("finded exisesting record, rule ID: %d, Sub ID: %d, BitMask: 0x%d, "
          "not_mask: 0x%d",
          existing->threat_id >> 8, existing->threat_id & 0xFF,
          existing->combined_rule_mask, existing->not_rule_mask);
    existing->rule_bit_mask |= rule_bit_mask;
    return NGX_OK;
  }

  MLOGD("recoed isn't exist, rule ID: %d, Sub ID: %d combined BitMask: 0x%d, "
        "not_mask: 0x%d, created new record",
        threat_id >> 8, threat_id & 0xFF, combined_rule_mask, not_rule_mask);

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
  node->not_rule_mask = not_rule_mask;

  // 插入节点到红黑树
  ngx_rbtree_insert(tree, &node->node);

  return NGX_OK;
}

// 递归遍历红黑树的辅助函数
void traverse_rule_hit_tree(ngx_rbtree_node_t *node,
                            ngx_rbtree_node_t *sentinel) {
  if (node == sentinel) {
    return;
  }

  // 先遍历左子树
  traverse_rule_hit_tree(node->left, sentinel);

  // 处理当前节点
  rule_hit_node_t *current = (rule_hit_node_t *)node;
  MLOGD(" tree Rule ID: %d, Sub ID: %d, BitMask: 0x%d, CombinedMask: 0x%d, "
        "not_mask: 0x%d",
        current->threat_id >> 8, current->threat_id & 0xFF,
        current->rule_bit_mask, current->combined_rule_mask,
        current->not_rule_mask);
  // 需要通过xor 排除非掩码，获取真正的andbit
  if (current->rule_bit_mask ==
          (current->combined_rule_mask ^ current->not_rule_mask) &&
      // 非条件判断
      (current->rule_bit_mask & current->not_rule_mask) == 0) {
    // TODO 上报告警
    MLOGD("Matched Rule ID: %d", current->threat_id >> 8);
  }

  // 再遍历右子树
  traverse_rule_hit_tree(node->right, sentinel);
}

// 开始遍历的函数
void traverse_rule_hits(ngx_rbtree_t *tree) {
  if (tree == NULL || tree->root == tree->sentinel) {
    MLOGN("Empty rule hit tree");
    return;
  }

  MLOGD("Traversing rule hits:");
  traverse_rule_hit_tree(tree->root, tree->sentinel);
}