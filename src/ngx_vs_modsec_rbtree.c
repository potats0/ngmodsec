#include "ngx_config.h"
#include "ngx_vs_modsec_runtime.h"

// 红黑树节点插入函数
void rule_hit_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                           ngx_rbtree_node_t *sentinel) {
        rule_hit_record_t *n, *t;
        ngx_rbtree_node_t **p;

        for (;;) {
                n = (rule_hit_record_t *)node;
                t = (rule_hit_record_t *)temp;

                if (node->key != temp->key) {
                        p = (node->key < temp->key) ? &temp->left
                                                    : &temp->right;
                } else {
                        // 如果key相同，比较完整的threat_id
                        p = (n->matched_rule_id < t->matched_rule_id)
                                ? &temp->left
                                : &temp->right;
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
rule_hit_record_t *find_rule_hit_node(ngx_rbtree_t *tree, u_int32_t threat_id) {
        ngx_rbtree_node_t *node = tree->root;
        ngx_rbtree_node_t *sentinel = tree->sentinel;

        while (node != sentinel) {
                rule_hit_record_t *current = (rule_hit_record_t *)node;

                if (threat_id < current->matched_rule_id) {
                        node = node->left;
                } else if (threat_id > current->matched_rule_id) {
                        node = node->right;
                } else {
                        return current; // 找到匹配的节点
                }
        }
        return NULL; // 未找到节点
}

// 创建并插入新节点的辅助函数
ngx_int_t insert_rule_hit_node(ngx_rbtree_t *tree, ngx_pool_t *pool,
                               u_int32_t threat_id, uint32_t rule_hit_bitmask,
                               uint32_t current_request_method) {
        // 先查找是否已存在相同threat_id的节点
        rule_hit_record_t *existing = find_rule_hit_node(tree, threat_id);
        uint32_t rule_id = threat_id >> 8;
        uint32_t sub_rule_id = threat_id & 0xFF;

        if (existing != NULL) {
                uint16_t alert_trigger_bitmask =
                    sign_rule_mg->rule_masks[rule_id].and_masks[sub_rule_id];
                uint16_t alert_exclusion_bitmask =
                    sign_rule_mg->rule_masks[rule_id].not_masks[sub_rule_id];

                // 如果找到现有节点
                MLOGD(
                    "finded exisesting record, rule ID: %d, Sub ID: %d, "
                    "BitMask: 0x%d, "
                    "not_mask: 0x%d",
                    existing->matched_rule_id >> 8,
                    existing->matched_rule_id & 0xFF, alert_trigger_bitmask,
                    alert_exclusion_bitmask);
                existing->rule_hit_bitmask |= rule_hit_bitmask;
                return NGX_OK;
        }

        MLOGD("recoed isn't exist, rule ID: %d, Sub ID: %d  created new record",
              threat_id >> 8, threat_id & 0xFF);

        // 如果不存在，创建新节点
        rule_hit_record_t *node;

        // 分配新节点内存
        node = ngx_palloc(pool, sizeof(rule_hit_record_t));
        if (node == NULL) {
                MLOGE("alloc rule_hit_node_t failed");
                return NGX_ERROR;
        }

        // 初始化节点数据
        node->node.key = threat_id; // 使用rule_id作为key
        node->matched_rule_id = threat_id;
        node->rule_hit_bitmask = rule_hit_bitmask;
        node->current_request_method = current_request_method;

        // 插入节点到红黑树
        ngx_rbtree_insert(tree, &node->node);

        MLOGD("success insert new record, rbtee key: %d", threat_id);
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
        rule_hit_record_t *current = (rule_hit_record_t *)node;
        uint32_t rule_id = current->matched_rule_id >> 8;
        uint32_t sub_rule_id = current->matched_rule_id & 0xFF;
        uint16_t alert_trigger_bitmask =
            sign_rule_mg->rule_masks[rule_id].and_masks[sub_rule_id];
        uint16_t alert_exclusion_bitmask =
            sign_rule_mg->rule_masks[rule_id].not_masks[sub_rule_id];
        u_int32_t matched_rule_methods =
            sign_rule_mg->rule_masks[rule_id].method[sub_rule_id];

        MLOGD(
            " tree Rule ID: %d, Sub ID: %d, BitMask: 0x%d, CombinedMask: 0x%d, "
            "not_mask: 0x%d, rule_method: %d, req method: %d",
            rule_id, sub_rule_id, current->rule_hit_bitmask,
            alert_trigger_bitmask, alert_exclusion_bitmask,
            matched_rule_methods, current->current_request_method);

        // 需要通过xor 排除非掩码，获取真正的andbit
        if (current->rule_hit_bitmask ==
                (alert_trigger_bitmask ^ alert_exclusion_bitmask) &&
            // 非条件判断
            (current->rule_hit_bitmask & alert_exclusion_bitmask) == 0 &&
            // 方法匹配 直接and操作就行
            matched_rule_methods & current->current_request_method) {
                // TODO 上报告警
                MLOGD("Matched Rule ID: %d", rule_id);
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