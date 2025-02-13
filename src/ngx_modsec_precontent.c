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

#include "ngx_config.h"
#include "ngx_http.h"
#include "ngx_modsec_runtime.h"

static void ngx_http_modsecurity_body_handler(ngx_http_request_t *r) {
        do {
                MLOGD("Starting body filter phase handler");
                ngx_chain_t *cl;
                // 获取上下文
                ngx_modsec_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
                if (ctx == NULL || sign_rule_mg == NULL) {
                        break;
                }

                if (r->request_body == NULL || r->request_body->bufs == NULL) {
                        MLOGD("no body found");
                        break;
                }

                // 计算body总长度
                size_t len = 0;
                for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
                        len += cl->buf->last - cl->buf->pos;
                }

                if (len == 0) {
                        MLOGD("empty body");
                        break;
                }

                // 分配内存存储完整body
                ngx_buf_t *buf = ngx_create_temp_buf(r->pool, len);
                if (buf == NULL) {
                        MLOGE("failed to allocate memory for body");
                        break;
                }

                // 复制所有body数据到一个连续的缓冲区
                u_char *p = buf->pos;
                for (cl = r->request_body->bufs; cl; cl = cl->next) {
                        p = ngx_copy(p, cl->buf->pos,
                                     cl->buf->last - cl->buf->pos);
                }
                buf->last = p;

                // 5. 执行body内容检测
                ngx_str_t body_content = {.data = buf->pos,
                                          .len = buf->last - buf->pos};
                DO_CHECK_VARS(body_content, HTTP_VAR_RAW_REQ_BODY);

                ngx_table_elt_t *content_type;

                /* 获取 Content-Type */
                content_type = r->headers_in.content_type;

                if (content_type) {
                        /* 打印 Content-Type 值 */
                        MLOGD("Content-Type: %V", &content_type->value);

                        static ngx_str_t form_urlencoded =
                            ngx_string("application/x-www-form-urlencoded");
                        if (content_type->value.len >= form_urlencoded.len &&
                            ngx_strncasecmp(content_type->value.data,
                                            form_urlencoded.data,
                                            form_urlencoded.len) == 0) {
                                // 是 application/x-www-form-urlencoded
                                MLOGD(
                                    "Found application/x-www-form-urlencoded "
                                    "content type");

                                PROCESS_ARGS(body_content, ctx,
                                             sign_rule_mg->get_match_context);

                        } else {
                                MLOGD(
                                    "Not found "
                                    "application/x-www-form-urlencoded content "
                                    "type in post body");
                        }
                } else {
                        MLOGD("Content-Type not found");
                }
        } while (0);

        MLOGD("Exiting body filter phase handler");
        // 继续处理请求
        ngx_http_finalize_request(r, NGX_OK);
}

ngx_int_t ngx_http_modsecurity_precontent_handler(ngx_http_request_t *r) {
        MLOGD("Entering precontent phase handler");
        ngx_modsec_ctx_t *ctx = ngx_http_modsecurity_get_ctx(r);
        if (ctx == NULL || sign_rule_mg == NULL) {
                // 内存耗尽，相当于Bypass
                MLOGE("sign_rule_mg or ngx_modsec_ctx is NULL");
                return NGX_DECLINED;
        }

        DO_CHECK_VARS(r->uri, HTTP_VAR_URI);
        DO_CHECK_VARS(r->unparsed_uri, HTTP_VAR_UNPARSED_URI);
        DO_CHECK_VARS(r->exten, HTTP_VAR_EXTEN);
        DO_CHECK_VARS(r->args, HTTP_VAR_QUERY_STRING);

        DO_CHECK_HEADER_VARS(host, HTTP_VAR_HOST);

        PROCESS_ARGS(r->args, ctx, sign_rule_mg->get_match_context);

        MLOGD("Starting to process headers");

        ITERATE_NGX_LIST(&r->headers_in.headers.part, header, ngx_table_elt_t, {
                CHECK_HTTP_PARAM_MATCH(header->key, header->value,
                                       sign_rule_mg->headers_match_context,
                                       ctx);
                DO_CHECK_VARS(header->value, HTTP_VAR_ALL_HEADER_VALUE);
        });

        MLOGD("Finished processing headers");

        // 读取请求体
        ngx_int_t rc = ngx_http_read_client_request_body(
            r, ngx_http_modsecurity_body_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
        }
        if (rc == NGX_AGAIN) {
                MLOGD("Waiting for body to be read");
                return NGX_DONE; // 告诉nginx等待body读取完成
        }

        // 放在结尾，准备上报日志
        traverse_rule_hits(ctx->rule_hit_rbtree);
        MLOGD("Exiting precontent phase handler");
        return NGX_OK;
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