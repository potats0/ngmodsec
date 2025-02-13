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
#include "ngx_vs_modsec_runtime.h"
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r,
                                                  ngx_chain_t *in) {
        MLOGD("entering modsecurity body filter");

        ngx_vs_modsec_ctx_t *usrdata = ngx_http_modsecurity_get_ctx(r);

        usrdata->request = r;
        
        return ngx_http_next_body_filter(r, in);
}

ngx_int_t ngx_http_modsecurity_body_filter_init() {
        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;
        return NGX_OK;
}
