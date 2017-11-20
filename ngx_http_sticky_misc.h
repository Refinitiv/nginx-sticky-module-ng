
/*
 * Copyright (C) 2010 Jerome Loyet (jerome at loyet dot net)
 */

#ifndef _NGX_HTTP_STICKY_MISC_H_INCLUDED_
#define _NGX_HTTP_STICKY_MISC_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>

typedef ngx_int_t (*ngx_http_sticky_misc_hash_pt)(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);
typedef ngx_int_t (*ngx_http_sticky_misc_hmac_pt)(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *key, ngx_str_t *digest);
typedef ngx_int_t (*ngx_http_sticky_misc_text_pt)(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);

ngx_int_t ngx_http_sticky_misc_set_cookie (ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires, unsigned secure, unsigned httponly);
ngx_int_t ngx_http_sticky_misc_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);
ngx_int_t ngx_http_sticky_misc_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);
ngx_int_t ngx_http_sticky_misc_hmac_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *key, ngx_str_t *digest);
ngx_int_t ngx_http_sticky_misc_hmac_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *key, ngx_str_t *digest);

ngx_int_t ngx_http_sticky_misc_text_raw(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest);

#endif /* _NGX_HTTP_STICKY_MISC_H_INCLUDED_ */
