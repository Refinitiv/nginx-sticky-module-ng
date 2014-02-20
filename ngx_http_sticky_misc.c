
/*
 * Copyright (C) 2010 Jerome Loyet (jerome at loyet dot net)
 */

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>

#include "ngx_http_sticky_misc.h"

#ifndef ngx_str_set
	#define ngx_str_set(str, text) (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#endif

ngx_int_t ngx_http_sticky_misc_set_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires)
{
	u_char  *cookie, *p;
	size_t  len;
	ngx_table_elt_t *set_cookie, *elt;
	ngx_str_t remove;
	ngx_list_part_t *part;
	ngx_uint_t i;

	if (value == NULL) {
		ngx_str_set(&remove, "_remove_");
		value = &remove;
	}

	/*    name        =   value */
	len = name->len + 1 + value->len;

	/*; Domain= */
	if (domain->len > 0) {
		len += sizeof("; Domain=") - 1 + domain->len;
	}

	/*; Max-Age= */
	if (expires != NGX_CONF_UNSET) {
		len += sizeof("; Max-Age=") - 1 + NGX_TIME_T_LEN;
	}

	/* ; Path= */
	if (path->len > 0) {
		len += sizeof("; Path=") - 1 + path->len;
	}

	cookie = ngx_pnalloc(r->pool, len);	
	if (cookie == NULL) {
		return NGX_ERROR;
	}

	p = ngx_copy(cookie, name->data, name->len);
	*p++ = '=';
	p = ngx_copy(p, value->data, value->len);

	if (domain->len > 0) {
		p = ngx_copy(p, "; Domain=", sizeof("; Domain=") - 1);	
		p = ngx_copy(p, domain->data, domain->len);
	}

	if (expires != NGX_CONF_UNSET) {
		p = ngx_copy(p, "; Max-Age=", sizeof("; Max-Age=") - 1);
		p = ngx_snprintf(p, NGX_TIME_T_LEN, "%T", expires);
	}

	if (path->len > 0) {
		p = ngx_copy(p, "; Path=", sizeof("; Path=") - 1);	
		p = ngx_copy(p, path->data, path->len);
	}

	part = &r->headers_out.headers.part;
	elt = part->elts;
	set_cookie = NULL;

	for (i=0 ;; i++) {
		if (part->nelts > 1 || i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}
			part = part->next;
			elt = part->elts;
			i = 0;
		}
		/* ... */
		if (ngx_strncmp(elt->value.data, name->data, name->len) == 0) {
			set_cookie = elt;
			break;
		}
	}

	/* found a Set-Cookie header with the same name: replace it */
	if (set_cookie != NULL) {
		set_cookie->value.len = p - cookie;
		set_cookie->value.data = cookie;
		return NGX_OK;
	}

	set_cookie = ngx_list_push(&r->headers_out.headers);
	if (set_cookie == NULL) {
		return NGX_ERROR;
	}
	set_cookie->hash = 1;
	ngx_str_set(&set_cookie->key, "Set-Cookie");
	set_cookie->value.len = p - cookie;
	set_cookie->value.data = cookie;

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest)
{
	ngx_md5_t md5;
	u_char hash[MD5_DIGEST_LENGTH];

	digest->data = ngx_pcalloc(pool, MD5_DIGEST_LENGTH * 2);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}

	digest->len = MD5_DIGEST_LENGTH * 2;
	ngx_md5_init(&md5);
	ngx_md5_update(&md5, in, len);
	ngx_md5_final(hash, &md5);

	ngx_hex_dump(digest->data, hash, MD5_DIGEST_LENGTH);
	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest)
{
	ngx_sha1_t sha1;
	u_char hash[SHA_DIGEST_LENGTH];

	digest->data = ngx_pcalloc(pool, SHA_DIGEST_LENGTH * 2);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}

	digest->len = SHA_DIGEST_LENGTH * 2;
	ngx_sha1_init(&sha1);
	ngx_sha1_update(&sha1, in, len);
	ngx_sha1_final(hash, &sha1);

	ngx_hex_dump(digest->data, hash, SHA_DIGEST_LENGTH);
	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_hmac_md5(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *key, ngx_str_t *digest)
{
	u_char hash[MD5_DIGEST_LENGTH];
	u_char k[MD5_CBLOCK];
	ngx_md5_t md5;
	u_int i;

	digest->data = ngx_pcalloc(pool, MD5_DIGEST_LENGTH * 2);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}
	digest->len = MD5_DIGEST_LENGTH * 2;

	ngx_memzero(k, sizeof(k));

	if (key->len > MD5_CBLOCK) {
		ngx_md5_init(&md5);
		ngx_md5_update(&md5, key->data, key->len);
		ngx_md5_final(k, &md5);
	} else {
		ngx_memcpy(k, key->data, key->len);
	}

	/* XOR ipad */
	for (i=0; i < MD5_CBLOCK; i++) {
		k[i] ^= 0x36;
	}

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, k, MD5_CBLOCK);
	ngx_md5_update(&md5, in, len);
	ngx_md5_final(hash, &md5);

	/* Convert k to opad -- 0x6A = 0x36 ^ 0x5C */
	for (i=0; i < MD5_CBLOCK; i++) {
		k[i] ^= 0x6a;
	}

	ngx_md5_init(&md5);
	ngx_md5_update(&md5, k, MD5_CBLOCK);
	ngx_md5_update(&md5, hash, MD5_DIGEST_LENGTH);
	ngx_md5_final(hash, &md5);

	ngx_hex_dump(digest->data, hash, MD5_DIGEST_LENGTH);

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_hmac_sha1(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *key, ngx_str_t *digest)
{
	u_char hash[SHA_DIGEST_LENGTH];
	u_char k[SHA_CBLOCK];
	ngx_sha1_t sha1;
	u_int i;

	digest->data = ngx_pcalloc(pool, SHA_DIGEST_LENGTH * 2);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}
	digest->len = SHA_DIGEST_LENGTH * 2;

	ngx_memzero(k, sizeof(k));

	if (key->len > SHA_CBLOCK) {
		ngx_sha1_init(&sha1);
		ngx_sha1_update(&sha1, key->data, key->len);
		ngx_sha1_final(k, &sha1);
	} else {
		ngx_memcpy(k, key->data, key->len);
	}

	/* XOR ipad */
	for (i=0; i < SHA_CBLOCK; i++) {
		k[i] ^= 0x36;
	}

	ngx_sha1_init(&sha1);
	ngx_sha1_update(&sha1, k, SHA_CBLOCK);
	ngx_sha1_update(&sha1, in, len);
	ngx_sha1_final(hash, &sha1);

	/* Convert k to opad -- 0x6A = 0x36 ^ 0x5C */
	for (i=0; i < SHA_CBLOCK; i++) {
		k[i] ^= 0x6a;
	}

	ngx_sha1_init(&sha1);
	ngx_sha1_update(&sha1, k, SHA_CBLOCK);
	ngx_sha1_update(&sha1, hash, SHA_DIGEST_LENGTH);
	ngx_sha1_final(hash, &sha1);

	ngx_hex_dump(digest->data, hash, SHA_DIGEST_LENGTH);

	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_text_raw(ngx_pool_t *pool, struct sockaddr *in, ngx_str_t *digest)
{
	size_t len;
	if (!in) {
		return NGX_ERROR;
	}

	switch (in->sa_family) {
		case AF_INET:
			len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
			break;

#if (NGX_HAVE_INET6)
		case AF_INET6:
			len = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
			break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
		case AF_UNIX:
			len = sizeof("unix:") - 1 + NGX_UNIX_ADDRSTRLEN;
			break;
#endif

		default:
			return NGX_ERROR;
	}


	digest->data = ngx_pnalloc(pool, len);
	if (digest->data == NULL) {
		return NGX_ERROR;
	}
	digest->len = ngx_sock_ntop(in, digest->data, len, 1);
	return NGX_OK;
	return NGX_OK;
}

ngx_int_t ngx_http_sticky_misc_text_md5(ngx_pool_t *pool, struct sockaddr *in, ngx_str_t *digest)
{
	ngx_str_t str;
	if (ngx_http_sticky_misc_text_raw(pool, in, &str) != NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_http_sticky_misc_md5(pool, (void *)str.data, str.len, digest) != NGX_OK) {
		ngx_pfree(pool, &str);
		return NGX_ERROR;
	}

	return ngx_pfree(pool, &str);
}

ngx_int_t ngx_http_sticky_misc_text_sha1(ngx_pool_t *pool, struct sockaddr *in, ngx_str_t *digest)
{
	ngx_str_t str;
	if (ngx_http_sticky_misc_text_raw(pool, in, &str) != NGX_OK) {
		return NGX_ERROR;
	}

	if (ngx_http_sticky_misc_sha1(pool, (void *)str.data, str.len, digest) != NGX_OK) {
		ngx_pfree(pool, &str);
		return NGX_ERROR;
	}

	return ngx_pfree(pool, &str);
}

