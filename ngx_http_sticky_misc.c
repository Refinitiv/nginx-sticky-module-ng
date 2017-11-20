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

/* - fix for 1.11.2 removes include <openssl/md5.h> in ngx_md5.h */
#define MD5_CBLOCK  64
#define MD5_LBLOCK  (MD5_CBLOCK/4)
#define MD5_DIGEST_LENGTH 16

// /* - bugfix for compiling on sles11 - needs gcc4.6 or later*/
// #pragma GCC diagnostic ignored "-Wuninitialized"

static ngx_int_t cookie_expires(char *str, size_t size, time_t t)
{
  char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  char *wdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  struct tm  e;
  gmtime_r(&t, &e);
  return snprintf(str, size, "%s, %02d-%s-%04d %02d:%02d:%02d GMT",
    wdays[e.tm_wday], e.tm_mday, months[e.tm_mon], e.tm_year + 1900, e.tm_hour,e.tm_min,e.tm_sec);
}


ngx_int_t ngx_http_sticky_misc_set_cookie(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value, ngx_str_t *domain, ngx_str_t *path, time_t expires, unsigned secure, unsigned httponly)
{
  u_char  *cookie, *p;
  size_t  len;
  ngx_table_elt_t *set_cookie, *elt;
  ngx_str_t remove;
  ngx_list_part_t *part;
  ngx_uint_t i;
  char expires_str[80];

  int expires_len = 0;

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
  /*; Expires= */
  if (expires != NGX_CONF_UNSET) {
   expires_len = cookie_expires(expires_str, sizeof(expires_str), time(NULL) + expires);
   len += sizeof("; Expires=") - 1 + expires_len;
  }

  /* ; Path= */
  if (path->len > 0) {
    len += sizeof("; Path=") - 1 + path->len;
  }

  /* ; Secure */
  if (secure) {
    len += sizeof("; Secure") - 1;
  }

  /* ; HttpOnly */
  if (httponly) {
    len += sizeof("; HttpOnly") - 1;
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
    p = ngx_copy(p, "; Expires=", sizeof("; Expires=") - 1);
    p = ngx_copy(p, expires_str, expires_len);
  }

  if (path->len > 0) {
    p = ngx_copy(p, "; Path=", sizeof("; Path=") - 1);
    p = ngx_copy(p, path->data, path->len);
  }

  if (secure) {
    p = ngx_copy(p, "; Secure", sizeof("; Secure") - 1);
  }

  if (httponly) {
    p = ngx_copy(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
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

ngx_int_t ngx_http_sticky_misc_text_raw(ngx_pool_t *pool, void *in, size_t len, ngx_str_t *digest)
{
  if (!in) {
    return NGX_ERROR;
  }

  digest->data = ngx_pnalloc(pool, len);
  if (digest->data == NULL) {
    return NGX_ERROR;
  }
  memcpy(digest->data, in, len);
  digest->len = len;

  return NGX_OK;
}
