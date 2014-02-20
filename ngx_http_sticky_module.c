
/*
 * Copyright (C) Jerome Loyet <jerome at loyet dot net>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_sticky_misc.h"

/* define a peer */
typedef struct {
	ngx_http_upstream_rr_peer_t *rr_peer;
	ngx_str_t                    digest;
} ngx_http_sticky_peer_t;

/* the configuration structure */
typedef struct {
	ngx_http_upstream_srv_conf_t  uscf;
	ngx_str_t                     cookie_name;
	ngx_str_t                     cookie_domain;
	ngx_str_t                     cookie_path;
	time_t                        cookie_expires;
	ngx_str_t                     hmac_key;
	ngx_http_sticky_misc_hash_pt  hash;
	ngx_http_sticky_misc_hmac_pt  hmac;
	ngx_http_sticky_misc_text_pt  text;
	ngx_uint_t                    no_fallback;
	ngx_http_sticky_peer_t       *peers;
} ngx_http_sticky_srv_conf_t;


/* the custom sticky struct used on each request */
typedef struct {
	/* the round robin data must be first */
	ngx_http_upstream_rr_peer_data_t   rrp;
	ngx_event_get_peer_pt              get_rr_peer;
	int                                selected_peer;
	int                                no_fallback;
	ngx_http_sticky_srv_conf_t        *sticky_conf;
	ngx_http_request_t                *request;
} ngx_http_sticky_peer_data_t;


static ngx_int_t ngx_http_init_sticky_peer(ngx_http_request_t *r,	ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data);
static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_sticky_create_conf(ngx_conf_t *cf);


static ngx_command_t  ngx_http_sticky_commands[] = {

	{ ngx_string("sticky"),
		NGX_HTTP_UPS_CONF|NGX_CONF_ANY,
		ngx_http_sticky_set,
		0,
		0,
		NULL },

	ngx_null_command
};


static ngx_http_module_t  ngx_http_sticky_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	ngx_http_sticky_create_conf,           /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_sticky_module = {
	NGX_MODULE_V1,
	&ngx_http_sticky_module_ctx, /* module context */
	ngx_http_sticky_commands,    /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


/*
 * function called by the upstream module to init itself
 * it's called once per instance
 */
ngx_int_t ngx_http_init_upstream_sticky(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_rr_peers_t *rr_peers;
	ngx_http_sticky_srv_conf_t *conf;
	ngx_uint_t i;

	/* call the rr module on wich the sticky module is based on */
	if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
		return NGX_ERROR;
	}

	/* calculate each peer digest once and save */
	rr_peers = us->peer.data;

	/* do nothing there's only one peer */
	if (rr_peers->number <= 1 || rr_peers->single) {
		return NGX_OK;
	}

	/* tell the upstream module to call ngx_http_init_sticky_peer when it inits peer */
	us->peer.init = ngx_http_init_sticky_peer;

	conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);

	/* if 'index', no need to alloc and generate digest */
	if (!conf->hash && !conf->hmac && !conf->text) {
		conf->peers = NULL;
		return NGX_OK;
	}

	/* create our own upstream indexes */
	conf->peers = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_peer_t) * rr_peers->number);
	if (conf->peers == NULL) {
		return NGX_ERROR;
	}

	/* parse each peer and generate digest if necessary */
	for (i = 0; i < rr_peers->number; i++) {
		conf->peers[i].rr_peer = &rr_peers->peer[i];

		if (conf->hmac) {
			/* generate hmac */
			conf->hmac(cf->pool, rr_peers->peer[i].sockaddr, rr_peers->peer[i].socklen, &conf->hmac_key, &conf->peers[i].digest);

		} else if (conf->text) {
			/* generate text */
			conf->text(cf->pool, rr_peers->peer[i].sockaddr, &conf->peers[i].digest);

		} else {
			/* generate hash */
			conf->hash(cf->pool, rr_peers->peer[i].sockaddr, rr_peers->peer[i].socklen, &conf->peers[i].digest);
		}

#if 0
/* FIXME: is it possible to log to debug level when at configuration stage ? */
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "[sticky/ngx_http_init_upstream_sticky] generated digest \"%V\" for upstream at index %d", &conf->peers[i].digest, i);
#endif

	}

	return NGX_OK;
}

/*
 * function called by the upstream module when it inits each peer
 * it's called once per request
 */
static ngx_int_t ngx_http_init_sticky_peer(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_sticky_peer_data_t  *iphp;
	ngx_str_t                     route;
	ngx_uint_t                    i;
	ngx_int_t                     n;

	/* alloc custom sticky struct */
	iphp = ngx_palloc(r->pool, sizeof(ngx_http_sticky_peer_data_t));
	if (iphp == NULL) {
		return NGX_ERROR;
	}

	/* attach it to the request upstream data */
	r->upstream->peer.data = &iphp->rrp;

	/* call the rr module on which the sticky is based on */
	if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
		return NGX_ERROR;
	}

	/* set the callback to select the next peer to use */
	r->upstream->peer.get = ngx_http_get_sticky_peer;

	/* init the custom sticky struct */
	iphp->get_rr_peer = ngx_http_upstream_get_round_robin_peer;
	iphp->selected_peer = -1;
	iphp->no_fallback = 0;
	iphp->sticky_conf = ngx_http_conf_upstream_srv_conf(us, ngx_http_sticky_module);
	iphp->request = r;

	/* check weather a cookie is present or not and save it */
	if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &iphp->sticky_conf->cookie_name, &route) != NGX_DECLINED) {
		/* a route cookie has been found. Let's give it a try */
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] got cookie route=%V, let's try to find a matching peer", &route);

		/* hash, hmac or text, just compare digest */
		if (iphp->sticky_conf->hash || iphp->sticky_conf->hmac || iphp->sticky_conf->text) {

			/* check internal struct has been set */
			if (!iphp->sticky_conf->peers) {
				/* log a warning, as it will continue without the sticky */
				ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[sticky/init_sticky_peer] internal peers struct has not been set");
				return NGX_OK; /* return OK, in order to continue */
			}

			/* search the digest found in the cookie in the peer digest list */
			for (i = 0; i < iphp->rrp.peers->number; i++) {

				/* ensure the both len are equal and > 0 */
				if (iphp->sticky_conf->peers[i].digest.len != route.len || route.len <= 0) {
					continue;
				}

				if (!ngx_strncmp(iphp->sticky_conf->peers[i].digest.data, route.data, route.len)) {
					/* we found a match */
					iphp->selected_peer = i;
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] the route \"%V\" matches peer at index %ui", &route, i);
					return NGX_OK;
				}
			}

		} else {

			/* switch back to index, just convert to integer and ensure it corresponds to a valid peer */
			n = ngx_atoi(route.data, route.len);
			if (n == NGX_ERROR) {
				ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "[sticky/init_sticky_peer] unable to convert the route \"%V\" to an integer value", &route);
			} else if (n >= 0 && n < (ngx_int_t)iphp->rrp.peers->number) {
				/* found one */
				ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] the route \"%V\" matches peer at index %i", &route, n);
				iphp->selected_peer = n;
				return NGX_OK;
			}
		}

		/* nothing was found, just continue with rr */
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] the route \"%V\" does not match any peer. Just ignoring it ...", &route);
		return NGX_OK;
	}

	/* nothing found */
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[sticky/init_sticky_peer] route cookie not found", &route);
	return NGX_OK; /* return OK, in order to continue */
}

/*
 * function called by the upstream module to choose the next peer to use
 * called at least one time per request
 */
static ngx_int_t ngx_http_get_sticky_peer(ngx_peer_connection_t *pc, void *data)
{
	ngx_http_sticky_peer_data_t  *iphp = data;
	ngx_http_sticky_srv_conf_t   *conf = iphp->sticky_conf;
	ngx_int_t                     selected_peer = -1;
	time_t                        now = ngx_time();
	uintptr_t                     m;
	ngx_uint_t                    n, i;
	ngx_http_upstream_rr_peer_t  *peer = NULL;

	ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] get sticky peer, try: %ui, n_peers: %ui, no_fallback: %ui/%ui", pc->tries, iphp->rrp.peers->number, conf->no_fallback, iphp->no_fallback);

	/* TODO: cached */

	/* has the sticky module already choosen a peer to connect to and is it a valid peer */
	/* is there more than one peer (otherwise, no choices to make) */
	if (iphp->selected_peer >= 0 && iphp->selected_peer < (ngx_int_t)iphp->rrp.peers->number && !iphp->rrp.peers->single) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] let's try the selected peer (%i)", iphp->selected_peer);

		n = iphp->selected_peer / (8 * sizeof(uintptr_t));
		m = (uintptr_t) 1 << iphp->selected_peer % (8 * sizeof(uintptr_t));

		/* has the peer not already been tried ? */
		if (!(iphp->rrp.tried[n] & m)) {
			peer = &iphp->rrp.peers->peer[iphp->selected_peer];

			/* if the no_fallback flag is set */
			if (conf->no_fallback) {

				iphp->no_fallback = 1;

				/* if peer is down */
				if (peer->down) {
					ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] the selected peer is down and no_fallback is flagged");
					return NGX_BUSY;
				}

				/* if it's been ignored for long enought (fail_timeout), reset timeout */
				/* do this check before testing peer->fails ! :) */
				if (now - peer->accessed > peer->fail_timeout) {
					peer->fails = 0;
				}

				/* if peer is failed */
				if (peer->max_fails > 0 && peer->fails >= peer->max_fails) {
					ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] the selected peer is maked as failed and no_fallback is flagged");
					return NGX_BUSY;
				}
			}

			/* ensure the peer is not marked as down */
			if (!peer->down) {

				/* if it's not failedi, use it */
				if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
					selected_peer = (ngx_int_t)n;

				/* if it's been ignored for long enought (fail_timeout), reset timeout and use it */
				} else if (now - peer->accessed > peer->fail_timeout) {
					peer->fails = 0;
					selected_peer = (ngx_int_t)n;

				/* it's failed or timeout did not expire yet */
				} else {
					/* mark the peer as tried */
					iphp->rrp.tried[n] |= m;
				}
			}
		}
	}

	/* we have a valid peer, tell the upstream module to use it */
	if (peer && selected_peer >= 0) {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] peer found at index %i", selected_peer);

		iphp->rrp.current = iphp->selected_peer;
		pc->cached = 0;
		pc->connection = NULL;
		pc->sockaddr = peer->sockaddr;
		pc->socklen = peer->socklen;
		pc->name = &peer->name;

		iphp->rrp.tried[n] |= m;

	} else {
		ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] no sticky peer selected, switch back to classic rr");

		if (iphp->no_fallback) {
			ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "[sticky/get_sticky_peer] No fallback in action !");
			return NGX_BUSY;
		}

		ngx_int_t ret = iphp->get_rr_peer(pc, &iphp->rrp);
		if (ret != NGX_OK) {
			ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] ngx_http_upstream_get_round_robin_peer returned %i", ret);
			return ret;
		}

		/* search for the choosen peer in order to set the cookie */
		for (i = 0; i < iphp->rrp.peers->number; i++) {

			if (iphp->rrp.peers->peer[i].sockaddr == pc->sockaddr && iphp->rrp.peers->peer[i].socklen == pc->socklen) {
				if (conf->hash || conf->hmac || conf->text) {
					ngx_http_sticky_misc_set_cookie(iphp->request, &conf->cookie_name, &conf->peers[i].digest, &conf->cookie_domain, &conf->cookie_path, conf->cookie_expires);
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] set cookie \"%V\" value=\"%V\" index=%ui", &conf->cookie_name, &conf->peers[i].digest, i);
				} else {
					ngx_str_t route;
					ngx_uint_t tmp = i;
					route.len = 0;
					do {
						route.len++;
					} while (tmp /= 10);
					route.data = ngx_pcalloc(iphp->request->pool, sizeof(u_char) * (route.len + 1));
					if (route.data == NULL) {
						break;
					}
					ngx_snprintf(route.data, route.len, "%d", i);
					route.len = ngx_strlen(route.data);
					ngx_http_sticky_misc_set_cookie(iphp->request, &conf->cookie_name, &route, &conf->cookie_domain, &conf->cookie_path, conf->cookie_expires);
					ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "[sticky/get_sticky_peer] set cookie \"%V\" value=\"%V\" index=%ui", &conf->cookie_name, &tmp, i);
				}
				break; /* found and hopefully the cookie have been set */
			}
		}
	}

	/* reset the selection in order to bypass the sticky module when the upstream module will try another peers if necessary */
	iphp->selected_peer = -1;

	return NGX_OK;
}

/*
 * Function called when the sticky command is parsed on the conf file
 */
static char *ngx_http_sticky_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_srv_conf_t  *upstream_conf;
	ngx_http_sticky_srv_conf_t    *sticky_conf;
	ngx_uint_t i;
	ngx_str_t tmp;
	ngx_str_t name = ngx_string("route");
	ngx_str_t domain = ngx_string("");
	ngx_str_t path = ngx_string("");
	ngx_str_t hmac_key = ngx_string("");
	time_t expires = NGX_CONF_UNSET;
	ngx_http_sticky_misc_hash_pt hash = NGX_CONF_UNSET_PTR;
	ngx_http_sticky_misc_hmac_pt hmac = NULL;
	ngx_http_sticky_misc_text_pt text = NULL;
	ngx_uint_t no_fallback = 0;

	/* parse all elements */
	for (i = 1; i < cf->args->nelts; i++) {
		ngx_str_t *value = cf->args->elts;

		/* is "name=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "name=") == value[i].data) {

			/* do we have at least on char after "name=" ? */
			if (value[i].len <= sizeof("name=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"name=\"");
				return NGX_CONF_ERROR;
			}

			/* save what's after "name=" */
			name.len = value[i].len - ngx_strlen("name=");
			name.data = (u_char *)(value[i].data + sizeof("name=") - 1);
			continue;
		}

		/* is "domain=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "domain=") == value[i].data) {

			/* do we have at least on char after "domain=" ? */
			if (value[i].len <= ngx_strlen("domain=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"domain=\"");
				return NGX_CONF_ERROR;
			}

			/* save what's after "domain=" */
			domain.len = value[i].len - ngx_strlen("domain=");
			domain.data = (u_char *)(value[i].data + sizeof("domain=") - 1);
			continue;
		}

		/* is "path=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "path=") == value[i].data) {

			/* do we have at least on char after "path=" ? */
			if (value[i].len <= ngx_strlen("path=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"path=\"");
				return NGX_CONF_ERROR;
			}

			/* save what's after "domain=" */
			path.len = value[i].len - ngx_strlen("path=");
			path.data = (u_char *)(value[i].data + sizeof("path=") - 1);
			continue;
		}

		/* is "expires=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "expires=") == value[i].data) {

			/* do we have at least on char after "expires=" ? */
			if (value[i].len <= sizeof("expires=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"expires=\"");
				return NGX_CONF_ERROR;
			}

			/* extract value */
			tmp.len =  value[i].len - ngx_strlen("expires=");
			tmp.data = (u_char *)(value[i].data + sizeof("expires=") - 1);

			/* convert to time, save and validate */
			expires = ngx_parse_time(&tmp, 1);
			if (expires == NGX_ERROR || expires < 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value for \"expires=\"");
				return NGX_CONF_ERROR;
			}
			continue;
		}

		/* is "text=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "text=") == value[i].data) {

			/* only hash or hmac can be used, not both */
			if (hmac || hash != NGX_CONF_UNSET_PTR) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "please choose between \"hash=\", \"hmac=\" and \"text\"");
				return NGX_CONF_ERROR;
			}

			/* do we have at least on char after "name=" ? */
			if (value[i].len <= sizeof("text=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"text=\"");
				return NGX_CONF_ERROR;
			}

			/* extract value to temp */
			tmp.len =  value[i].len - ngx_strlen("text=");
			tmp.data = (u_char *)(value[i].data + sizeof("text=") - 1);

			/* is name=raw */
			if (ngx_strncmp(tmp.data, "raw", sizeof("raw") - 1) == 0 ) {
				text = ngx_http_sticky_misc_text_raw;
				continue;
			}

			/* is name=md5 */
			if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0 ) {
				text = ngx_http_sticky_misc_text_md5;
				continue;
			}

			/* is name=sha1 */
			if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0 ) {
				text = ngx_http_sticky_misc_text_sha1;
				continue;
			}

			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "wrong value for \"text=\": raw, md5 or sha1");
			return NGX_CONF_ERROR;
		}

		/* is "hash=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "hash=") == value[i].data) {

			/* only hash or hmac can be used, not both */
			if (hmac || text) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "please choose between \"hash=\", \"hmac=\" and \"text=\"");
				return NGX_CONF_ERROR;
			}

			/* do we have at least on char after "hash=" ? */
			if (value[i].len <= sizeof("hash=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"hash=\"");
				return NGX_CONF_ERROR;
			}

			/* extract value to temp */
			tmp.len =  value[i].len - ngx_strlen("hash=");
			tmp.data = (u_char *)(value[i].data + sizeof("hash=") - 1);

			/* is hash=index */
			if (ngx_strncmp(tmp.data, "index", sizeof("index") - 1) == 0 ) {
				hash = NULL;
				continue;
			}

			/* is hash=md5 */
			if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0 ) {
				hash = ngx_http_sticky_misc_md5;
				continue;
			}

			/* is hash=sha1 */
			if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0 ) {
				hash = ngx_http_sticky_misc_sha1;
				continue;
			}

			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "wrong value for \"hash=\": index, md5 or sha1");
			return NGX_CONF_ERROR;
		}

		/* is "hmac=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "hmac=") == value[i].data) {

			/* only hash or hmac can be used, not both */
			if (hash != NGX_CONF_UNSET_PTR || text) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "please choose between \"hash=\", \"hmac=\" and \"text\"");
				return NGX_CONF_ERROR;
			}

			/* do we have at least on char after "hmac=" ? */
			if (value[i].len <= sizeof("hmac=") - 1) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"hmac=\"");
				return NGX_CONF_ERROR;
			}

			/* extract value */
			tmp.len =  value[i].len - ngx_strlen("hmac=");
			tmp.data = (u_char *)(value[i].data + sizeof("hmac=") - 1);

			/* is hmac=md5 ? */
			if (ngx_strncmp(tmp.data, "md5", sizeof("md5") - 1) == 0 ) {
				hmac = ngx_http_sticky_misc_hmac_md5;
				continue;
			}

			/* is hmac=sha1 ? */
			if (ngx_strncmp(tmp.data, "sha1", sizeof("sha1") - 1) == 0 ) {
				hmac = ngx_http_sticky_misc_hmac_sha1;
				continue;
			}
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "wrong value for \"hmac=\": md5 or sha1");
			return NGX_CONF_ERROR;
		}

		/* is "hmac_key=" is starting the argument ? */
		if ((u_char *)ngx_strstr(value[i].data, "hmac_key=") == value[i].data) {

			/* do we have at least on char after "hmac_key=" ? */
			if (value[i].len <= ngx_strlen("hmac_key=")) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "a value must be provided to \"hmac_key=\"");
				return NGX_CONF_ERROR;
			}

			/* save what's after "hmac_key=" */
			hmac_key.len = value[i].len - ngx_strlen("hmac_key=");
			hmac_key.data = (u_char *)(value[i].data + sizeof("hmac_key=") - 1);
			continue;
		}

		/* is "no_fallback" flag present ? */
		if (ngx_strncmp(value[i].data, "no_fallback", sizeof("no_fallback") - 1) == 0 ) {
			no_fallback = 1;
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid arguement (%V)", &value[i]);
		return NGX_CONF_ERROR;
	}

	/* if has and hmac and name have not been set, default to md5 */
	if (hash == NGX_CONF_UNSET_PTR && hmac == NULL && text == NULL) {
		hash = ngx_http_sticky_misc_md5;
	}

	/* don't allow meaning less parameters */
	if (hmac_key.len > 0 && hash != NGX_CONF_UNSET_PTR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"hmac_key=\" is meaningless when \"hmac\" is used. Please remove it.");
		return NGX_CONF_ERROR;
	}

	/* ensure we have an hmac key if hmac's been set */
	if (hmac_key.len == 0 && hmac != NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "please specify \"hmac_key=\" when using \"hmac\"");
		return NGX_CONF_ERROR;
	}

	/* ensure hash is NULL to avoid conflicts later */
	if (hash == NGX_CONF_UNSET_PTR) {
		hash = NULL;
	}

	/* save the sticky parameters */
	sticky_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_sticky_module);
	sticky_conf->cookie_name = name;
	sticky_conf->cookie_domain = domain;
	sticky_conf->cookie_path = path;
	sticky_conf->cookie_expires = expires;
	sticky_conf->hash = hash;
	sticky_conf->hmac = hmac;
	sticky_conf->text = text;
	sticky_conf->hmac_key = hmac_key;
	sticky_conf->no_fallback = no_fallback;
	sticky_conf->peers = NULL; /* ensure it's null before running */

	upstream_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

	/* 
	 * ensure another upstream module has not been already loaded
	 * peer.init_upstream is set to null and the upstream module use RR if not set
	 * But this check only works when the other module is declared before sticky
	 */
	if (upstream_conf->peer.init_upstream) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "You can't use sticky with another upstream module");
		return NGX_CONF_ERROR;
	}

	/* configure the upstream to get back to this module */
	upstream_conf->peer.init_upstream = ngx_http_init_upstream_sticky;

	upstream_conf->flags = NGX_HTTP_UPSTREAM_CREATE
		| NGX_HTTP_UPSTREAM_MAX_FAILS
		| NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
		| NGX_HTTP_UPSTREAM_DOWN
    | NGX_HTTP_UPSTREAM_WEIGHT;

	return NGX_CONF_OK;
}

/*
 * alloc stick configuration
 */
static void *ngx_http_sticky_create_conf(ngx_conf_t *cf)
{
	ngx_http_sticky_srv_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sticky_srv_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}

	return conf;
}
