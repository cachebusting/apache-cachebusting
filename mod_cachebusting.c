#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <http_core.h>
#include <http_request.h>
#include <ap_config.h>
#include <ap_regex.h>
#include <apr_strings.h>
#include <apr_buckets.h>
#include <apr_hash.h>
#include <util_filter.h>
#include <apr_lib.h>

#define DISABLED    2
#define ENABLED     1

#define CB_UPDATE_HASH   (1<<1)
#define CB_ADD_HEADER    (1<<2)
#define CB_HAPPENING_NAME "happening"

#define CACHEBUSTING_PATTERN "img(?: )+src=['\"](.*?)['\"]"

static ap_filter_rec_t *cachebusting_add_header_filter;
static ap_filter_rec_t *cachebusting_add_hash_filter;
static ap_filter_rec_t *cachebusting_rewrite_html_filter;

module AP_MODULE_DECLARE_DATA cachebusting_module;

/* {{{ Structure to hold the config */
typedef struct _cachebusting_server_conf {
	int state;              /* State of the module                                */
	unsigned int lifetime;  /* Lifetime for cachebusting caches, default 15724800 */
	char* prefix;           /* Prefix for cachebusting assets, default cb         */
} cachebusting_server_conf;
/* }}} */

/* {{{ Thread-shared structure */
typedef struct _cachebusting_struct {
	ap_regex_t* compiled;   /* Regex to rewrite HTML                              */
	apr_pool_t* pool;		/* Pool to register the values in                     */
	apr_hash_t* hash;       /* The key/value pairs for cachebusting hashes        */
} cachebusting_struct;
/* }}} */

static cachebusting_struct *cb;

/* {{{ Cachebusting initialisation */
static void cachebusting_init(apr_pool_t *child, server_rec *s) 
{
	/* Create thread-safe data structure 
	 * Lives as long as the process itself
	 *
	 * *Note:* Do not read and write in the same thread and get rid of the mutex 
	 *
	 * No error handling neccessary - if it fails it becomes an unrecoverable state anyways */
	cb = apr_pcalloc(s->process->pool, sizeof(cachebusting_struct));
	apr_pool_create(&cb->pool, s->process->pool);
	cb->compiled = ap_pregcomp(cb->pool, CACHEBUSTING_PATTERN, AP_REG_EXTENDED);
	cb->hash = apr_hash_make(s->process->pool);
}
/* }}} */

/* {{{ Create the cachebusting server config */
static void *create_cachebusting_server_conf(apr_pool_t *p, server_rec *s)
{
	cachebusting_server_conf *sconf = apr_pcalloc(s->process->pool, sizeof(cachebusting_server_conf));
	sconf->state = DISABLED;
	sconf->prefix = apr_pstrndup(p, "cb", 2);

	return sconf;
}
/* }}} */

/* {{{ Command to enable/disable cachebusting */
static const char* cmd_cachebusting(cmd_parms *cmd, void *in_dconf, int flag) 
{
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	sconf->state = (flag ? ENABLED : DISABLED);

	return NULL;
}
/* }}} */

/* {{{ Set the prefix for cachebusting elements, default 'cb' */
static const char* cmd_cachebusting_prefix(cmd_parms *cmd, void *in_dconf, char* prefix)
{
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	if (sconf->state) sconf->prefix = prefix;

	return NULL;
}
/* }}} */

/* {{{ Set the lifetime for cachebusting caches, default '15724800' */
static const char* cmd_cachebusting_lifetime(cmd_parms *cmd, void *in_dconf, char* lifetime)
{
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	if (sconf->state) sconf->lifetime = atoi(lifetime);

	return NULL;
}
/* }}} */

/* {{{ Defined commands */
static const command_rec cachebusting_cmds[] = {
	AP_INIT_FLAG("Cachebusting", cmd_cachebusting, NULL, RSRC_CONF,
			"Whether to enable or disable cachebusting"),
	AP_INIT_TAKE1("CachebustingPrefix", cmd_cachebusting_prefix, NULL, RSRC_CONF,
			"Prefix for cachebusting elements, default 'cb'"),
	AP_INIT_TAKE1("CachebustingLifetime", cmd_cachebusting_lifetime, NULL, RSRC_CONF,
			"Lifetime for cachebusting caches, default '15724800'"),
	{NULL}
};
/* }}} */

/* {{{ Set HTTP Metadata cover sheet for cachebusting */
static apr_status_t cachebusting_header_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	char* timestr;
	apr_time_t expires;
	cachebusting_server_conf *sconf;

	sconf = ap_get_module_config(f->r->server->module_config, &cachebusting_module);
	apr_table_t *headers_out = f->r->headers_out;

	/* Maybe we need to add public here too */
	apr_table_mergen(headers_out, "Cache-Control", 
			apr_psprintf(f->r->pool, "max-age=%" APR_TIME_T_FMT, sconf->lifetime));
	timestr = apr_palloc(f->r->pool, APR_RFC822_DATE_LEN);

	/* Calculate correct formatted expires string */
	expires = f->r->request_time+apr_time_from_sec(sconf->lifetime);
	apr_rfc822_date(timestr, expires);
	apr_table_setn(headers_out, "Expires", timestr);

	/* Remove filter and go to the next one in the pipe */
	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb) ;
}
/* }}} */

/* {{{ Add hash of delivered image to table  */
static apr_status_t cachebusting_hash_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(f->r->server->module_config, &cachebusting_module);
	apr_status_t rv;
	
	/* TODO: use apr_time_sec() instead
	 * microseconds for browsercaching seems ... Oversized 
	 *
	 * However, apt_time_t is an int64 and need a conversion to char* 
	 * */
	/* Add to r->notes instead of this hash for cluster capability
	 * Needs to be sent on the logging phase after the response */
	char* found = ap_strstr_c(f->r->unparsed_uri, sconf->prefix);
	char* hash = NULL;
	int mtime = 0;

	if (found) {
		hash = apr_palloc(f->r->pool, strlen(found) - strlen(sconf->prefix));
		strncpy(hash, found + strlen(sconf->prefix), strlen(found) - strlen(sconf->prefix));
		hash[strlen(found) - strlen(sconf->prefix)] = 0;
		mtime = apr_time_sec(f->r->finfo.mtime);
	}
	/* Only write the hash if it has changed */	
	if (!found || atoi(hash) != mtime) {
		apr_hash_set(cb->hash, apr_pstrdup(cb->pool, f->r->uri), APR_HASH_KEY_STRING, apr_itoa(cb->pool, apr_time_sec(f->r->finfo.mtime)));
	}

	/* Remove filter and go to the next one in the pipe */
	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb) ;
}
/* }}} */

/* {{{ Rewrite HTML content */
static apr_status_t cachebusting_html_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	cachebusting_server_conf *sconf;
	apr_bucket *bucket, *out;
	apr_status_t rv;
	ap_regmatch_t regm[AP_MAX_REG_MATCH];

	sconf = ap_get_module_config(f->r->server->module_config, &cachebusting_module);

	for (bucket = APR_BRIGADE_FIRST(bb);
		 bucket != APR_BRIGADE_SENTINEL(bb);
		 bucket = APR_BUCKET_NEXT(bucket)) {
		char* buf;
		size_t bytes;
		const char* data;

		if (APR_BUCKET_IS_EOS(bucket)) {
			/* Ignore */
		} else if (APR_BUCKET_IS_METADATA(bucket)) {
			/* Ignore */	
		} else if (apr_bucket_read(bucket, &data, &bytes, APR_BLOCK_READ) == APR_SUCCESS) {
			char *filename;
			int length = 0;

			while (!ap_regexec(cb->compiled, data, AP_MAX_REG_MATCH, regm, 0)) {
				/* Split off the bucket till the first char of the match */
				length = regm[1].rm_so;
				rv = apr_bucket_split(bucket, length);
				if (rv == APR_SUCCESS) {
					/* and jump to the next one */
					bucket = APR_BUCKET_NEXT(bucket);
				}

				/* Filename to look for */
				char *tmp = apr_pstrndup(f->r->pool, &data[regm[1].rm_so], regm[1].rm_eo - regm[1].rm_so);
				if (*tmp != '/') {
					tmp = apr_pstrcat(f->r->pool, "/", tmp, NULL);
				}
				char *hash = apr_hash_get(cb->hash, tmp, APR_HASH_KEY_STRING);
				if (hash) {
					filename = apr_pstrcat(f->r->pool, tmp, ";", sconf->prefix, hash, NULL);
					/* Create a new bucket */
					out = apr_bucket_pool_create(filename, strlen(filename), f->r->pool, f->r->connection->bucket_alloc);
					APR_BUCKET_INSERT_BEFORE(bucket, out);
				
					/* Remove current name */
					int length = regm[1].rm_eo - regm[1].rm_so;
					rv = apr_bucket_split(bucket, length);
					if (rv == APR_SUCCESS) {
						APR_BUCKET_REMOVE(bucket);
						bucket = APR_BUCKET_NEXT(bucket);
					} 
				}
				/* Read bucket again or break the loop */
				if (apr_bucket_read(bucket, &data, &bytes, APR_BLOCK_READ) != APR_SUCCESS) {
					break;
				}
			} 
		}
	}

	/* Pass module brigade */
	return ap_pass_brigade(f->next, bb) ;
}
/* }}} */

/* {{{ Strip ;prefixHash from the request path and resolve to
 * local file */
static int resolve_cachebusting_name(request_rec *r) 
{
	/* Skip if request doesn't start with / and first character isn't NULL */
	if (r->uri[0] != '/' && r->uri[0] != '\0') {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03461) "Wrong request type");
		return DECLINED;
	}
	
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(r->server->module_config, &cachebusting_module);

	/* Skip if not enabled */
	if (!sconf || sconf->state == DISABLED) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03462) "Disabled");
		return DECLINED;
	}

	char *prefix, *found;
	int happening = 0, res;
	prefix = apr_pstrcat(r->pool, ";", sconf->prefix, NULL);
	happening |= CB_UPDATE_HASH;

	/* Skip if prefix not found */
	if ((found = ap_strstr_c(r->uri, prefix)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03463) "Prefix not found");
		apr_table_setn(r->notes, CB_HAPPENING_NAME, apr_itoa(r->pool, happening));
		return DECLINED;
	}

	happening |= CB_ADD_HEADER;
	/* Use the core translator after modifying the uri from the request */
	char* new_filename = apr_palloc(r->pool, found - r->uri + 1);
	strncpy(new_filename, r->uri, found - r->uri);
	new_filename[found - r->uri] = 0;
	/* Check if mod_rewrite and mod_alias still work as expected */
	r->uri = new_filename;
	apr_table_setn(r->notes, CB_HAPPENING_NAME, apr_itoa(r->pool, happening));
	res = ap_core_translate(r);

	return res;
}
/* }}} */

/* {{{ Add filters */
static void cachebusting_insert_filter(request_rec* r)
{
	/* Don't add Expires headers to errors */
	if (ap_is_HTTP_ERROR(r->status)) {
		return;
	}

	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(r->server->module_config, &cachebusting_module);

	/* Skip if not enabled */
	if (!sconf || sconf->state == DISABLED) {
		return;
	}

	char *prefix, *found;
	int happening = NULL;
	prefix = apr_pstrcat(r->pool, ";", sconf->prefix, NULL);
	found = strstr(r->uri, prefix);
	happening = atoi(apr_table_get(r->notes, CB_HAPPENING_NAME));

	/* Check if content type is an image and headers should be appended */
	if (r->content_type && !strncmp(r->content_type, "image", 5) && (happening & CB_ADD_HEADER)) {
		ap_add_output_filter_handle(cachebusting_add_header_filter, NULL, r, r->connection);
	}

	/* Check if content type is an image and hash should be updated */
	if (r->content_type && !strncmp(r->content_type, "image", 5) && (happening & CB_UPDATE_HASH)) {
		ap_add_output_filter_handle(cachebusting_add_hash_filter, NULL, r, r->connection);
		return;
	}

	if (r->content_type && !strncmp(r->content_type, "text/html", 9)) {
		ap_add_output_filter_handle(cachebusting_rewrite_html_filter, NULL, r, r->connection);
		return;
	}
}
/* }}} */

/* {{{ Register hooks into runtime */
static void cachebusting_hooks(apr_pool_t *pool) 
{
	/* TODO: Let mod_alias and mod_rewrite run before mod_cachebusting
	 * to ensure the functionality will stack 
	 *
	 * How to do it:
	 * Add a new dependency array for cachebusting_insert_filter that includes
	 * http_core, mod_mime, mod_alias and mod_rewrite
	 *
	 * Translate_name need to run really first, to ensure the hashed are stripped once
	 * it comes to mod_alias or mod_rewrite. 
	 * Need to check which value needs modification for that
	 *
	 * Alias /foo.png /bar.png
	 *
	 * Should deliver /bar.png if request looks like host/foo.png;cb123456 */
	static const char * const aszPre[] = { "http_core.c", "mod_mime.c", NULL };

	/* Create filter handles */
	cachebusting_add_header_filter = 
		ap_register_output_filter("MOD_CACHEBUSTING_HEADER", cachebusting_header_filter, NULL, AP_FTYPE_RESOURCE); 

	cachebusting_add_hash_filter = 
		ap_register_output_filter("MOD_CACHEBUSTING_HASH", cachebusting_hash_filter, NULL, AP_FTYPE_RESOURCE);

	cachebusting_rewrite_html_filter =
		ap_register_output_filter("MOD_CACHEBUSTING_HTML", cachebusting_html_filter, NULL, AP_FTYPE_RESOURCE);

	ap_hook_child_init(cachebusting_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_translate_name(resolve_cachebusting_name, NULL, aszPre, APR_HOOK_MIDDLE);
	ap_hook_insert_filter(cachebusting_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
}
/* }}} */

module AP_MODULE_DECLARE_DATA cachebusting_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                               /* create per server config structure   */
	NULL,                               /* merge per dir config structure       */
	create_cachebusting_server_conf,    /* create per server config structure   */
	NULL,                               /* merge per server config structure    */
	cachebusting_cmds,                  /* table of config file commands        */
	cachebusting_hooks                  /* register hooks                       */
} ;

