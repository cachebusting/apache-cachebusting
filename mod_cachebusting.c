#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <http_core.h>
#include <http_request.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <apr_hash.h>
#include <util_filter.h>

#define DISABLED    2
#define ENABLED     1

static ap_filter_rec_t *cachebusting_add_header_filter;
static ap_filter_rec_t *cachebusting_add_hash_filter;

module AP_MODULE_DECLARE_DATA cachebusting_module;

/* {{{ Structure to hold the config */
typedef struct _cachebusting_server_conf {
	int state;              /* State of the module                                */
	unsigned int lifetime;  /* Lifetime for cachebusting caches, default 15724800 */
	char* prefix;           /* Prefix for cachebusting assets, default cb         */
	apr_hash_t* hash;       /* The key/value pairs for cachebusting hashes        */
} cachebusting_server_conf;
/* }}} */

/* {{{ Create the cachebusting server config */
static void *create_cachebusting_server_conf(apr_pool_t *p, server_rec *s)
{
    cachebusting_server_conf *sconf = apr_pcalloc(p, sizeof(cachebusting_server_conf));
    sconf->state = DISABLED;

    return sconf;
}
/* }}} */

/* {{{ Command to enable/disable cachebusting */
static const char* cmd_cachebusting(cmd_parms *cmd, void *in_dconf, int flag) 
{
	cachebusting_server_conf *sconf;

	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	sconf->state = (flag ? ENABLED : DISABLED);
	if (sconf->state) {
		sconf->prefix = strdup("cb");
		sconf->hash = apr_hash_make(cmd->pool);
	}

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
	
	/* TODO: use apr_time_sec() instead
	 * microseconds for browsercaching seems ... Oversized 
	 *
	 * However, apt_time_t is an int64 and need a conversion to char* 
	 * */
	/* Add to r->notes instead of this hash for cluster capability
	 * Needs to be sent on the logging phase after the response */
	if (f->r->finfo.mtime) {
		apr_hash_set(sconf->hash, f->r->filename, APR_HASH_KEY_STRING, apr_itoa(f->r->pool, f->r->finfo.mtime));
	}

	/* Remove filter and go to the next one in the pipe */
	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb) ;
}
/* }}} */

/* {{{ Strip ;prefixHash from the request path and resolve to
 * local file */
static int resolve_cachebusting_name(request_rec *r) 
{
	int res;

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
	prefix = apr_pstrcat(r->pool, ";", sconf->prefix, NULL);

	/* Skip if prefix not found */
	if ((found = ap_strstr_c(r->uri, prefix)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03463) "Prefix not found");
		return DECLINED;
	}

	/* Use the core translator after modifying the uri from the request */
	char* new_filename = apr_palloc(r->pool, found - r->uri + 1);
	strncpy(new_filename, r->uri, found - r->uri);
	new_filename[found - r->uri] = 0;
	/* Check if mod_rewrite and mod_alias still work as expected */
	r->uri = new_filename;
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
	prefix = apr_pstrcat(r->pool, ";", sconf->prefix, NULL);
	found = strstr(r->parsed_uri.path, prefix);

	/* Check if content type is an image and hash is appended */
	if (r->content_type && !strncmp(r->content_type, "image", 5) && found != NULL) {
		ap_add_output_filter_handle(cachebusting_add_header_filter, NULL, r, r->connection);
		return;
	}

	/* Check if content type is an image and no hash is appended */
	if (r->content_type && !strncmp(r->content_type, "image", 5) && found == NULL) {
		ap_add_output_filter_handle(cachebusting_add_hash_filter, NULL, r, r->connection);
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
		ap_register_output_filter("MOD_CACHEBUSTING_HEADER", cachebusting_header_filter, NULL, AP_FTYPE_CONTENT_SET); 

	cachebusting_add_hash_filter = 
		ap_register_output_filter("MOD_CACHEBUSTING_HASH", cachebusting_hash_filter, NULL, AP_FTYPE_CONTENT_SET);

	ap_hook_translate_name(resolve_cachebusting_name, NULL, aszPre, APR_HOOK_REALLY_FIRST);
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

