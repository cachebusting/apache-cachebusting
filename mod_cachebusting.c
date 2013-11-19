#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <http_log.h>
#include <http_core.h>
#include <http_request.h>
#include <string.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <util_filter.h>
#include "cachebusting/cachebusting.h"

#define DISABLED    2
#define ENABLED     1

static ap_filter_rec_t *cachebusting_add_header_filter;
static ap_filter_rec_t *cachebusting_add_hash_filter;

module AP_MODULE_DECLARE_DATA cachebusting_module;

/* {{{ Structure to hold the config */
typedef struct _cachebusting_server_conf {
	int state;              /* State of the module */
	cb_config *cb_conf;     /* Cachebusting config */
	unsigned int lifetime;  /* Lifetime for cachebusting caches */
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
		sconf->cb_conf = cb_init("cb");
	}

	return NULL;
}
/* }}} */

/* {{{ Set the prefix for cachebusting elements, default 'cb' */
static const char* cmd_cachebusting_prefix(cmd_parms *cmd, void *in_dconf, char* prefix)
{
	cachebusting_server_conf *sconf;

	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	if (sconf->state) sconf->cb_conf->prefix = prefix;

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
	expires = f->r->request_time+apr_time_from_sec(sconf->cb_conf->cache_lifetime);
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
	
	/* TODO: Check size of mtime and use apr_time_sec() instead
	 * microseconds for browsercaching seems ... Oversized 
	 *
	 * However, apt_time_t is an int64 and need a conversion to char* 
	 * */
	cb_add(sconf->cb_conf->hashtable, cb_item_create(f->r->filename, 
				apr_itoa(f->r->pool, f->r->finfo.mtime)));

	/* Remove filter and go to the next one in the pipe */
	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb) ;
}
/* }}} */

/* {{{ Strip ;prefixHash from the request path and resolve to
 * local file */
static int resolve_cachebusting_name(request_rec *r) 
{
	/* Skip if request doesn't start with / and first character isn't NULL 
	 * Only allow GET requests */
	if ((r->uri[0] != '/' && r->uri[0] != '\0') || r->method_number != M_GET) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03461)	"Wrong request type");
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
	prefix = apr_pstrcat(r->pool, ";", sconf->cb_conf->prefix, NULL);

	/* Skip if prefix not found */
	if ((found = strstr(r->parsed_uri.path, prefix)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, APLOGNO(03463)	"Hash not found");
		return DECLINED;
	}

	/* Hence we only serve static stuff yet, asset is always doc_root/r->parsed_uri.path */
	char* new_filename = apr_palloc(r->pool, found - r->parsed_uri.path + 1);
	strncpy(new_filename, r->parsed_uri.path, found - r->parsed_uri.path);

	r->filename = apr_pstrcat(r->pool, ap_document_root(r), new_filename, NULL);

	return OK;
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
	prefix = apr_pstrcat(r->pool, ";", sconf->cb_conf->prefix, NULL);
	found = strstr(r->parsed_uri.path, prefix);

	/* Check if content type is an image and hash is appended */
	if (!strncmp(r->content_type, "image", 5) && found != NULL) {
		ap_add_output_filter_handle(cachebusting_add_header_filter, NULL, r, r->connection);
		return;
	}

	/* Check if content type is an image and no hash is appended */
	if (!strncmp(r->content_type, "image", 5) && found == NULL) {
		ap_add_output_filter_handle(cachebusting_add_hash_filter, NULL, r, r->connection);
		return;
	}
}
/* }}} */

/* {{{ Register hooks into runtime */
static void cachebusting_hooks(apr_pool_t *pool) 
{
	/* TODO: Let mod_alias and mod_rewrite run before mod_cachebusting
	 * to ensure the functionality will stack */
	static const char * const aszPre[] = { "http_core.c", "mod_mime.c", NULL };

	/* Create filter handles */
	cachebusting_add_header_filter = 
		ap_register_output_filter("MOD_CACHEBUSTING_HEADER", cachebusting_header_filter, NULL, AP_FTYPE_CONTENT_SET); 

	cachebusting_add_hash_filter = 
		ap_register_output_filter("MOD_CACHEBUSTING_HASH", cachebusting_hash_filter, NULL, AP_FTYPE_CONTENT_SET);

	ap_hook_translate_name(resolve_cachebusting_name, aszPre, NULL, APR_HOOK_MIDDLE);
	ap_hook_insert_filter(cachebusting_insert_filter, aszPre, NULL, APR_HOOK_MIDDLE);
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

