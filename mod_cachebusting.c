#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <string.h>
#include <ap_config.h>
#include <apr_strings.h>

#define DISABLED 2
#define ENABLED 1

module AP_MODULE_DECLARE_DATA cachebusting_module;

/* {{{ Structure to hold the config */
typedef struct _cachebusting_server_conf {
	int state;			/* State of the module */
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

	return NULL;
}
/* }}} */

/* {{{ Defined commands */
static const command_rec cachebusting_cmds[] = {
	AP_INIT_FLAG("Cachebusting", cmd_cachebusting, NULL, RSRC_CONF,
			"Whether to enable or disable cachebusting"),
	{NULL}
};
/* }}} */

/* {{{ Strip ;prefixHash from the request path and resolve to
 * local file */
static int resolve_cachebusting_name(request_rec *r) 
{
	if (r->uri[0] != '/' && r->uri[0] != '\0') {
		return DECLINED;
	}
	
	char* prefix;
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(r->server->module_config, &cachebusting_module);

	/* Skip if not enabled or prefix not found */
	if (!sconf || sconf->state == DISABLED || (prefix = strstr(r->parsed_uri.path, ";cb")) == NULL) {
		return DECLINED;
	}
	/* Hence we only serve static stuff yet, asset is always doc_root/r->parsed_uri.path */
	char* new_filename = apr_palloc(r->pool, prefix - r->parsed_uri.path + 1);
	new_filename = strncpy(new_filename, r->parsed_uri.path, prefix - r->parsed_uri.path);

	r->filename = apr_pstrcat(r->pool, ap_document_root(r), new_filename, NULL);

	return OK;
}
/* }}} */

/* {{{ Register hooks into runtime */
static void cachebusting_hooks(apr_pool_t *pool) 
{
	/* TODO: Let mod_alias and mod_rewrite run before mod_cachebusting
	 * to ensure the functionality will stack */
	static const char * const aszPre[] = { "http_core.c", NULL };
	ap_hook_translate_name(resolve_cachebusting_name, aszPre, NULL, APR_HOOK_REALLY_FIRST);
}
/* }}} */

module AP_MODULE_DECLARE_DATA cachebusting_module = {
	STANDARD20_MODULE_STUFF,
	NULL,								/* create per server config structure	*/
	NULL,								/* merge per dir config structure		*/
	create_cachebusting_server_conf,	/* create per server config structure	*/
	NULL,								/* merge per server config structure	*/
	cachebusting_cmds,					/* table of config file commands		*/
	cachebusting_hooks					/* register hooks						*/
} ;

