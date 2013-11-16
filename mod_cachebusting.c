#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <string.h>
#include <ap_config.h>
#include <apr_strings.h>
#include "cachebusting/cachebusting.h"

#define DISABLED 2
#define ENABLED 1

module AP_MODULE_DECLARE_DATA cachebusting_module;

/* {{{ Structure to hold the config */
typedef struct _cachebusting_server_conf {
	int state;				/* State of the module */
	cb_config *cb_conf;		/* Cachebusting config */
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
	if (sconf->state)
		sconf->cb_conf = cb_init("cb");

	return NULL;
}
/* }}} */

/* {{{ Set the prefix for cachebusting elements, default 'cb' */
static const char* cmd_cachebusting_prefix(cmd_parms *cmd, void *in_dconf, char* prefix)
{
	cachebusting_server_conf *sconf;

	sconf = ap_get_module_config(cmd->server->module_config, &cachebusting_module);
	if(sconf->state)
		sconf->cb_conf->prefix = prefix;

	return NULL;
}
/* }}} */

/* {{{ Defined commands */
static const command_rec cachebusting_cmds[] = {
	AP_INIT_FLAG("Cachebusting", cmd_cachebusting, NULL, RSRC_CONF,
			"Whether to enable or disable cachebusting"),
	AP_INIT_TAKE1("CachebustingPrefix", cmd_cachebusting_prefix, NULL, RSRC_CONF,
			"Prefix for cachebusting elements, default 'cb'"),
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
	
	cachebusting_server_conf *sconf;
	sconf = ap_get_module_config(r->server->module_config, &cachebusting_module);

	/* Skip if not enabled */
	if (!sconf || sconf->state == DISABLED) {
		return DECLINED;
	}

	char *prefix, *found;
	prefix = apr_pstrcat(r->pool, ";", sconf->cb_conf->prefix, NULL);

	/* Skip if prefix not found */
	if ((found = strstr(r->parsed_uri.path, prefix)) == NULL) {
		return DECLINED;
	}
	/* Hence we only serve static stuff yet, asset is always doc_root/r->parsed_uri.path */
	char* new_filename = apr_palloc(r->pool, found - r->parsed_uri.path + 1);
	new_filename = strncpy(new_filename, r->parsed_uri.path, found - r->parsed_uri.path);

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

