#include <httpd.h>
#include <http_protocol.h>
#include <http_config.h>
#include <string.h>
#include "apr_strings.h"

/* {{{ Strip ;prefixHash from the request path and resolve to
 * local file */
static int resolve_cachebusting_name(request_rec *r) 
{
	if (r->uri[0] != '/' && r->uri[0] != '\0') {
		return DECLINED;
	}
	char* prefix;
	/* Skip if prefix is not set */
	if ((prefix = strstr(r->parsed_uri.path, ";cb")) == NULL) {
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
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	cachebusting_hooks
} ;

