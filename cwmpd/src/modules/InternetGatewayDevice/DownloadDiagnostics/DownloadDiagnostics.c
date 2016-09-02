/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/DownloadDiagnostics/DownloadDiagnostics.c
 */

int
cpe_reload_dd(cwmp_t *cwmp, callback_register_func_t callback_reg)
{
	DM_TRACE_RELOAD();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_dscp(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_epri(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_iface(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_result(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_state(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_dd_url(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_set_dd_dscp(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_set_dd_epri(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_set_dd_iface(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_set_dd_state(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_set_dd_url(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}


