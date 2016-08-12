/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/LANDevice/LANEthernetInterfaceConfig/LANEthernetInterfaceConfig.c
 */

int
cpe_refresh_LEIC(cwmp_t *cwmp, parameter_node_t *param_node, callback_register_func_t callback_reg)
{
	DM_TRACE_REFRESH();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MAC(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MaxBitRate(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Name(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_stats(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Status(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_DuplexMode(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_DuplexMode(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Enable(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_Enable(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MACcontrol(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_MACcontrol(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	return FAULT_CODE_OK;
}

