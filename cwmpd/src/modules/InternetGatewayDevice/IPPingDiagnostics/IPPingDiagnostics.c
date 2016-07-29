/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/IPPingDiagnostics/IPPingDiagnostics.c
 */

enum ping_state {
	PING_NONE,
	PING_REQUESTED,
	PING_COMPLETE,
	PING_ERROR_RESOLVE,
	PING_ERROR_INTERNAL,
	PING_ERROR_OTHER,
	PING_NOT_A_STATE
};

static const char *ping_state_string[] =
	{
		"None",
		"Requested",
		"Complete",
		"Error_CannotResolveHostName",
		"Error_Internal",
		"Error_Other"
	};

static struct ping_values_t {
	enum ping_state state;

	char iface[256];
	char host[256];

	unsigned repeat; /* range: 1- (default: 1) */
	unsigned timeout; /* range: 1- (default: 1) */
	unsigned data_size; /* range: 1-65535 (default: 1) */
	unsigned dscp; /* range: 0-63 (default: 0) */

	struct {
		unsigned success;
		unsigned failure;
		unsigned average;
		unsigned minimum;
		unsigned maximum;
	} r;
} ping_values = {.repeat = 1u, .timeout = 1u, .data_size = 1u};

static const char *
state_to_string(enum ping_state state)
{
	const size_t n =
		sizeof(ping_state_string) / sizeof(*ping_state_string);
	if ((size_t)state < n) {
		return ping_state_string[state];
	}
	return "?";
}

static int
set_integer(const char *name, unsigned *target, const char *value,
		unsigned range_min, unsigned range_max)
{
	unsigned long v = 0u;
	char *pend = NULL;
	v = strtoul(value, &pend, 10);
	if (pend && *pend) {
		cwmp_log_error("IPPingDiagnostics.%s not a number: '%s'",
				name, value);
		return FAULT_CODE_9007;
	}
	if (v < range_min || v > range_max) {
		cwmp_log_error("IPPingDiagnostics.%s value '%s' not in range %u-%u",
			   name, value, range_min, range_max);
		return FAULT_CODE_9007;
	}
	*target = (unsigned)v;
	return FAULT_CODE_OK;
}

static enum ping_state
string_to_state(const char *string)
{
	enum ping_state state = PING_NONE;
	const size_t l = sizeof(*ping_state_string);
	for (; state != PING_NOT_A_STATE; state++) {
		if (!strncmp(string, ping_state_string[state], l))
			break;
	}
	return state;
}

/* internal values */
void
perform_ping()
{
	char iface_info[256] = {};
	if (*ping_values.iface) {
		snprintf(iface_info, sizeof(iface_info),
				", Interface=\"%s\"", ping_values.iface);
	}
	cwmp_log_debug("IPPingDiagnostics("
			"Host=\"%s\"%s, "
			"NumberOfRepetitions=%u, "
			"Timeout=%u, "
			"DataBlockSize=%u, "
			"DSCP=%u)",
			ping_values.host,
			iface_info,
			ping_values.repeat,
			ping_values.timeout,
			ping_values.data_size,
			ping_values.dscp);
	memset(&ping_values.r, 0u, sizeof(ping_values.r));
}

/* result values */
int
cpe_get_igd_ping_success(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.r.success);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_failure(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.r.failure);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_average(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.r.average);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_minimum(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.r.minimum);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_maximum(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.r.maximum);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

/* request values */
int
cpe_set_igd_ping_state(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	enum ping_state state = string_to_state(value);
	if (state != PING_REQUESTED) {
		cwmp_log_error("IPPingDiagnostics.DiagnosticsState invalid value: '%s'", value);
		return FAULT_CODE_9007;
	}
	ping_values.state = state;

	queue_push(cwmp->queue, NULL, TASK_PING_TAG);
	return FAULT_CODE_OK;
}

int
cpe_set_igd_ping_dscp(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	return set_integer("DSCP", &ping_values.dscp, value, 0, 63);
}

int
cpe_set_igd_ping_host(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	if (!length) {
		cwmp_log_error("IPPingDiagnostics.Host zero-length host not allowed");
		return FAULT_CODE_9007;
	}
	strncpy(ping_values.host, value, sizeof(ping_values.host));
	return FAULT_CODE_OK;
}

int
cpe_set_igd_ping_iface(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	if (!length) {
		memset(ping_values.iface, 0u, sizeof(ping_values.iface));
		return FAULT_CODE_OK;
	}

	/* TODO: check iface name */
	strncpy(ping_values.iface, value, sizeof(ping_values.iface));
	return FAULT_CODE_OK;
}

int
cpe_set_igd_ping_repeat(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	return set_integer("NumberOfRepetitions", &ping_values.repeat, value, 1, (unsigned)-1);
}

int
cpe_set_igd_ping_data_size(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	return set_integer("DataBlockSize", &ping_values.data_size, value, 1, 65535);
}

int
cpe_set_igd_ping_timeout(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	return set_integer("Timeout", &ping_values.timeout, value, 1, (unsigned)-1);
}

int
cpe_get_igd_ping_state(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	*value = pool_pstrdup(pool, state_to_string(ping_values.state));
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_dscp(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char dscp[8] = {};
	snprintf(dscp, sizeof(dscp), "%u", ping_values.dscp);
	*value = pool_pstrdup(pool, dscp);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_host(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	*value = pool_pstrdup(pool, ping_values.host);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_iface(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	*value = pool_pstrdup(pool, ping_values.iface);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_repeat(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.repeat);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_data_size(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.data_size);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

int
cpe_get_igd_ping_timeout(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char v[32] = {};
	snprintf(v, sizeof(v), "%u", ping_values.timeout);
	*value = pool_pstrdup(pool, v);
	return FAULT_CODE_OK;
}

