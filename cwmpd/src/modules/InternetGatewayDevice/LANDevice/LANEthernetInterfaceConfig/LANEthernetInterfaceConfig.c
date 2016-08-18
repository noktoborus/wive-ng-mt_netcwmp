/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/LANDevice/LANEthernetInterfaceConfig/LANEthernetInterfaceConfig.c
 */

static unsigned leic_max_port = 0u;

static bool
leic_get_if_mac(char ifname[IFNAMSIZ], char mac[18])
{
	struct ifreq ifr = {};
	int s = -1;

	*mac = '\0';

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		return false;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);

	if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1) {
		cwmp_log_error("%s(): ioctl(SIOCGIFHWADDR) failed: %s",
				__func__, strerror(errno));
		close(s);
		return false;
	}

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			(unsigned char)ifr.ifr_hwaddr.sa_data[0],
			(unsigned char)ifr.ifr_hwaddr.sa_data[1],
			(unsigned char)ifr.ifr_hwaddr.sa_data[2],
			(unsigned char)ifr.ifr_hwaddr.sa_data[3],
			(unsigned char)ifr.ifr_hwaddr.sa_data[4],
			(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	close(s);
	return true;
}

static int
leic_portNo_from_path(cwmp_t *cwmp, const char *path, bool stats)
{
	unsigned pno = 0u;
	parameter_node_t *pn = NULL;
	unsigned wan_port = 0;
	char *n = NULL;
    char *lan_first = cwmp_nvram_get("lan_port");
	wan_port = cwmp_nvram_get_int("wan_port", 0);

	pn = cwmp_get_parameter_path_node(cwmp->root, path);

	if (!pn || !(pn = pn->parent)) {
		goto error;
	}

	if (stats && !(pn = pn->parent)) {
		goto error;
	}

	pno = strtoul(pn->name, &n, 10);
	if (*n != '\0' && *n != '.') {
		cwmp_log_error("LEIC: segment '%s' not a number (from %s)",
				pn->name, path);
		return -1;
	}

    /* convert number to index */
    if (!strcmp(lan_first, "near")) {
        if (wan_port == 0) {
            /* data in array: "4 3 2 1 W" */
            pno = leic_max_port - pno;
        } else {
            /* data in array: "W 1 2 3 4" */
        }
    } else if (!strcmp(lan_first, "distant")) {
        if (wan_port != 0) {
            /* data in array: "W 4 3 2 1" */
            pno = wan_port - (pno - 1);
        } else {
            /* data in array: "4 3 2 1 W" */
            pno -= 1;
        }
    }

    /* check out of range(0, leic_max_port) */
    if (pno > leic_max_port) {
		cwmp_log_error("LEIC: number %d not a port (max port: %d)",
				pno, leic_max_port);
		return -1;
	}

	return pno;

error:
	cwmp_log_error("LEIC: can't get port number from path: '%s'",  path);
	return -1;
}

int
cpe_refresh_LEIC(cwmp_t *cwmp, parameter_node_t *param_node, callback_register_func_t callback_reg)
{
	/* five physical ports */
	const unsigned count = 5;

	unsigned i = 0u;
	parameter_node_t *pn = NULL;
	unsigned wan_port = 0;

	DM_TRACE_REFRESH();

	wan_port = cwmp_nvram_get_int("wan_port", 0);

	/* remove old list  */
	cwmp_model_delete_object_child(cwmp, param_node);

	/* populate new */
	for (i = (count - 1); i < count; i--) {
		if (i == wan_port)
			continue;
		cwmp_model_copy_parameter(param_node, &pn, i + 1);
	}

    /* one port for WAN */
	leic_max_port = count - 1;

	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_number(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
    char buf[22] = "0";
    snprintf(buf, sizeof(buf), "%u", leic_max_port);
    *value = pool_pstrdup(buf);
    return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MAC(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char mac[18] = {};

	DM_TRACE_GET();
	leic_get_if_mac(IOCTL_IF, mac);

	*value = pool_pstrdup(pool, mac);
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_MaxBitRate(cwmp_t *cwmp, const char *name, char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	/* TODO: ... */
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MaxBitRate(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	unsigned pno = 0u;
	struct port_status ps = {};
	char b[24] = {};

	DM_TRACE_GET();
	pno = leic_portNo_from_path(cwmp, name, false);
	if (pno == -1) {
		return FAULT_CODE_9003;
	}

	portstatus(&ps, pno);

	snprintf(b, sizeof(b), "%d", ps.speed);
	*value = pool_pstrdup(pool, b);

	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Name(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();

	*value = IOCTL_IF;
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_stats(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	unsigned pno = -1;
	struct port_counts pc = {};
	char b[24] = {};
	parameter_node_t *pn = NULL;

	DM_TRACE_GET();
	if ((pno = leic_portNo_from_path(cwmp, name, true)) == -1) {
		return FAULT_CODE_9003;
	}
	pn = cwmp_get_parameter_path_node(cwmp->root, name);

	portscounts(&pc);

	if (!strcmp(pn->name, "BytesSent")) {
		snprintf(b, sizeof(b), "%llu", pc.tx_count[pno]);
		*value = pool_pstrdup(pool, b);
	} else if (!strcmp(pn->name, "BytesReceived")) {
		snprintf(b, sizeof(b), "%llu", pc.rx_count[pno]);
		*value = pool_pstrdup(pool, b);
	} else {
		*value = "0";
	}

	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Status(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	unsigned pno = 0u;
	struct port_status ps = {};

	DM_TRACE_GET();
	pno = leic_portNo_from_path(cwmp, name, false);
	if (pno == -1)
		return FAULT_CODE_9003;

	portstatus(&ps, pno);

	if (ps.link) {
		*value = "Up";
	} else {
		*value = "NoLink";
	}

	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_DuplexMode(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	unsigned pno = 0u;
	struct port_status ps = {};

	DM_TRACE_GET();
	pno = leic_portNo_from_path(cwmp, name, false);
	if (pno == -1)
		return FAULT_CODE_9003;

	portstatus(&ps, pno);

	switch (ps.duplex) {
	case DUPLEX_HALF:
		*value = "Half";
		break;
	case DUPLEX_FULL:
		*value = "Full";
		break;
	default:
		*value = "Auto";
		break;
	}

	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_DuplexMode(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();

	/* TODO: ... */
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_Enable(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	*value = "1";
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_Enable(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();

	/* TODO: ... */
	return FAULT_CODE_OK;
}

int
cpe_get_LEIC_MACcontrol(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	DM_TRACE_GET();
	/* TODO: not awailable? */
	*value = "0";
	return FAULT_CODE_OK;
}

int
cpe_set_LEIC_MACcontrol(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
	/* TODO: not awailable? */
	return FAULT_CODE_OK;
}

