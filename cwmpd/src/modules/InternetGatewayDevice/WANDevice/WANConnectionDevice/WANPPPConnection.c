/* vim: set et: */
int cpe_get_igd_wan_ppp_servicename(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{

    char* sername = NULL;

	DM_TRACE_GET();
	sername = cwmp_nvram_pool_get(pool, "vpnService");
    if (sername == NULL)
    {
	*value = pool_pstrdup(pool, "");
	return FAULT_CODE_OK;
    }

    *value = sername;

    return FAULT_CODE_OK;
}



int cpe_get_igd_wan_ppp_authprot(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{

    int authProt =  0;

	DM_TRACE_GET();
	authProt = cwmp_nvram_get_int("vpnAuthProtocol", 0);
    char* stdstr;

    switch (authProt) {

	case 1: stdstr = "PAP";break;
	case 2: stdstr = "CHAP";break;
	case 3: stdstr = "MS-CHAP";break;
	default: stdstr = "AUTO";break;
    }

    *value = pool_pstrdup(pool, stdstr);

    return FAULT_CODE_OK;
}

int cpe_set_igd_wan_ppp_authprot(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{

    char* valStr = "0";

    DM_TRACE_SET();

    if (strcmp(value,"PAP") == 0) valStr = "1"; else
    if (strcmp(value,"CHAP") == 0) valStr = "2"; else
    if (strcmp(value,"MS-CHAP") == 0) valStr = "3";

    cwmp_nvram_set("vpnAuthProtocol", valStr);

    return FAULT_CODE_OK;
}

/* Uptime
 * ConnectionStatus
 * EthernetBytesSent
 * EthernetBytesReceived
 * EthernetPacketsSent
 * EthernetPacketsReceived
 */
int cpe_get_igd_wan_ppp_stats(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
	parameter_node_t *pn = NULL;
	struct nic_counts *ncs = NULL;
	struct nic_counts *nc = NULL;
	int elc = 0;
	int status = 0;
	char buf[42] = {};
    struct stat st = {};
    time_t t = 0;

	DM_TRACE_GET();
	pn = cwmp_get_parameter_path_node(cwmp->root, name);
	ncs = nicscounts(&elc);

	for (; elc-- > 0;) {
		nc = &ncs[elc];
		if (!strncmp(nc->ifname, "ppp", 3)) {
			break;
		}
	}

     if (!strcmp(pn->name, "ConnectionStatus")) {
		status = getVPNStatusCode();
		switch (status) {
			case 0:
				*value = "Unconfigured";
				break;
			case 1:
				*value = "Disconnected";
				break;
			case 2:
				*value = "Connecting";
				break;
			case 3: /* 3 - Connected or 'kabinet network' for kabinet type */
			case 4: /* 4 - full access for kabinet type */
				*value = "Connected";
				break;
			default:
				cwmp_log_error("WANPPPConnection.{i}.ConnectionStatus: "
						"unknown status: %d", status);
				break;
		}
	} else if (nc) {
        if (!strcmp(pn->name, "Uptime")) {
            time(&t);
            snprintf(buf, sizeof(buf), "/var/run/%s.pid", nc->ifname);
            if (stat(buf, &st) == -1) {
                cwmp_log_error("WANPPPConnection.{i}.Uptime: stat(%s) failed: %s",
                        buf, strerror(errno));
            } else if (t < st.st_mtim.tv_sec) {
                cwmp_log_error(
                        "WANPPPConnection.{i}.Uptime: system time less then mtime(%s)",
                        buf);
            } else {
                snprintf(buf, sizeof(buf), "%llu",
                        (unsigned long long)(time(NULL) - st.st_mtim.tv_sec));
                *value = pool_pstrdup(pool, buf);
            }
        } else if (!strcmp(pn->name, "EthernetBytesSent")) {
			snprintf(buf, sizeof(buf), "%llu", nc->tx_bytes);
		} else if (!strcmp(pn->name, "EthernetBytesReceived")) {
			snprintf(buf, sizeof(buf), "%llu", nc->rx_bytes);
		} else if (!strcmp(pn->name, "EthernetPacketsSent")) {
			snprintf(buf, sizeof(buf), "%llu", nc->tx_packets);
		} else if (!strcmp(pn->name, "EthernetPacketsReceived")) {
			snprintf(buf, sizeof(buf), "%llu", nc->rx_packets);
		}
		*value = pool_pstrdup(pool, buf);
	}
	return FAULT_CODE_OK;
}

