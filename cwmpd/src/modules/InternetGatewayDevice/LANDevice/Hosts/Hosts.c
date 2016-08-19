/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/LANDevice/Hosts/Hosts.c
 */

struct hosts_addr {
	char addr[INET_ADDRSTRLEN];
	char mac[18];

	char hostname[128];

	unsigned hw_type;

	bool is_dhcp;
	unsigned long lease;

	struct hosts_addr *next;
};

static void
hosts_leases_expand(struct dyn_lease *dl, char addr[INET_ADDRSTRLEN], char mac[18])
{
	struct in_addr ina;
	assert(dl != NULL);
	assert(addr != NULL);
	assert(mac != NULL);

	ina.s_addr = dl->lease_nip;
	inet_ntop(AF_INET, (void*)&ina, addr, INET_ADDRSTRLEN);

	snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			dl->lease_mac[0], dl->lease_mac[1], dl->lease_mac[2],
			dl->lease_mac[3], dl->lease_mac[4], dl->lease_mac[5]);
}

static void
_hosts_check(struct hosts_addr *list)
{
	assert(list != NULL);
	struct hosts_addr *np = NULL;

	char addr[INET_ADDRSTRLEN];
	char mac[18];

	struct dyn_lease *dl = NULL;
	int row_count = 0;
	uint64_t written_at = 0;

	int row_no = 0;

	dl = getDhcpClientList(&row_count, &written_at);
	if (!row_count) {
		return;
	}

	for (np = list; np; np = np->next) {
		for (row_no = 0; row_no < row_count; row_no++) {
			hosts_leases_expand(&dl[row_no], addr, mac);
			if (strcmp(addr, np->addr) || strcmp(mac, np->mac)) {
				/* skip unmatched */
				continue;
			}
			np->is_dhcp = true;
			if (dl[row_no].expires) {
				/* FIXME: htonl() must be called on udhcpd.leases read */
				np->lease = htonl(dl[row_no].expires);
			} else {
				np->lease = -1;
			}
			snprintf(np->hostname, sizeof(np->hostname),
					"%s", dl[row_no].hostname);
			break;
		}
	}
}

static unsigned
hosts_list(struct hosts_addr **list)
{
	/* TODO: to libwive */
	unsigned c = 0;
	char line[160] = {};
	FILE *f = NULL;
	struct hosts_addr *n = NULL;
	struct hosts_addr *np = NULL;

	struct {
		char addr[sizeof(n->addr)];
		char mac[sizeof(n->mac)];
		int hw_type;
		int flags;
		char iface[IFNAMSIZ];
	} v = {};

	f = fopen("/proc/net/arp", "r");
	if (!f) {
		return 0;
	}

	fgets(line, sizeof(line), f);
	while (fgets(line, sizeof(line), f)) {
		sscanf(line, "%s %x %x %s %*s %s",
				v.addr, &v.hw_type, &v.flags, v.mac, v.iface);
		/* skip arp uncomplete */
		if (!v.flags)
			continue;
		/* FIXME: skip non-LAN ifaces */
		if (strcmp(v.iface, "br0"))
			continue;
		if (!list) {
			/* increment counter and skip */
			c++;
			continue;
		}
		/* allocate */
		n = calloc(1, sizeof(*n));
		if (!n) {
			/* logging? */
			continue;
		}
		/* increment counter */
		c++;
		/* copy data */
		memcpy(n->addr, v.addr, sizeof(n->addr));
		memcpy(n->mac, v.mac, sizeof(n->mac));
		n->hw_type = (unsigned)v.hw_type;
		/* attach to list */
		if (!*list) {
			*list = n;
			np = *list;
		} else {
			np->next = n;
			np = n;
		}
	}
	fclose(f);
	if (list && *list)
		_hosts_check(*list);
	return c;
}

static void
hosts_list_free(struct hosts_addr **list)
{
	struct hosts_addr *n = NULL;

	assert(list != NULL);

	for (n = *list; n;) {
		*list = n;
		n = n->next;
		free(*list);
	}
	*list = NULL;
}

/* device model code */

static struct hosts_addr *hosts_addrs = NULL;
static unsigned hosts_count = 0u;

int
cpe_get_hosts_count(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	char buf[30];
	snprintf(buf, sizeof(buf), "%u", hosts_count);
	*value = pool_pstrdup(pool, buf);
	return FAULT_CODE_OK;
}

int
cpe_refresh_hosts(cwmp_t *cwmp, parameter_node_t *param_node, callback_register_func_t callback_reg)
{
	unsigned i = 0u;
	parameter_node_t *pn = NULL;
	DM_TRACE_REFRESH();

	/* remove old list  */
	cwmp_model_delete_object_child(cwmp, param_node);

	/* populate new */
	if (hosts_addrs) {
		hosts_list_free(&hosts_addrs);
	}

	hosts_count = hosts_list(&hosts_addrs);

	for (i = 0u; i < hosts_count; i++) {
		cwmp_model_copy_parameter(param_node, &pn, i + 1);
	}

	return FAULT_CODE_OK;
}

