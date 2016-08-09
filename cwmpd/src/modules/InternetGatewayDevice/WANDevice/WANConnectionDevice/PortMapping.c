/* vim: ft=c ff=unix fenc=utf-8
 * file: cwmpd/src/modules/InternetGatewayDevice/WANDevice/WANConnectionDevice/PortMapping.c
 */

enum pm_type {
	PM_WAN = 1,
	PM_VPN
};

/* lists of pm rules */
static struct pm_rule *rules[3] = {};
/* lengths of rules lists */
static size_t rules_s[sizeof(rules)] = {};

/* internal lib */
#include <regex.h>
#ifndef MIN
# define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

enum pm_proto {
	PM_NONE = 0,
	PM_TCP,
	PM_UDP,
	PM_UDPTCP
};

struct pm_rule
{
	char iface[16];
	enum pm_proto proto;
	unsigned sport_min;
	unsigned sport_max;
	char addr[64];
	unsigned dport_min;
	unsigned dport_max;
	bool loopback;
	char description[256];
};

bool
pm_parse(const char *in, struct pm_rule *rule, char **next);

static unsigned
rule_count(const char *pm_line, const char *ift)
{
	struct pm_rule rule = {};

	unsigned cc = 0u;

	if (!pm_line)
		return 0u;

	while(pm_line) {
		if (!pm_parse(pm_line, &rule, (char**)&pm_line)) {
			continue;
		}
		/* count rules */
		if (!strcmp(rule.iface, ift)) {
			cc++;
			/* explain UDP&TCP line to UDP and TCP */
			if (rule.proto == PM_UDPTCP) {
				cc++;
			}
		}
	}
	return cc;
}

static const char *
nodename_to_ift(const char *nodename, enum pm_type *ift_i)
{
	if (!strncmp(nodename, "WANIPConnection", 15)) {
		if (ift_i)
			*ift_i = PM_WAN;
		return "WAN";
	} else if (!strncmp(nodename, "WANPPPConnection", 16)) {
		if (ift_i)
			*ift_i = PM_VPN;
		return "VPN";
	} else {
		cwmp_log_warn("PortMapping: unknown model node: %s. "
				"Expect WANIPConnection or WANPPPConnection",
				nodename);
		return NULL;
	}
}

bool
pm_parse(const char *in, struct pm_rule *rule, char **next)
{
	regex_t preg = {};
	char *pattern = "\\([[:alpha:]]*\\),\\([1-3]\\)," /* iface, type */
		"\\([[:digit:]]*\\),\\([[:digit:]]*\\)," /* src port min, src port max */
		"\\([a-fA-F0-9.:]*\\)," /* addr */
		"\\([[:digit:]]*\\),\\([[:digit:]]*\\)," /* dst port min, dst port max */
		"\\([0-1]\\),\\([^;]*\\)" /* loopback, description */
		"\\(;\\)"
		;

	int rc = 0;
	regmatch_t pmatch[11] = {};

	memset(rule, 0u, sizeof(*rule));
	rc = regcomp(&preg, pattern, 0);
	if (rc != 0) {
		cwmp_log_warn("PortMapping: regcomp(\"%s\") failed: %d\n", pattern, rc);
		return false;
	}

	rc = regexec(&preg, in, sizeof(pmatch) / sizeof(*pmatch), pmatch, 0);
	if (rc != 0) {
		cwmp_log_warn("PortMapping: regexec(\"%s\", \"%s\") failed: %d\n",
				pattern, in, rc);
		return false;
	}

	strncpy(rule->iface,
			&in[pmatch[1].rm_so],
			MIN(sizeof(rule->iface), pmatch[1].rm_eo - pmatch[1].rm_so));
	rule->proto = (int)strtoul(&in[pmatch[2].rm_so], NULL, 10);
	rule->sport_min = (unsigned)strtoul(&in[pmatch[3].rm_so], NULL, 10);
	rule->sport_max = (unsigned)strtoul(&in[pmatch[4].rm_so], NULL, 10);
	strncpy(rule->addr,
			&in[pmatch[5].rm_so],
			MIN(sizeof(rule->addr), pmatch[5].rm_eo - pmatch[5].rm_so));
	rule->dport_min = (unsigned)strtoul(&in[pmatch[6].rm_so], NULL, 10);
	rule->dport_max = (unsigned)strtoul(&in[pmatch[7].rm_so], NULL, 10);
	rule->loopback = (in[pmatch[8].rm_so] == '1') ? true : false;
	strncpy(rule->description,
			&in[pmatch[9].rm_so],
			MIN(sizeof(rule->description), pmatch[9].rm_eo - pmatch[9].rm_so));

	if (next) {
		if (*(*next = (char*)in + pmatch[10].rm_so + 1) == '\0')
			*next = NULL;
	}

	regfree(&preg);

	/* check values */
	if (rule->dport_max > 0 || rule->sport_max > 0) {
		if (rule->sport_max && rule->sport_max < rule->sport_min) {
			cwmp_log_warn("PortMapping: src-port-max can't be less src-port-min\n");
			return false;
		}

		if (rule->dport_max && rule->dport_max < rule->dport_min) {
			cwmp_log_warn("PortMapping: dst-port-max can't be less dst-port-min\n");
			return false;
		}

		if (rule->dport_max - rule->dport_min != rule->sport_max - rule->sport_min) {
				cwmp_log_warn("PortMapping: dst-port and src-port ranges not match\n");
			return false;
		}
	}
	return true;
}

int
cpe_add_pm(cwmp_t *cwmp, parameter_node_t *param_node, int *pinstance_number, callback_register_func_t callback_reg)
{
	const char *ift = NULL;
	enum pm_type ift_i = 0u;
	parameter_node_t *pn = param_node;
	void *tmp = NULL;
	cwmp_log_trace("%s(cwmp=%p, param_node=%p [name=%s], pinstance_number=%p, callback_reg=%p)",
			__func__, (void*)cwmp, (void*)param_node,
			param_node ? param_node->name : "",
			(void*)pinstance_number, (void*)callback_reg);

	/* interface number */
	pn = pn->parent;
	/* interface type */
	pn = pn->parent;

	ift = nodename_to_ift(pn->name, &ift_i);
	if (!ift) {
		return FAULT_CODE_9005;
	}

	cwmp_log_debug("PortMapping[%s]: append new rule. Counter: %"PRIuPTR,
			ift, rules_s[ift_i]);

	tmp = realloc(rules[ift_i], (rules_s[ift_i] + 1) * sizeof(struct pm_rule));
	if (!tmp) {
		cwmp_log_debug("PortMapping[%s]: realloc(%d) failed: %s",
				ift, (rules_s[ift_i] + 1) * sizeof(struct pm_rule),
				strerror(errno));
		return FAULT_CODE_9002;
	}

	rules[ift_i] = tmp;

	memset(&rules[ift_i][rules_s[ift_i]], 0u, sizeof(struct pm_rule));

	rules_s[ift_i]++;
	cwmp_model_copy_parameter(param_node, &pn, rules_s[ift_i]);
	*pinstance_number = rules_s[ift_i];
	return FAULT_CODE_OK;
}

int
cpe_del_pm(cwmp_t *cwmp, parameter_node_t *param_node, int instance_number, callback_register_func_t callback_reg)
{
	const char *ift = NULL;
	enum pm_type ift_i = 0u;
	parameter_node_t *pn = param_node;
	size_t rule_no = 0u;

	cwmp_log_trace(
			"%s(cwmp=%p, param_node=%p [name=%s], "
			"instance_number=%d, callback_reg=%p)",
			__func__, (void*)cwmp, (void*)param_node,
			param_node ? param_node->name : "",
			instance_number, (void*)callback_reg);

	/* PortMapping node */
	pn = pn->parent;
	/* Interface number */
	pn = pn->parent;
	/* Interface type */
	pn = pn->parent;

	ift = nodename_to_ift(pn->name, &ift_i);
	if (!ift) {
		return FAULT_CODE_9005;
	}

	rule_no = strtoul(param_node->name, NULL, 10);
	if (rule_no > rules_s[ift_i]) {
		cwmp_log_warn("PortMapping[%s]: unknown rule number %"PRIuPTR". "
				"Rule count: %"PRIuPTR,
				ift, rule_no, rules_s[ift_i]);
		return FAULT_CODE_9005;
	}

	cwmp_log_debug("PortMapping[%s]: remove rule %"PRIuPTR, ift, rule_no);

	memset(&rules[ift_i][rule_no - 1], 0, sizeof(struct pm_rule));
	cwmp_model_delete_parameter(param_node);

	return FAULT_CODE_OK;
}

int
cpe_refresh_pm(cwmp_t * cwmp, parameter_node_t * param_node, callback_register_func_t callback_reg)
{
	const char *pm_line = NULL;
	struct pm_rule rule = {};
	const char *ift = NULL;
	enum pm_type ift_i = PM_NONE;
	unsigned rules_c = 0u;

	char *parent_name = NULL;
	parameter_node_t *pn_tmp = param_node->parent;
	parameter_node_t *pn = NULL;

	cwmp_log_trace("%s(cwmp=%p, param_node=%p [name=%s], callback_reg=%p)",
			__func__, (void*)cwmp,
			(void*)param_node, param_node->name, (void*)callback_reg);

	if (pn_tmp == NULL || (pn_tmp = pn_tmp->parent) == NULL) {
		return FAULT_CODE_9002;
	}

	parent_name = pn_tmp->name;

	ift = nodename_to_ift(parent_name, &ift_i);
	if (!ift) {
		return FAULT_CODE_9002;
	}

	cwmp_log_debug("PortMapping[%s]: refresh (%s) for %s",
			ift, param_node->name, parent_name);

	/* remove old list  */
	pn_tmp = param_node->child;
	while (pn_tmp) {
		pn = pn_tmp;
		pn_tmp = pn_tmp->next_sibling;

		/* skip "{i}" */
		if (!strcmp(pn->name, "{i}"))
			continue;

		/* delete */
		cwmp_model_delete_parameter(pn);
	}

	free(rules[ift_i]);
	rules[ift_i] = NULL;
	rules_s[ift_i] = 0u;

	/* generate new list */
	pm_line = cwmp_nvram_get("PortForwardRules");
	rules_c = rule_count(pm_line, ift);
	if (!rules_c) {
		cwmp_log_info("PortMapping[%s]: no rules", ift);
		return FAULT_CODE_OK;
	}

	cwmp_log_debug("PortMapping[%s]: allocate %"PRIuPTR" rules",
			ift, rules_c);
	rules[ift_i] = calloc(rules_c, sizeof(struct pm_rule));
	if (!rules[ift_i]) {
		cwmp_log_error("PortMapping[%s]: calloc(%d) failed: %s",
				ift, rules_c * sizeof(struct pm_rule), strerror(errno));
		return FAULT_CODE_9002;
	}
	rules_s[ift_i] = rules_c;

	rules_c = 0u;
	while (pm_line) {
		if (!pm_parse(pm_line, &rule, (char**)&pm_line)) {
			cwmp_log_info("PortMapping[%s]: parse error, next val: %s",
					ift, pm_line);
			continue;
		}

		/* skip values for another iface */
		if (strcmp(rule.iface, ift) != 0) {
			continue;
		}
		/* add rule (from 1 to infinity) */
		cwmp_model_copy_parameter(param_node, &pn, (rules_c + 1));
		/* save data (from 0 to infinity) */
		memcpy(&rules[ift_i][rules_c], &rule, sizeof(rule));
		/* fix rules */
		if (rule.proto == PM_UDPTCP) {
			rules[ift_i][rules_c].proto = PM_UDP;
			memcpy(&rules[ift_i][++rules_c], &rule, sizeof(rule));
			cwmp_model_copy_parameter(param_node, &pn, (rules_c + 1));
			rules[ift_i][rules_c].proto = PM_TCP;
		}

		rules_c++;
	}

	return FAULT_CODE_OK;
}


struct pm_rule *
name_to_rule(cwmp_t *cwmp, const char *fullpath, char *out_name, size_t out_len)
{
	/* InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.PortMapping.1.InternalPort */
	parameter_node_t *pn = NULL;
	size_t rule_no = 0u;
	const char *ift = NULL;
	enum pm_type ift_i = PM_NONE;

	pn = cwmp_get_parameter_path_node(cwmp->root, fullpath);
	if (!pn) {
		return NULL;
	}

	/* copy name (InternalPort) */
	*out_name = '\0';
	strncpy(out_name, pn->name, out_len - 1);

	/* rule's number (1) */
	pn = pn->parent;
	rule_no = ((size_t)strtoul(pn->name, NULL, 10));

	/* skip module name (PortMapping) */
	pn = pn->parent;

	/* skip device number (1) */
	pn = pn->parent;
	/* ... */

	/* device type (WANIPConnection) */
	pn = pn->parent;
	ift = nodename_to_ift(pn->name, &ift_i);
	if (!ift) {
		return NULL;
	}

	if (rule_no > rules_s[ift_i]) {
		cwmp_log_warn("PortMapping[%s]: unknown rule number %"PRIuPTR". "
				"Rule count: %"PRIuPTR, ift,
				rule_no, rules_s[ift_i]);
		return NULL;
	}

	cwmp_log_debug("PortMapping[%s]: work with rule %"PRIuPTR, ift, rule_no);

	return &rules[ift_i][rule_no - 1];
}

int
cpe_set_pm(cwmp_t *cwmp, const char *name, const char *value, int length, callback_register_func_t callback_reg)
{
	return FAULT_CODE_OK;
}

int
cpe_get_pm(cwmp_t *cwmp, const char *name, char **value, char *args, pool_t *pool)
{
	struct pm_rule *rule = NULL;
	char param[64] = {};
	char buf[128] = {};

	const char *enabled = "";

	rule = name_to_rule(cwmp, name, param, sizeof(param));

	if (!rule)
		return FAULT_CODE_9002;

	enabled = cwmp_nvram_get("PortForwardEnable");

	if (!strcmp("PortMappingEnabled", param)) {
		if (*enabled == '1' || *enabled == 't') {
			*value = "true";
		} else {
			*value = "false";
		}
	} else if (!strcmp("Alias", param)) {
		*value = pool_pstrdup(pool, "");
	} else if (!strcmp("PortMappingLeaseDuration", param)) {
		/* not supported timed rules */
		*value = "0";
	} else if (!strcmp("RemoteHost", param)) {
		*value = pool_pstrdup(pool, rule->addr);
	} else if (!strcmp("ExternalPort", param)) {
		snprintf(buf, sizeof(buf), "%u", rule->dport_min);
		*value = pool_pstrdup(pool, buf);
	} else if (!strcmp("ExternalPortEndRange", param)) {
		snprintf(buf, sizeof(buf), "%u", rule->dport_max);
		*value = pool_pstrdup(pool, buf);
	} else if (!strcmp("InternalPort", param)) {
		snprintf(buf, sizeof(buf), "%u", rule->sport_max);
		*value = pool_pstrdup(pool, buf);
	} else if (!strcmp("PortMappingProtocol", param)) {
		switch (rule->proto) {
			case PM_TCP:
				*value = "TCP";
				break;
			case PM_UDP:
				*value = "UDP";
				break;
			default:
				return FAULT_CODE_9002;
		}
	} else if (!strcmp("InternalClient", param)) {
		/* not supported: address must be getted from device (VPN or WAN) */
		*value = "0.0.0.0";
	} else if (!strcmp("PortMappingDescription", param)) {
		*value = pool_pstrdup(pool, rule->description);
	}

	return FAULT_CODE_OK;
}

