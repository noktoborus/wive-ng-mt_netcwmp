/* vim: set et: */
//FIXME: Multichannel auth functions!

BOOL prefix(const char *str, const char *pre)
{
    return strncmp(pre, str, strlen(pre)) == 0;
}

int cpe_get_igd_lan_wlan_bssid(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_bssid\n");
    char if_hw[18] = {0};

    char* ifstart = cwmp_nvram_pool_get(pool,"BssidIfName");
    char ifname[20] = {0};
    strcat(ifname,ifstart);
    strcat(ifname,args);

    if (getIfMac(ifname, if_hw, ':') == -1) *value = pool_pstrdup(pool,"00:00:00:00:00:00");
    else *value = pool_pstrdup(pool,if_hw);

    cwmp_log_debug("DEBUG cpe_get_igd_lan_wlan_bssid: BSSID%s %s \n",args,*value);

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_autochannel(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_autochannel\n");
    int chan =  cwmp_nvram_get_int("Channel", 0);
    int autoselect = cwmp_nvram_get_int("AutoChannelSelect",1);

    *value = pool_pstrdup(pool, ((chan==0) || autoselect)?"1":"0");

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_autochannel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_autochannel\n");
    if (value == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_autochannel: undefined value!");
	return FAULT_CODE_9002;
    }

    if (value[0] == '1') {
	cwmp_nvram_set("Channel","0");
	cwmp_nvram_set("AutoChannelSelect","1");
    }
    else
    {
        int chan =  cwmp_nvram_get_int("Channel", 0);
	cwmp_nvram_set("AutoChannelSelect","0");
	if (chan == 0) cwmp_nvram_set("Channel", "9");
    }

    return FAULT_CODE_OK;
}

int cpe_get_igd_lan_wlan_channel(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_channel\n");
    char* chan =  cwmp_nvram_pool_get(pool, "Channel");
    if (chan == NULL)
    {
	chan = "0";
    }

    int autoselect = cwmp_nvram_get_int("AutoChannelSelect",1);

    if (autoselect)
    {
	*value = pool_pstrdup(pool, "0");
    }
    else
    {
	*value = pool_pstrdup(pool, chan);
    }


    return FAULT_CODE_OK;

}

int cpe_set_igd_lan_wlan_channel(cwmp_t * cwmp, const char * name, const char * value, int length, callback_register_func_t callback_reg)
{
    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_channel\n");

    if (value == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_channel: undefined value!");
	return FAULT_CODE_9002;
    }

    cwmp_nvram_set("Channel",value);

    if (value[0] == '0' && value[1] == '\0') {
	cwmp_nvram_set("AutoChannelSelect", "1");
    }
    else
    {
	cwmp_nvram_set("AutoChannelSelect", "0");
    }

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_standard(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_standard\n");
    int standard =  cwmp_nvram_get_int("WirelessMode", 9);

    char* stdstr;

    switch (standard) {

	case 0: stdstr = "b/g/n";break;
	case 1: stdstr = "b";break;
	case 4: stdstr = "g";break;
	case 6: stdstr = "n";break;
	case 7: stdstr = "b/g/n";break;
	case 9: stdstr = "b/g/n";break;
	default: stdstr = "b/g/n";break;
    }

    *value = pool_pstrdup(pool, stdstr);
    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_standard %s\n",stdstr);

    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_standard(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    char* valStr = "9";

	DM_TRACE_SET();
    if (strcmp(value, "n") == 0) valStr="6";else
    if (strcmp(value, "g") == 0) valStr="4";else
    if (strcmp(value, "b") == 0) valStr="1";

    cwmp_nvram_set("WirelessMode", valStr);

    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_standard %s \n", valStr);

    return FAULT_CODE_OK;
}



//InternetGatewayDevice.LANDevice.WLANConfiguration.BasicAuthenticationMode
int cpe_get_igd_lan_wlan_basicauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const char* authMode = NULL;

	DM_TRACE_GET();
	authMode = cwmp_nvram_pool_get(pool, "AuthMode");
    if (authMode == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_basicauthmode: undefined AuthMode param!");
	return FAULT_CODE_9002;
    }

    char* valStr = prefix(authMode,"Disable;")?"None":"EAPAuthentication";


    *value = pool_pstrdup(pool, valStr);

    cwmp_log_debug("cpe_get_igd_lan_wlan_basicauthmode: value is %s", valStr);
    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_basicauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();

    if (strcmp(value,"None") == 0 ) cwmp_nvram_set("AuthMode", "Disable;Disable;Disable");

    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_wpaauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const char* authMode = NULL;

	DM_TRACE_GET();
	authMode = cwmp_nvram_pool_get(pool, "AuthMode");
    if (authMode == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_wpaauthmode: undefined AuthMode param!");
	return FAULT_CODE_9002;
    }


    char* valStr = "EAPAuthentication";//prefix(authMode,"Disable;")?"None":"EAPAuthentication";
    if (prefix(authMode,"WPAPSK;")) valStr = "PSKAuthentication"; else
    if (prefix(authMode,"WPA2PSK;")) valStr = "PSKAuthentication"; else
    if (prefix(authMode,"WPAPSKWPA2PSK;")) valStr = "PSKAuthentication";

    *value = pool_pstrdup(pool, valStr);

    cwmp_log_debug("DEBUG: cpe_get_igd_lan_wlan_wpaauthmode value is %s \n", valStr);
    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_wpaauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
    //FIXME: STUB

    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_wpaauthmode\n");
    return FAULT_CODE_OK;
}

int cpe_get_igd_lan_wlan_ieeeauthmode(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const char* authMode = NULL;

	DM_TRACE_GET();
	authMode = cwmp_nvram_pool_get(pool, "AuthMode");
    if (authMode == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_ieeeauthmode: undefined AuthMode param!");
	return FAULT_CODE_9002;
    }

    char* valStr = "EAPAuthentication";//prefix(authMode,"Disable;")?"None":"EAPAuthentication";
    if (prefix(authMode,"WPAPSK;")) valStr = "PSKAuthentication";
    if (prefix(authMode,"WPA2PSK;")) valStr = "PSKAuthentication";
    if (prefix(authMode,"WPAPSKWPA2PSK;")) valStr = "PSKAuthentication";

    *value = pool_pstrdup(pool, valStr);

    cwmp_log_debug("cpe_get_igd_lan_wlan_ieeeauthmode: value is %s", valStr);
    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_ieeeauthmode(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();
    //FIXME: STUB

    cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_ieeeauthmode\n");
    return FAULT_CODE_OK;
}


int cpe_get_igd_lan_wlan_beacontype(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    const char* authMode = NULL;

	DM_TRACE_GET();
	authMode = cwmp_nvram_pool_get(pool, "AuthMode");
    if (authMode == NULL) {
	cwmp_log_error("cpe_get_igd_lan_wlan_beacontype: undefined AuthMode param!");
	return FAULT_CODE_9002;
    }

    char* valStr = "Basic";

    if (prefix(authMode,"WPA1WPA2;")) valStr = "WPAand11i"; else
    if (prefix(authMode,"WPAPSKWPA2PSK;")) valStr = "WPAand11i"; else
    if (prefix(authMode,"WPA2PSK;")) valStr = "11i"; else
    if (prefix(authMode,"WPA2;")) valStr = "11i"; else
    if (prefix(authMode,"WPA;")) valStr = "WPA"; else
    if (prefix(authMode,"WPAPSK;")) valStr = "WPA";


    *value = pool_pstrdup(pool, valStr);

    cwmp_log_debug("cpe_get_igd_lan_wlan_beacontype: value is %s", valStr);
    return FAULT_CODE_OK;
}

int cpe_set_igd_lan_wlan_beacontype(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    char* authStr = "WPAPSKWPA2PSK;WPAPSKWPA2PSK;WPAPSKWPA2PSK";

	DM_TRACE_SET();
    if (value == 0) cwmp_log_debug("DEBUG: cpe_set_igd_lan_wlan_beacontype VALUE IS NULL\n");

    if (strcmp(value,"WPAand11i") == 0) authStr = "WPAPSKWPA2PSK;WPAPSKWPA2PSK;WPAPSKWPA2PSK"; else
    if (strcmp(value,"11i") == 0) authStr = "WPA2PSK;WPA2PSK;WPA2PSK"; else
    if (strcmp(value,"WPA") == 0) authStr = "WPAPSK;WPAPSK;WPAPSK"; else
    if (strcmp(value,"Basic") == 0) authStr = "Disable;Disable;Disable";

    cwmp_nvram_set("AuthMode", authStr);

    cwmp_log_debug("cpe_set_igd_lan_wlan_beacontype: set value %s\n", authStr);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_possiblechannels(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int v = 0;

    DM_TRACE_GET();
    v = cwmp_nvram_get_int("CountryRegion", -1);

    switch (v) {
        case 0:
            *value = "1-11";
            break;
        case 1:
            *value = "1-13";
            break;
        case 2:
            *value = "10-11";
            break;
        case 3:
            *value = "10-13";
            break;
        case 4:
            *value = "14";
            break;
        case 5:
            *value = "1-14";
            break;
        case 6:
            *value = "3-9";
            break;
        case 7:
            *value = "5-13";
            break;
        default:
            cwmp_log_error("%s: error get CountryRegion nvram value", __func__);
            return FAULT_CODE_9002;
    }

    return FAULT_CODE_OK;
}

/* WPA Encryptions:
 *   WEPEncryption (DEPRECATED)
 *   TKIPEncryption
 *   WEPandTKIPEncryption (DEPRECATED)
 *   AESEncryption (OPTIONAL)
 *   WEPandAESEncryption (DEPRECATED)
 *   TKIPandAESEncryption (OPTIONAL)
 *   WEPandTKIPandAESEncryption (DEPRECATED)
 */

int
cpe_set_igd_lan_wlan_wpaencryption(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (!strcmp(value, "TKIPEncryption")) {
        cwmp_nvram_set("EncrypType", "TKIP");
    } else if (!strcmp(value, "AESEncryption")) {
        cwmp_nvram_set("EncrypType", "AES");
    } else if (!strcmp(value, "TKIPandAESEncryption")) {
        cwmp_nvram_set("EncrypType", "TKIPAES");
    } else {
        cwmp_log_trace(
                "%s: invalid value '%s', supports only: "
                "TKIPEncryption, AESEncryption, TKIPandAESEncryption",
                __func__, value);
        return FAULT_CODE_9007;
    }
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_wpaencryption(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *mode = NULL;

    DM_TRACE_GET();
    mode = cwmp_nvram_get("EncrypType");

    if (!strcmp(mode, "TKIPAES")) {
        *value = "TKIPandAESEncryption";
    } else if (!strcmp(mode, "TKIP")) {
        *value = "AESEncryption";
    } else if (!strcmp(mode, "AES")) {
        *value = "TKIPEncryption";
    }
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_status(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *v = NULL;
    DM_TRACE_GET();
    v = cwmp_nvram_get("RadioOn");
    if (*v == '0') {
        *value = "Disabled";
    } else if (*v == '1') {
        *value = "Up";
    } else {
        *value = "Error";
        cwmp_log_error("%s: nvram RadioOn invalid value: '%s'", __func__, v);
    }
    return FAULT_CODE_OK;
}

int
cpe_set_igd_lan_wlan_enabled(cwmp_t * cwmp, const char * name, const char * value, int length, char *args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (*value == '0') {
        cwmp_nvram_set("RadioOn", "0");
    } else if (*value == '1') {
        cwmp_nvram_set("RadioOn", "1");
    } else {
        cwmp_log_error("%s: invalid value: '%s'", __func__, value);
        return FAULT_CODE_9007;
    }
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_enabled(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char *v = NULL;
    DM_TRACE_GET();
    v = cwmp_nvram_get("RadioOn");
    if (*v == '0') {
        *value = "0";
    } else if (*v == '1') {
        *value = "1";
    } else {
        *value = "0";
        cwmp_log_error("%s: nvram RadioOn invalid value: '%s'", __func__, v);
    }
    return FAULT_CODE_OK;
}



static struct wlan_assoc
{
    char mac[18];
    char addr[40];
    bool authenticated;
} *wlan_assoc;

static unsigned wlan_assoc_count;

static void
igd_lan_wlan_arp(const char *n, struct wlan_assoc *wa)
{
    char arp_addr[40];
    char arp_mac[18];
    FILE *f = fopen("/proc/net/arp", "r");
    int r = EOF;

    if (!f) {
        cwmp_log_error(
                "%s: fopen(\"/proc/net/arp\", \"r\") failure: %s",
                n, strerror(errno));
        return;
    }

	/* skip header */
	fscanf(f, "IP address HW type Flags HW address Mask Device");
	/* process */
	while ((r = fscanf(f, "%s %*x %*x %s %*s %*s",
				arp_addr, arp_mac)) != EOF) {
		/* skip invalid matching */
		if (r != 2)
			continue;
        if (!strcmp(wa->mac, arp_mac)) {
            memcpy(wa->addr, arp_addr, sizeof(wa->addr));
            break;
        }
    }
    fclose(f);
}

int
cpe_refresh_igd_lan_wlan_associated(cwmp_t * cwmp, parameter_node_t * param_node, callback_register_func_t callback_reg)
{
	RT_802_11_MAC_TABLE table24 = {};
	RT_802_11_MAC_ENTRY *pe = NULL;
    int row_no = 0;
    parameter_node_t *pn = NULL;

    DM_TRACE_REFRESH();
    /* delete */
    cwmp_model_delete_object_child(cwmp, param_node);
    if (wlan_assoc) {
        free(wlan_assoc);
        wlan_assoc = NULL;
        wlan_assoc_count = 0u;
    }

    /* populate 2.4GHz */
	getWlanStationTable(&table24, 1);

    wlan_assoc = calloc(table24.Num, sizeof(*wlan_assoc));
    if (!wlan_assoc) {
        cwmp_log_error("%s: calloc(%d) failed: %s",
                __func__, table24.Num * sizeof(*wlan_assoc), strerror(errno));
        return FAULT_CODE_9002;
    }
    wlan_assoc_count = table24.Num;

    for (row_no = 0; row_no < table24.Num; row_no++) {
        pe = &(table24.Entry[row_no]);
        snprintf(wlan_assoc[row_no].mac,
                sizeof(wlan_assoc[row_no].mac),
                "%02x:%02x:%02x:%02x:%02x:%02x",
                pe->Addr[0], pe->Addr[1], pe->Addr[2],
                pe->Addr[3], pe->Addr[4], pe->Addr[5]);
        /* FIXME: too simple */
        igd_lan_wlan_arp(__func__, &wlan_assoc[row_no]);
		cwmp_model_copy_parameter(param_node, &pn, row_no + 1);
    }
    return FAULT_CODE_OK;
}

static long
igd_lan_wlan_no_from_path(cwmp_t *cwmp, const char *name)
{
	parameter_node_t *pn = NULL;
	long no = 0;

	pn = cwmp_get_parameter_path_node(cwmp->root, name);
	if (!pn || !(pn = pn->parent)) {
		cwmp_log_error("%s: can't get rule's number", name);
		return -1;
	}

	no = strtol(pn->name, NULL, 10);

	if (!no) {
		cwmp_log_error("%s: node name '%s' not a valid number", name, pn->name);
		return -1;
	}

	if ((unsigned long)no > wlan_assoc_count) {
		cwmp_log_error("%s: invalid rule number: %lu", name, no);
		return -1;
	}

	return (no - 1);
}


int
cpe_get_igd_lan_wlan_assoc_mac(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int no = -1;
    DM_TRACE_GET();
    no = igd_lan_wlan_no_from_path(cwmp, name);
    if (no == -1) {
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, wlan_assoc[no].mac);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_assoc_addr(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    int no = -1;
    DM_TRACE_GET();
    no = igd_lan_wlan_no_from_path(cwmp, name);
    if (no == -1) {
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, wlan_assoc[no].addr);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_assoc_state(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();
    *value = "1";
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_associated_count(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char buf[42] = {};
    DM_TRACE_GET();
    snprintf(buf, sizeof(buf), "%u", wlan_assoc_count);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_set_igd_lan_wlan_wepkey(cwmp_t *cwmp, const char *name, const char *value, int length, char *args, callback_register_func_t callback_reg)
{
    char tkey[42] = {};
    char key[42] = {};
    char *end = NULL;

    DM_TRACE_SET();
    snprintf(tkey, sizeof(tkey), "Key%sType", args);
    snprintf(key, sizeof(key), "Key%sStr1", args);

    if (length != 10 || length != 26) {
        cwmp_log_trace("%s: invalid value length: %d, must be equal 10 or 26",
                __func__, length);
        return FAULT_CODE_9007;
    }

    strtoul(value, &end, 16);
    if (end && *end) {
        cwmp_log_error("%s: invalid hex: '%s' at symbol number %"PRIuPTR,
            __func__, value, end - value);
        return FAULT_CODE_9007;
    }

    cwmp_nvram_set(tkey, "0");
    cwmp_nvram_set(key, value);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_wepkey(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    char tkey[42] = {};
    char key[42] = {};
    char *val = NULL;
    char hex[27];

    DM_TRACE_GET();
    snprintf(tkey, sizeof(tkey), "Key%sType", args);
    snprintf(key, sizeof(key), "Key%sStr1", args);

    if (cwmp_nvram_get_int(tkey, 0) == 0) {
        /* hex value */
        *value = cwmp_nvram_pool_get(pool, key);
    } else {
        /* ASCII value */
        val = cwmp_nvram_get(key);
        if (!*val) {
            return FAULT_CODE_OK;
        }
        cwmp_string_to_hex(val, hex, sizeof(hex));
        *value = pool_pstrdup(pool, hex);
    }
    return FAULT_CODE_OK;
}

static bool
get_igd_lan_wlan_txrx(struct nic_counts *result)
{
    int count = 0;
    int i = 0;
    struct nic_counts *nc = NULL;
    nc = nicscounts(&count);
    for (i = 0; i < count; i++) {
        if (!strcmp(nc[i].ifname, "ra0")) {
            memcpy(result, &nc[i], sizeof(*result));
            goto success;
        }
    }

    if (nc)
        free(nc);
    return false;
success:
    free(nc);
    return true;
}

int
cpe_get_igd_lan_wlan_tx_bytes(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.tx_bytes);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_rx_bytes(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.rx_bytes);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_tx_packets(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.tx_packets);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_rx_packets(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    struct nic_counts nc = {};
    char buf[42] = {};
    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }
    snprintf(buf, sizeof(buf), "%llu", nc.rx_packets);
    *value = pool_pstrdup(pool, buf);
    return FAULT_CODE_OK;
}

int
cpe_get_igd_lan_wlan_stats(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    parameter_node_t *pn = NULL;
    struct nic_counts nc = {};
    char buf[42] = "0";

    DM_TRACE_GET();
    if (!get_igd_lan_wlan_txrx(&nc)) {
        cwmp_log_error("%s: can't get counter for WLAN interface");
        return FAULT_CODE_9002;
    }

    pn  = cwmp_get_parameter_path_node(cwmp->root, name);

    if (!strcmp("ErrorsSent", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.tx_errs);
    } else if (!strcmp("ErrorsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_errs);
    } else if (!strcmp("UnicastPacketsSent", pn->name)) {
    } else if (!strcmp("UnicastPacketsReceived", pn->name)) {
    } else if (!strcmp("DiscardPacketsSent", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.tx_drops);
    } else if (!strcmp("DiscardPacketsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_drops);
    } else if (!strcmp("MulticastPacketsSent", pn->name)) {
    } else if (!strcmp("MulticastPacketsReceived", pn->name)) {
        snprintf(buf, sizeof(buf), "%llu", nc.rx_multi);
    } else if (!strcmp("BroadcastPacketsSent", pn->name)) {
    } else if (!strcmp("BroadcastPacketsReceived", pn->name)) {
    } else if (!strcmp("UnknownProtoPacketsReceived", pn->name)) {
    } else {
        cwmp_log_error("%s: unknown node name: %s", __func__, pn->name);
        return FAULT_CODE_9002;
    }
    *value = pool_pstrdup(pool, buf);

    return FAULT_CODE_OK;
}

