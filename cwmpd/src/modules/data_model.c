/* vim: set et: */
#include "cwmp/model.h"
#include "data_model.h"
#include "cwmp_module.h"

#define DM_TRACE_REFRESH() \
	cwmp_log_trace("%s(cwmp=%p, param_node=%p [name=%s], callback_reg=%p)",\
			__func__, (void*)cwmp,\
			(void*)param_node,\
            (param_node ? param_node->name : ""), (void*)callback_reg);

#define DM_TRACE_SET() \
    cwmp_log_trace("%s(cwmp=%p, name=\"%s\", value=\"%s\", length=%d, args=\"%s\", callback_reg=%p)",\
            __func__, (void*)cwmp, name, value, length, args, (void*)callback_reg);

#define DM_TRACE_GET() \
    cwmp_log_trace("%s(cwmp=%p, name=\"%s\", value=%p, args=\"%s\", pool=%p)",\
            __func__, (void*)cwmp, name, (void*)value, args, (void*)pool);

#define DM_TRACE_RELOAD() \
    cwmp_log_trace("%s(cwmp=%p, callback_reg=%p)",\
            __func__, (void*)cwmp, (void*)callback_reg);

#include "InternetGatewayDevice/InternetGatewayDevice.c"
#include "alias.c"

model_func_t ModelFunction[] =
{
    {"cpe_reload_all", cpe_reload_all},
    {"cpe_get_alias", cpe_get_alias},
    {"cpe_set_alias", cpe_set_alias},
    {"cpe_get_igd_di_uptime", cpe_get_igd_di_uptime},
    {"cpe_get_igd_di_manufacturer", cpe_get_igd_di_manufacturer},
    {"cpe_get_igd_di_manufactureroui", cpe_get_igd_di_manufactureroui},
    {"cpe_get_igd_di_productclass", cpe_get_igd_di_productclass},
/*    {"cpe_get_igd_di_serialnumber", cpe_get_igd_di_serialnumber},
    {"cpe_get_igd_di_specversion", cpe_get_igd_di_specversion},
    {"cpe_get_igd_di_hardwareversion", cpe_get_igd_di_hardwareversion},
    {"cpe_get_igd_di_softwareversion", cpe_get_igd_di_softwareversion},
    {"cpe_get_igd_di_provisioningcode", cpe_get_igd_di_provisioningcode},
*/
    {"cpe_reload_user", cpe_reload_user},
    {"cpe_get_user_mngmt_enable", cpe_get_user_mngmt_enable},
    {"cpe_set_user_mngmt_enable", cpe_set_user_mngmt_enable},
    {"cpe_set_user_name", cpe_set_user_name},

    {"cpe_get_igd_di_devicelog", cpe_get_igd_di_devicelog},

    {"cpe_get_ms_periodic_inform_enable", cpe_get_ms_periodic_inform_enable},
    {"cpe_set_ms_periodic_inform_enable", cpe_set_ms_periodic_inform_enable},
    {"cpe_get_ms_periodic_inform_interval", cpe_get_ms_periodic_inform_interval},
    {"cpe_set_ms_periodic_inform_interval", cpe_set_ms_periodic_inform_interval},
    {"cpe_get_igd_ms_username", cpe_get_igd_ms_username},
    {"cpe_get_igd_ms_password", cpe_get_igd_ms_password},
    {"cpe_get_igd_ms_connectionrequesturl", cpe_get_igd_ms_connectionrequesturl},
    {"cpe_get_igd_ms_url", cpe_get_igd_ms_url},
    {"cpe_set_igd_ms_url", cpe_set_igd_ms_url},
    {"cpe_get_igd_ms_connectionrequestusername", cpe_get_igd_ms_connectionrequestusername},
    {"cpe_get_igd_ms_connectionrequestpassword", cpe_get_igd_ms_connectionrequestpassword},
    {"cpe_set_igd_ms_connectionrequestusername", cpe_set_igd_ms_connectionrequestusername},
    {"cpe_set_igd_ms_connectionrequestpassword", cpe_set_igd_ms_connectionrequestpassword},

    {"cpe_get_igd_lan_igmp_enabled", cpe_get_igd_lan_igmp_enabled},
    {"cpe_set_igd_lan_igmp_enabled", cpe_set_igd_lan_igmp_enabled},
    {"cpe_get_igd_lan_igmp_version", cpe_get_igd_lan_igmp_version},
    {"cpe_set_igd_lan_igmp_version", cpe_set_igd_lan_igmp_version},

    {"cpe_get_igd_lan_hcm_dhcpenable", cpe_get_igd_lan_hcm_dhcpenable},
    {"cpe_set_igd_lan_hcm_dhcpenable", cpe_set_igd_lan_hcm_dhcpenable},

    {"cpe_get_igd_lan_wlan_standard", cpe_get_igd_lan_wlan_standard},
    {"cpe_set_igd_lan_wlan_standard", cpe_set_igd_lan_wlan_standard},

    {"cpe_get_igd_lan_wlan_channel", cpe_get_igd_lan_wlan_channel},
    {"cpe_set_igd_lan_wlan_channel", cpe_set_igd_lan_wlan_channel},

    {"cpe_get_igd_lan_wlan_autochannel", cpe_get_igd_lan_wlan_autochannel},
    {"cpe_set_igd_lan_wlan_autochannel", cpe_set_igd_lan_wlan_autochannel},

    {"cpe_get_igd_lan_wlan_basicauthmode", cpe_get_igd_lan_wlan_basicauthmode},
    {"cpe_set_igd_lan_wlan_basicauthmode", cpe_set_igd_lan_wlan_basicauthmode},

    {"cpe_get_igd_lan_wlan_wpaauthmode", cpe_get_igd_lan_wlan_wpaauthmode},
    {"cpe_set_igd_lan_wlan_wpaauthmode", cpe_set_igd_lan_wlan_wpaauthmode},

    {"cpe_get_igd_lan_wlan_ieeeauthmode", cpe_get_igd_lan_wlan_ieeeauthmode},
    {"cpe_set_igd_lan_wlan_ieeeauthmode", cpe_set_igd_lan_wlan_ieeeauthmode},

    {"cpe_get_igd_lan_wlan_beacontype", cpe_get_igd_lan_wlan_beacontype},
    {"cpe_set_igd_lan_wlan_beacontype", cpe_set_igd_lan_wlan_beacontype},

    {"cpe_get_igd_lan_wlan_bssid", cpe_get_igd_lan_wlan_bssid},

    {"cpe_get_igd_wan_ppp_authprot", cpe_get_igd_wan_ppp_authprot},
    {"cpe_set_igd_wan_ppp_authprot", cpe_set_igd_wan_ppp_authprot},

    {"cpe_get_igd_wan_ppp_servicename", cpe_get_igd_wan_ppp_servicename},
    {"cpe_get_igd_wan_ppp_stats", cpe_get_igd_wan_ppp_stats},

//    {"cpe_get_igd_services_iptv_igmpversion", cpe_get_igd_services_iptv_igmpversion},
//    {"cpe_set_igd_services_iptv_igmpversion", cpe_set_igd_services_iptv_igmpversion},

    {"cpe_refresh_igd_wandevice", cpe_refresh_igd_wandevice},
    {"cpe_refresh_igd_wanconnectiondevice", cpe_refresh_igd_wanconnectiondevice},
    {"cpe_refresh_igd_wanipconnection", cpe_refresh_igd_wanipconnection},

    {"cpe_get_igd_wan_ip_addrtype", cpe_get_igd_wan_ip_addrtype},
    {"cpe_set_igd_wan_ip_addrtype", cpe_set_igd_wan_ip_addrtype},

    {"cpe_get_igd_wan_ip_rxtxbytes", cpe_get_igd_wan_ip_rxtxbytes},

    {"cpe_set_igd_wan_ip_dnsenabled", cpe_set_igd_wan_ip_dnsenabled},

    {"cpe_get_igd_wan_ip_dnsservers", cpe_get_igd_wan_ip_dnsservers},
    {"cpe_set_igd_wan_ip_dnsservers", cpe_set_igd_wan_ip_dnsservers},

    {"cpe_get_igd_l3f_defaultconnection", cpe_get_igd_l3f_defaultconnection},
    {"cpe_set_igd_l3f_defaultconnection", cpe_set_igd_l3f_defaultconnection},

	{"cpe_get_igd_wan_ip", cpe_get_igd_wan_ip},

    {"cpe_get_conf_string", cpe_get_conf_string},
    {"cpe_set_conf_string", cpe_set_conf_string},

    {"cpe_get_nvram_string_or_empty", cpe_get_nvram_string_or_empty},

    {"cpe_get_nvram_string", cpe_get_nvram_string},
    {"cpe_set_nvram_string", cpe_set_nvram_string},

    {"cpe_get_nvram_bool", cpe_get_nvram_bool},
    {"cpe_set_nvram_bool", cpe_set_nvram_bool},

    {"cpe_get_nvram_bool_onoff", cpe_get_nvram_bool_onoff},
    {"cpe_set_nvram_bool_onoff", cpe_set_nvram_bool_onoff},

    {"cpe_get_nvram_int", cpe_get_nvram_int},
    {"cpe_set_nvram_int", cpe_set_nvram_int},

//    {"cpe_set_nvram_bool", cpe_set_nvram_bool},

    {"cpe_get_const_string", cpe_get_const_string},

    {"cpe_set_null", cpe_set_null},
    {"cpe_add_null", cpe_add_null},

    {"cpe_get_igd_ping_success", cpe_get_igd_ping_success},
    {"cpe_get_igd_ping_failure", cpe_get_igd_ping_failure},
    {"cpe_get_igd_ping_average", cpe_get_igd_ping_average},
    {"cpe_get_igd_ping_minimum", cpe_get_igd_ping_minimum},
    {"cpe_get_igd_ping_maximum", cpe_get_igd_ping_maximum},
    {"cpe_set_igd_ping_state", cpe_set_igd_ping_state},
    {"cpe_set_igd_ping_dscp", cpe_set_igd_ping_dscp},
    {"cpe_set_igd_ping_host", cpe_set_igd_ping_host},
    {"cpe_set_igd_ping_iface", cpe_set_igd_ping_iface},
    {"cpe_set_igd_ping_repeat", cpe_set_igd_ping_repeat},
    {"cpe_set_igd_ping_data_size", cpe_set_igd_ping_data_size},
    {"cpe_set_igd_ping_timeout", cpe_set_igd_ping_timeout},
    {"cpe_get_igd_ping_state", cpe_get_igd_ping_state},
    {"cpe_get_igd_ping_dscp", cpe_get_igd_ping_dscp},
    {"cpe_get_igd_ping_host", cpe_get_igd_ping_host},
    {"cpe_get_igd_ping_iface", cpe_get_igd_ping_iface},
    {"cpe_get_igd_ping_repeat", cpe_get_igd_ping_repeat},
    {"cpe_get_igd_ping_data_size", cpe_get_igd_ping_data_size},
    {"cpe_get_igd_ping_timeout", cpe_get_igd_ping_timeout},

    {"cpe_get_pm", cpe_get_pm},
    {"cpe_set_pm", cpe_set_pm},
    {"cpe_add_pm", cpe_add_pm},
    {"cpe_del_pm", cpe_del_pm},
    {"cpe_refresh_pm", cpe_refresh_pm},
    {"cpe_reload_pm", cpe_reload_pm},

    {"cpe_get_time_status", cpe_get_time_status},
    {"cpe_get_time_localtime", cpe_get_time_localtime},
    {"cpe_get_time_zonename", cpe_get_time_zonename},

    {"cpe_refresh_LEIC", cpe_refresh_LEIC},
    {"cpe_get_LEIC_MAC", cpe_get_LEIC_MAC},
    {"cpe_get_LEIC_MaxBitRate", cpe_get_LEIC_MaxBitRate},
    {"cpe_get_LEIC_Name", cpe_get_LEIC_Name},
    {"cpe_get_LEIC_stats", cpe_get_LEIC_stats},
    {"cpe_get_LEIC_Status", cpe_get_LEIC_Status},
    {"cpe_get_LEIC_DuplexMode", cpe_get_LEIC_DuplexMode},
    {"cpe_set_LEIC_DuplexMode", cpe_set_LEIC_DuplexMode},
    {"cpe_get_LEIC_Enable", cpe_get_LEIC_Enable},
    {"cpe_set_LEIC_Enable", cpe_set_LEIC_Enable},
    {"cpe_get_LEIC_MACcontrol", cpe_get_LEIC_MACcontrol},
    {"cpe_set_LEIC_MACcontrol", cpe_set_LEIC_MACcontrol},
    {"cpe_get_LEIC_number", cpe_get_LEIC_number},

    {"cpe_refresh_hosts", cpe_refresh_hosts},
    {"cpe_get_hosts_count", cpe_get_hosts_count},
    {"cpe_get_hosts", cpe_get_hosts},


    {"cpe_reload_trd", cpe_reload_trd},
    {"cpe_get_trd_state", cpe_get_trd_state},
    {"cpe_set_trd_state", cpe_set_trd_state},
    {"cpe_get_trd_iface", cpe_get_trd_iface},
    {"cpe_set_trd_iface", cpe_set_trd_iface},
    {"cpe_get_trd_host", cpe_get_trd_host},
    {"cpe_set_trd_host", cpe_set_trd_host},
    {"cpe_get_trd_tries", cpe_get_trd_tries},
    {"cpe_set_trd_tries", cpe_set_trd_tries},
    {"cpe_get_trd_timeout", cpe_get_trd_timeout},
    {"cpe_set_trd_timeout", cpe_set_trd_timeout},
    {"cpe_get_trd_dbs", cpe_get_trd_dbs},
    {"cpe_set_trd_dbs", cpe_set_trd_dbs},
    {"cpe_get_trd_dscp", cpe_get_trd_dscp},
    {"cpe_set_trd_dscp", cpe_set_trd_dscp},
    {"cpe_get_trd_mhc", cpe_get_trd_mhc},
    {"cpe_set_trd_mhc", cpe_set_trd_mhc},
    {"cpe_get_trd_hop", cpe_get_trd_hop},
    {"cpe_get_trd_hop_count", cpe_get_trd_hop_count},
    {"cpe_get_trd_response", cpe_get_trd_response},

    {"cpe_reload_dd", cpe_reload_dd},
    {"cpe_get_dd_dscp", cpe_get_dd_dscp},
    {"cpe_get_dd_epri", cpe_get_dd_epri},
    {"cpe_get_dd_iface", cpe_get_dd_iface},
    {"cpe_get_dd_result", cpe_get_dd_result},
    {"cpe_get_dd_state", cpe_get_dd_state},
    {"cpe_get_dd_url", cpe_get_dd_url},
    {"cpe_set_dd_dscp", cpe_set_dd_dscp},
    {"cpe_set_dd_epri", cpe_set_dd_epri},
    {"cpe_set_dd_iface", cpe_set_dd_iface},
    {"cpe_set_dd_state", cpe_set_dd_state},
    {"cpe_set_dd_url", cpe_set_dd_url},

    {"cpe_reload_ud", cpe_reload_ud},
    {"cpe_set_ud_iface", cpe_set_ud_iface},
    {"cpe_set_ud_url", cpe_set_ud_url},
    {"cpe_set_ud_length", cpe_set_ud_length},
    {"cpe_set_ud_state", cpe_set_ud_state},
    {"cpe_get_ud_length", cpe_get_ud_length},
    {"cpe_get_ud_url", cpe_get_ud_url},
    {"cpe_get_ud_iface", cpe_get_ud_iface},
    {"cpe_get_ud_state", cpe_get_ud_state},
    {"cpe_get_ud", cpe_get_ud},

    {"cpe_get_wan_elc_status", cpe_get_wan_elc_status},

    {"cpe_get_wan_eic_stats", cpe_get_wan_eic_stats},
    {"cpe_get_eic_status", cpe_get_eic_status},
    {"cpe_get_eic_mac", cpe_get_eic_mac},
    {"cpe_get_wan_eic_mbr", cpe_get_wan_eic_mbr},
    {"cpe_get_wan_eic_duplex", cpe_get_wan_eic_duplex},
    {"cpe_set_wan_eic_duplex", cpe_set_wan_eic_duplex},
    {"cpe_set_wan_eic_mbr", cpe_set_wan_eic_mbr},

    {"cpe_get_lhcm_ipi_addr_type", cpe_get_lhcm_ipi_addr_type},
};

const char *cwmp_model_ptr_to_func(void *p)
{
    int n = (sizeof(ModelFunction) / sizeof(*ModelFunction));

    if (!p) {
        return "null";
    }

    while (n-- > 0) {
        if (ModelFunction[n].func == p)
            return ModelFunction[n].name;
    }
    return "?";
}

int get_index_after_paramname(parameter_node_t * param, const char * tag_name)
{
    parameter_node_t * parent;
    parameter_node_t * tmp;
    for(parent=param->parent, tmp = param; parent; tmp = parent, parent = parent->parent)
    {
        if(TRstrcmp(parent->name, tag_name) == 0)
        {
             if(is_digit(tmp->name) == 0)
             {
                return TRatoi(tmp->name);
             }
        }
    }
    return -1;
}


void cwmp_model_load(cwmp_t * cwmp, const char * xmlfile)
{

    cwmp_model_load_xml(cwmp, xmlfile, ModelFunction, sizeof(ModelFunction)/sizeof(model_func_t));
}

//constant string getter
int cpe_get_const_string(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    *value = pool_pstrdup(pool, args);
    return FAULT_CODE_OK;
}

//config string getter
int cpe_get_conf_string(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();

    char* nvval = cwmp_conf_pool_get(pool, args);
    if (nvval == NULL) {
        cwmp_log_error("cpe_get_conf_string: undefined param (%s)!",args);
	return FAULT_CODE_9002;
    }

    *value = nvval;
//    cwmp_log_error("cpe_get_conf_string: value is %s",*value);
    return FAULT_CODE_OK;
}

//conf string setter
int cpe_set_conf_string(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (value == NULL)
    {
        cwmp_log_error("cpe_set_conf_string: param (%s) value is NULL", name);
	return FAULT_CODE_9002;
    }

    cwmp_conf_set(args,value);
    return FAULT_CODE_OK;
}



//nvram string getter
int cpe_get_nvram_string(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();

    char* nvval = cwmp_nvram_pool_get(pool, args);
    if (nvval == NULL) {
        cwmp_log_error("cpe_get_nvram_string: undefined param (%s)!",args);
	return FAULT_CODE_9002;
    }

    *value = nvval;
//    cwmp_log_error("cpe_get_nvram_string: value is %s",*value);
    return FAULT_CODE_OK;
}

int cpe_get_nvram_string_or_empty(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{

    DM_TRACE_GET();

    char* nvval = cwmp_nvram_pool_get(pool, args);
    if (nvval == NULL) {
	*value = pool_pstrdup(pool, "0");
	*value[0] = '\0';
	return FAULT_CODE_OK;
    }

    *value = nvval;
    return FAULT_CODE_OK;
}

//nvram bool getter
int cpe_get_nvram_bool(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();

    const char* nvval = cwmp_nvram_pool_get(pool, args);
    if (nvval == NULL) {
    cwmp_log_error("cpe_get_nvram_bool: undefined param (%s)!",args);
	return FAULT_CODE_9002;
    }

    int val = (nvval[0] == '1');
    const char* valStr = val?"1":"0";

    *value = pool_pstrdup(pool, valStr);
//    cwmp_log_debug("cpe_get_igd_lan_hcm_dhcpenabled: value is %s", *value);
//    cwmp_log_debug("cpe_get_nvram_string: value is %s",*value);
    return FAULT_CODE_OK;

}

//nvram bool getter
int cpe_get_nvram_bool_onoff(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{

    DM_TRACE_GET();

    const char* nvval = cwmp_nvram_pool_get(pool, args);
    if (nvval == NULL) {
	cwmp_log_error("cpe_get_nvram_bool: undefined param (%s)!",args);
	return FAULT_CODE_9002;
    }

    if (nvval[0] == '\0') {
	cwmp_log_error("cpe_get_nvram_bool: zero param (%s)!",args);
	return FAULT_CODE_9002;
    }

    int val = (nvval[0] == 'o' && nvval[1] == 'n');
    const char* valStr = val?"1":"0";

    *value = pool_pstrdup(pool, valStr);
//    cwmp_log_debug("cpe_get_igd_lan_hcm_dhcpenabled: value is %s", *value);
//    cwmp_log_debug("cpe_get_nvram_string: value is %s",*value);
    return FAULT_CODE_OK;

}




//nvram bool getter
int cpe_get_nvram_int(cwmp_t * cwmp, const char * name, char ** value, char * args, pool_t * pool)
{
    DM_TRACE_GET();

    const char* nvval = cwmp_nvram_pool_get(pool, args);
    if (nvval == NULL)
    {
	cwmp_log_error("cpe_get_nvram_bool: undefined param (%s)!",args);
	return FAULT_CODE_9002;
    }

    long val = strtol(nvval, NULL, 10);
    char valStr[256];// = pool_palloc(pool, strlen(val));
    snprintf(&valStr[0], 256, "%li",val);


    *value = pool_pstrdup(pool, &valStr);
//    cwmp_log_debug("cpe_get_igd_lan_hcm_dhcpenabled: value is %s", *value);
//    cwmp_log_debug("cpe_get_nvram_string: value is %s",*value);
    return FAULT_CODE_OK;

}



//nvram string setter
int cpe_set_nvram_string(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();

    if (value == NULL)
    {
        cwmp_log_error("%s: param (%s) value is NULL", __func__, name);
        return FAULT_CODE_9002;
    }

    cwmp_nvram_set(args,value);
    return FAULT_CODE_OK;
}

//nvram int setter
int cpe_set_nvram_int(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
	DM_TRACE_SET();

    if (value == NULL)
    {
        cwmp_log_error("cpe_set_nvram_string: param (%s) value is NULL", name);
        return FAULT_CODE_9002;
    }

    long val = strtol(value, NULL, 10);
    char valStr[256];
    snprintf(&valStr[0], 256, "%li",val);

    cwmp_nvram_set(args,valStr);
    return FAULT_CODE_OK;
}


//nvram bool setter
int cpe_set_nvram_bool(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (value == NULL)
    {
        cwmp_log_error("cpe_set_nvram_string: param (%s) value is NULL", name);
	return FAULT_CODE_9002;
    }

    long val = strtol(value, NULL, 10);
    cwmp_nvram_set(args,val?"1":"0");
    return FAULT_CODE_OK;
}

//nvram bool setter
int cpe_set_nvram_bool_onoff(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
    DM_TRACE_SET();
    if (value == NULL)
    {
        cwmp_log_error("cpe_set_nvram_string: param (%s) value is NULL", name);
	return FAULT_CODE_9002;
    }

    long val = strtol(value, NULL, 10);
    if (val > 1) val = 1;
    if (val < 0) val = 0;
    char valStr[4] = {0};

    strcpy(&valStr[0], val?"on":"off");
//    snprintf(&valStr, 256, "%li",val);

    cwmp_nvram_set(args,valStr);
    return FAULT_CODE_OK;
}


int cpe_set_null(cwmp_t * cwmp, const char * name, const char * value, int length, char * args, callback_register_func_t callback_reg)
{
    return FAULT_CODE_OK;
}

int cpe_add_null(cwmp_t * cwmp, parameter_node_t * param_node, int *pinstance_number, callback_register_func_t callback_reg)
{
    *pinstance_number = 1;

    return FAULT_CODE_OK;
}
