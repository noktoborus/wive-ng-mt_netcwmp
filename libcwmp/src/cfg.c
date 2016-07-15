/* vim: set et: */
/************************************************************************
 * Id: cfg.c                                                            *
 *                                                                      *
 * TR069 Project:  A TR069 library in C                                 *
 * Copyright (C) 2013-2014  netcwmp.netcwmp group                                *
 *                                                                      *
 *                                                                      *
 * Email: netcwmp ( & ) gmail dot com                                *
 *                                                                      *
 ***********************************************************************/

#include <cwmp/cwmp.h>
#include <cwmp/pool.h>
#include <cwmp/log.h>
#include <cwmp/cfg.h>
#include <ini.h>

#ifndef MIN
# define MIN(x, y) (((x) > (y)) ? (y) : (x))
#endif

typedef struct conf_t conf_t;

struct conf_t {
    char * filename;
    FILE * fd;
};


static conf_t	* cwmp_conf_handle = NULL;

int cwmp_conf_open(const char * filename)
{
    FUNCTION_TRACE();
    cwmp_conf_handle = malloc(sizeof(cwmp_conf_handle));
    if (!cwmp_conf_handle) {
        cwmp_log_error("conf malloc faild.");
        return CWMP_ERROR;
    }
    cwmp_conf_handle->filename = TRstrdup(filename);
    return CWMP_OK;
}

void cwmp_conf_split(char * name, char **s , char **k)
{
    *s = strchr(name, ':');
    if(*s == NULL) {
        k = &name;
        *s = "cwmp";
    } else {
        *s[0] = 0;
        *k = *s+1;
        *s = name;
    }
}

int cwmp_conf_get(const char * key, char *value)
{
    char *s, *k;
    char name[INI_BUFFERSIZE] = {};

    char nvram_name[sizeof(name) + 3] = {};
    char nvram_val[256] = {};
    //char value[INI_BUFFERSIZE] = {};

    cwmp_log_trace("%s(\"%s\", %p)", __func__, key, (void*)value);

    if(key == NULL) {
        return CWMP_ERROR;
    }

    if (cwmp_conf_handle == NULL) {
        cwmp_log_error("cwmp_conf_get: config file handle is not initialized!");
        return CWMP_ERROR;
    }

    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);

    /* 'evn' only from config file */
    if (!TRstrcmp(s, "env")) {
        ini_gets(s, k, NULL, value, INI_BUFFERSIZE, cwmp_conf_handle->filename);
        cwmp_log_debug("cwmp_conf_get(%s) = '%s': readed from %s", key, value,
                cwmp_conf_handle->filename);
        return CWMP_OK;
    }
    /* get nvram value */
    TRsnprintf(nvram_name, sizeof(nvram_name), "%s_%s", s, k);
    cwmp_nvram_get(nvram_name, nvram_val);

    if (!*nvram_val) {
        ini_gets(s, k, NULL, value, INI_BUFFERSIZE, cwmp_conf_handle->filename);
        cwmp_log_debug("cwmp_conf_get(%s) = '%s': write to nvram", key, value);
        TRstrncpy(nvram_val, value, MIN(INI_BUFFERSIZE, sizeof(nvram_val)));
        cwmp_nvram_set(nvram_name, nvram_val);
    } else {
        TRstrncpy(value, nvram_val, MIN(INI_BUFFERSIZE, sizeof(nvram_val)));
        cwmp_log_debug("cwmp_conf_get(%s) = '%s': readed from nvram",
                key, value);
    }

    return CWMP_OK;
}

int cwmp_conf_set(const char * key, const char * value)
{
    char * s, *k;
    char name[INI_BUFFERSIZE] = {0};
    FUNCTION_TRACE();
    if(key == NULL) {
        return CWMP_ERROR;
    }
    if (cwmp_conf_handle == NULL) {
        cwmp_log_error("cwmp_conf_get: config file handle is not initialized!");
        return CWMP_ERROR;
    }

    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);

    if (!TRstrcmp(s, "env")) {
        cwmp_log_debug("cwmp_conf_set(%s, %s): write to %s",
                key, value, cwmp_conf_handle->filename);
        return ini_puts(s, k, value, cwmp_conf_handle->filename);
    } else {
        cwmp_log_debug("cwmp_conf_set(%s, %s): write to nvram", key, value);
        return cwmp_nvram_set(k, value);
    }
}

char * cwmp_conf_pool_get(pool_t * pool, const char * key)
{
    char value[INI_BUFFERSIZE] = {0};

    FUNCTION_TRACE();

    cwmp_conf_get(key, value);

    return pool_pstrdup(pool, value);
}

int cwmp_conf_get_int(const char * key)
{
    char * s, *k;
    char name[INI_BUFFERSIZE] = {};
    char nvram_name[sizeof(name) + 3] = {};
    char nvram_val[256] = {};
    int rval = 0;

    FUNCTION_TRACE();
    if(key == NULL) {
        return 0;
    }
    TRstrncpy(name, key, INI_BUFFERSIZE);
    cwmp_conf_split(name, &s, &k);

    /* check value in nvram */
    TRsnprintf(nvram_name, sizeof(nvram_name), "%s_%s", s, k);
    cwmp_nvram_get(nvram_name, nvram_val);

    if (!*nvram_val) {
        /* get from cwmp.cfg and write to nvram */
        rval = (int)ini_getl(s, k, 0, cwmp_conf_handle->filename);
        cwmp_log_debug("cwmp_conf_get_int(%s) = %d: write to nvram",
                key, rval);
        TRsnprintf(nvram_val, sizeof(nvram_val), "%d", rval);
        cwmp_nvram_set(nvram_name, nvram_val);
    } else {
        /* get from nvram */
        rval = strtol(nvram_val, NULL, 10);
        cwmp_log_debug("cwmp_conf_get_int(%s) = %d: readed from nvram",
                key, rval);
    }
    return rval;
}


int cwmp_nvram_set(const char * key, const char * value)
{
    cwmp_log_debug("cwmp_nvram_set(%s, %s)", key, value);
    //FIXME: libnvram check const!
    return nvram_set(RT2860_NVRAM, (char*) key, (char*) value);
}



int cwmp_nvram_get(const char * key, char *value)
{
    char* nvval;
    //FIXME: libnvram check const!
    nvval = nvram_get(RT2860_NVRAM, (char*) key);
    cwmp_log_debug("cwmp_nvram_get(%s) = %s", key, nvval);
    strcpy(value, nvval);
    return CWMP_OK;//strlen(nvval);
}

char * cwmp_nvram_pool_get(pool_t * pool, const char * key)
{
//    char keybuf[1024];
//    sprintf(keybuf,"nvram:%s",key);
//    return cwmp_conf_pool_get(pool, keybuf);
    //FIXME: libnvram check const!
    char* val = nvram_get(RT2860_NVRAM, (char*)key);
    cwmp_log_debug("cwmp_nvram_pool_get: %s=%s (%i)",key,val, val);

    return pool_pstrdup(pool,val);
}



int cwmp_nvram_get_int(const char * key, int def)
{
    char valbuf[256];
    cwmp_nvram_get(key,&valbuf[0]);

    if (strlen(valbuf) == 0) {
        return def;
    }

    return strtol(&valbuf[0], NULL, 10);

}

int cwmp_nvram_get_bool_onoff(const char * key, int def)
{
    char valbuf[256];
    cwmp_nvram_get(key,&valbuf[0]);

    if (strlen(valbuf) == 0) {
        return def;
    }

    if (strcmp(valbuf,"on") == 0) return 1;
    else if (strcmp(valbuf,"off") == 0) return 0;

    return def;

}

