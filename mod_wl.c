/* 
 * Licensed to the Apache Software Foundation (ASF) under one or more
 *
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /*
 * mod_wl.c
  
 * Prevents user agent spoofing by reverse / forwarding ips 
 * more information on the procedure found at: 
 * https://modules.apache.org/modules.lua?id=13738
 * https://support.google.com/webmasters/answer/80553?hl=en
 *
 *
 * Nadir Hamid <matrix.nad@gmail.com> 16 May 2014
 * Based on mod_spamhaus
 */

/* std libraries */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <regex.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
/* apache libraries */
#include <string.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "apr_tables.h"
#include "apr_strings.h"


#define WL_MODULE_DEBUG_MODE 1
#define WL_MODULE_STATUS_OK "OK"
#define WL_MODULE_STATUS_FAIL "FAIL"
#define WL_MODULE_LOG_ID "mod_wl"

#define AP_LOG_DEBUG(rec, fmt, ...) ap_log_rerror(APLOG_MARK, APLOG_DEBUG,  0, rec, fmt, ##__VA_ARGS__)
#define AP_LOG_INFO(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_INFO,   0, rec, "[" WL_MODULE_LOG_ID "] " fmt, ##__VA_ARGS__)
#define AP_LOG_WARN(rec, fmt, ...)  ap_log_rerror(APLOG_MARK, APLOG_WARNING,0, rec, "[" WL_MODULE_LOG_ID "] " fmt, ##__VA_ARGS__)
#define AP_LOG_ERR(rec, fmt, ...)   ap_log_rerror(APLOG_MARK, APLOG_ERR,    0, rec, "[" WL_MODULE_LOG_ID "] " fmt, ##__VA_ARGS__)

typedef struct {
    char*          wl_dns_forward;
    char*          wl_dns_reverse;
} wl_dns_multi;

struct wl_list {
    char*                    addr;
    struct wl_list*          next; 
};

struct wl_bot_list {
    char*                    name;
    struct wl_bot_list*      next;
};

typedef struct       wl_list item;
typedef struct wl_bot_list  bitem;

typedef struct {
    char             context[256];
    char*                     bot;
    char*                    list;
    char*                   blist;
    char*                bhandler;
    char*                ahandler;
    char*                  btlist;
    int                     btany;
    int                    btauto;
    int                   enabled;
    int                     debug;
    int                  lenabled;
    int                dnstimeout;
    int			    spenv;
    bitem*                   cbot;
    bitem*                  chead;
} wl_config;

module AP_MODULE_DECLARE_DATA   
wl_module;

unsigned char                 wl_bytes[4];
static wl_config*   	      wl_cfg;
static int                    wl_init(request_rec* rec);
static int                    wl_close(int status);
static void                   wl_hooks(apr_pool_t* pool);
static char*                  wl_forward_dns(char* addr);
static char*                  wl_reverse_dns(char* addr);
static void                   wl_append_wl(char* addr); 
static void                   wl_append_bl(char* addr);
static void                   wl_strip_append_wl(char* addr);
static void                   wl_strip_append_bl(char* addr);
static void                   wl_fail(const char* what);
static void*                  wl_xmalloc(size_t sz);
static void 		      wl_reset_wl();
static int                    wl_in_wl(char* addr);
static void 		      wl_reset_bl();
static int                    wl_in_bl(char* addr);
static void                   wl_load_wl(char* fl, request_rec* rec);
static void                   wl_load_bl(char* fl, request_rec* rec);
static void 		      wl_reset_bots();
static void                   wl_load_bots(char* fl, request_rec* rec, wl_config* wl_cfg);
static void                   wl_strip_ip(char *addr, char* strip);
static char*                  wl_replace_ip(char* addr, char* rep, char* with);
const char*                   apr_table_get(const apr_table_t* t, const char* key);
static item*                  wl_element;
static item*                  bl_element;
inline static void            wl_strip_append_bot(char* bot, wl_config* wl_cfg);
inline static int             wl_in_agents(char* agent, wl_config* wl_cfg);
inline static void            wl_append_bot(wl_config* wl_cfg, char* bot);
inline static void*           wl_server_config(apr_pool_t* pool, server_rec* s);
inline static void*           wl_dir_config(apr_pool_t* pool, char* context);
inline static void            wl_append_list(char* fl, char* addr, request_rec* rec);
const char*                   wl_set_enabled(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_list_enabled(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_block_handler(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_bot(cmd_parms* cmd, void* cfg, const char* args);
const char*                   wl_set_list(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_blist(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_bot_auto_add(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_dns_timeout(cmd_parms* cmd, void* cfg, const char* arg);
const char*		      wl_concat(char* ip1, char* ip2);
static int                    wl_wl_loaded = 0;
static int                    wl_bl_loaded = 0;
static int                    wl_bots_loaded = 0;
static item*                  wl_head = NULL;
static item*                  bl_head = NULL;


/**
 * wl_fail is called whenever
 * an error happens throughout this module
 * 
 * @param what -> error message
 */
static void wl_fail(const char* what)
{
    fprintf(stderr, "wl_module: system call failed: %s: %s\n", what, what);
}

/**
 * internal malloc
 * report any error that arose from
 * wl's memory allocation
 * 
 * @param sz -> target allocation
 */
static void* wl_xmalloc(size_t sz)
{
    void* res = malloc(sz);
    if (res) return res;

    wl_fail((char*) "malloc");

    return (char*)"";
}

/**
 * reverse DNS a given address
 * 
 * @param addr -> IPv4 address
 */
static char* wl_reverse_dns(char* addr)
{
    struct hostent* he;
    struct in_addr ipv4addr;
    
    inet_pton(AF_INET, addr, &ipv4addr);
    he = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
    if ( he == NULL ) {
      return NULL;
    }
    
    return he->h_name;
}

/**
 * forward DNS a given address
 * 
 * @param addr -> IPv4 address
 */
static char* wl_forward_dns(char* addr_a)
{
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));    
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((status = getaddrinfo(addr_a, NULL, &hints, &res)) != 0) 
        return addr_a;

    p = res;

    while (p != NULL) {
            void* taddr;

            if (p->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in *) p->ai_addr;
                taddr = &(ipv4->sin_addr);
            }        

            inet_ntop(p->ai_family, taddr, ipstr, sizeof(ipstr));
            p = p->ai_next;
    }

    freeaddrinfo(res);
    memmove(addr_a, ipstr, sizeof(ipstr));

    return addr_a;
}

/**
 * verify if the user agent is an agent
 * we need to evaluate
 *
 * @param: agent -> HTTP Agent Tag
 * @param: wl_cfg -> module config
 */
inline static int wl_in_agents(char* agent, wl_config* wl_cfg)
{
    regex_t rgx;
    int rgx_state;
    size_t found = 0;

    if (wl_cfg->btany == 1)
        return 1;

    wl_strip_ip(agent, " ");

    while (wl_cfg->cbot != NULL) {
        rgx_state = regcomp(&rgx, wl_cfg->cbot->name, REG_EXTENDED);
        
        if (rgx_state)
            wl_fail("ERR: WL couldn't compile agaisnt expression");

        rgx_state = regexec(&rgx, agent, 0, NULL, 0);
    
        if (!rgx_state)
            found = 1;

        wl_cfg->cbot = wl_cfg->cbot->next;
    }
   
    wl_cfg->cbot = wl_cfg->chead; 

    return found;
}

/**
 * point the whitelist to 
 * it's head
 * 
 */
static void wl_reset_wl()
{
    wl_element = wl_head;
}

/**
 * same as wl_reset_wl/0
 * for blacklists
 * 
 */
static void wl_reset_bl()
{
    bl_element = bl_head;
}

/** 
 * append to the whitelist
 * in memory
 *
 * @param addr -> IPv4 address
 */
static void wl_append_wl(char* addr)
{
    wl_element = (item*) wl_xmalloc(sizeof(item));
    wl_element->addr = addr;
    wl_element->next = wl_head;
    wl_head = wl_element;
}

/**
 * same as wl_append_wl/1
 * for blacklists
 *
 * @param addr -> IPv4 address
 */
static void wl_append_bl(char* addr)
{
    bl_element = (item*) wl_xmalloc(sizeof(item));
    bl_element->addr = addr;
    bl_element->next = bl_head;
    bl_head = bl_element;
}

/**
 * append a new bot to
 * WL's configuration.
 *
 * @param wl_cfg -> module config
 * @param bot -> user agent substring (for bot). i.e: Yandex/2.1
 */
inline static void wl_append_bot(wl_config* wl_cfg, char* bot)
{
    wl_cfg->cbot = (bitem*) wl_xmalloc(sizeof(bitem));
    wl_cfg->cbot->name = bot;
    wl_cfg->cbot->next = wl_cfg->chead;
    wl_cfg->chead = wl_cfg->cbot;
}

/**
 * gets rid of any extra characters this ip addr
 * may have.
 *
 * @param addr -> IPv4 address
 * @param strip -> character delimiter
 */
static void wl_strip_ip(char *addr, char* strip)
{
    char *p, *q;

    for (q = p = addr; *p; p++)
        if (*p != *strip)
            *q++ = *p;

    *q = '\0';
}

/** 
 * concatenate two ip strings
 * 
 * @param ip1 -> IPv4 address
 * @param ip2 -> IPv4 address
 */
const char* wl_concat(char* ip1, char* ip2)
{
    char *result = malloc(strlen(ip1)+strlen(ip2)+1); //+1 for the zero-terminator
    strcpy(result, ip1);
    strcat(result, ip2);

    return result;
}

/** 
 * do any pre insertion checks before
 * appending to whitelist
 *  
 * @param addr -> IPv4 address
 */
static void wl_strip_append_wl(char* addr)
{
    wl_strip_ip(addr, " ");
    wl_strip_ip(addr, "\n");
    addr = wl_replace_ip(addr, (char*) "/32", (char*) "");
    addr = wl_replace_ip(addr, (char*) "/16", (char*) "");

    if (strcmp(addr, "") != -1)
        wl_append_wl(addr);
}

/* 
 * same as wl_strip_append_wl/1
 * for blacklists
 *
 * @param addr -> IPv4 address
 */
static void wl_strip_append_bl(char* addr)
{
    wl_strip_ip(addr, " ");
    wl_strip_ip(addr, "\n");
    addr = wl_replace_ip(addr, (char*) "/32", (char*) "");
    addr = wl_replace_ip(addr, (char*) "/16", (char*) "");

    if (strcmp(addr, "") != -1)
        wl_append_bl(addr);
}

/**
 * adds a user agent to our list of
 * bots
 *
 * @param bot -> HTTP user agent
 * @param wl_cfg -> module config
 */
inline static void wl_strip_append_bot(char* bot, wl_config* wl_cfg)
{
    wl_strip_ip(bot, " ");
    wl_strip_ip(bot, "\n");

    if (strcmp(bot, "") != -1)    
        wl_append_bot(wl_cfg, bot);
}

/**
 * remove the trailing /32 or /16
 * on a ip address
 *
 * @param addr -> IPv4 address
 * @param rep -> port string "/32" or "/16"
 * @param with -> replacement string
 */ 
static char* wl_replace_ip(char *addr, char *rep, char *with) {
    char *result;       //the return string
    char *ins;          // the next insert point
    char *tmp;          // varies
    int len_rep;        // length of rep
    int len_with;       // length of with
    int len_front;      // distance between rep and end of last rep
    int count;          // number of replacements

    result = "";

    if (!addr)
        return result;

    if (!rep)
        rep = "";

    len_rep = strlen(rep);

    if (!with)
        with = "";

    len_with = strlen(with);

    ins = addr;

    for (count = 0; (tmp = strstr(ins, rep)); ++count) 
        ins = tmp + len_rep;

    tmp = result = malloc(strlen(addr) + (len_with - len_rep) * count + 1);

    if (!result)
        return result;
    
    while (count--) {
        ins = strstr(addr, rep);
        len_front = ins - addr;
        tmp = strncpy(tmp, addr, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        addr += len_front + len_rep; // move to next "end of rep"
    }

    strcpy(tmp, addr);
    return result;
}

/**
 * point the bot list to 
 * head
 */
static void wl_reset_bots()
{
    wl_cfg->cbot = wl_cfg->chead;
}

/**
 * load a list of user agents
 *
 * @param fl -> path to file
 * @param rec -> Apache 2 request
 */
static void wl_load_bots(char* fl, request_rec* rec, wl_config* wl_cfg)
{
    apr_file_t* wl_file;
    apr_status_t wl_st;
    apr_size_t datalen = 256;
    char* data = ""; 
    char* bot;

    wl_st = apr_file_open(&wl_file, fl, APR_FOPEN_CREATE | APR_FOPEN_READ, 0, rec->pool);

    // Can't use file..
    if (!(wl_st == APR_SUCCESS))
	return;

    while (apr_file_gets(data, datalen, wl_file) == APR_SUCCESS) {
        if (!strcasecmp(data, ""))
            continue;

        wl_strip_ip(data, " ");
        wl_strip_ip(data, "\n");

        bot = wl_xmalloc(sizeof(char) * 256);

        strcpy(bot, data);
        wl_append_bot(wl_cfg, bot);
    }

    wl_st = apr_file_close(wl_file);
    wl_bots_loaded = 1;
}

/**
 * checks whether an incoming request
 * needs to be blocked
 * 
 * @param rec -> Apache 2 request
 */
static int wl_init(request_rec* rec)
{
    char* addr;
    char* initial;
    char* agent;
    wl_config* wl_cfg = (wl_config*) ap_get_module_config(rec->per_dir_config, &wl_module);
        
    if (wl_cfg->spenv == 1) {
	    apr_table_set(rec->subprocess_env, "MODWL_BOTS", wl_cfg->bot);
    }

    if (wl_cfg->enabled != 1) {
        return (OK);
    }

    if (strcasecmp(wl_cfg->btlist, "") && wl_bots_loaded != 1) {
        wl_load_bots(wl_cfg->btlist, rec, wl_cfg);
    }

#if AP_SERVER_MAJORVERSION_NUMBER >= 2 && AP_SERVER_MINORVERSION_NUMBER >= 4
    addr = initial = rec->connection->client_ip;
#else
    addr = initial = rec->connection->remote_ip;
#endif

    if (wl_cfg->spenv == 1) {
	apr_table_set(rec->subprocess_env, "MODWL_ORIGINAL", addr);
    }

#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Original remote ip is: %s", addr);

    while (wl_cfg->cbot != NULL) {
        AP_LOG_INFO(rec, "Initialized bot: %s", wl_cfg->cbot->name);
	
        wl_cfg->cbot = wl_cfg->cbot->next;
    }
    wl_reset_bots();
#endif

    agent = wl_xmalloc(sizeof(char) * 256);
    strcpy(agent, (char*) apr_table_get(rec->headers_in, "User-Agent"));

#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec,  "User agent is: %s", agent);
#endif
    
#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Agent: %s did not match any needed user agents", agent);
#endif
     addr = wl_reverse_dns(addr);
     if (addr == NULL) {
#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Couldn't call gethostbyaddr on %s", initial);
#endif
        return wl_close(DECLINED);
    }


#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Reverse dns is: %s", addr);
#endif

     if (wl_cfg->spenv == 1) {
  	apr_table_set(rec->subprocess_env, "MODWL_REVERSE_DNS", addr);
     }

     addr = wl_forward_dns(addr);

     if (wl_cfg->spenv == 1) {
	apr_table_set(rec->subprocess_env, "MODWL_FORWARD_DNS", addr);
     }

#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Final conversion of remote ip is: %s", addr);
#endif 

    if (strcasecmp(initial, addr) != 0) {
        if (wl_cfg->btauto == 1) {
            wl_append_bot(wl_cfg, agent);
        }

        wl_append_bl(initial);
        wl_append_list(wl_cfg->blist, initial, rec);
	apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_FAIL);
        return wl_close(DECLINED);
    }
    // add to white list

    wl_append_wl(initial);
    wl_append_list(wl_cfg->list, initial, rec);
    apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_OK);

    return wl_close(OK);
}

/**
 * cleanup any whitelist or
 * blacklist
 * 
 * @param status -> DECLINED or OK
 */
static int wl_close(int status)
{
    return (status);
}

/**
 * per server configuration.
 *
 * @param pool -> apache's memory pool or HTTPd in this case
 * @param server_rec -> Apache 2 server rec
 */
inline static void* wl_server_config(apr_pool_t* pool, server_rec* s)
{
    wl_config* cfg = apr_pcalloc(pool, sizeof(wl_config));

    if (cfg) {
        cfg->enabled = 0;
        cfg->lenabled = 0;
        cfg->debug = 0;
        cfg->list = "";
        cfg->blist = "";
        cfg->btlist = "";
        cfg->bot = "";
        cfg->btany = 0;
        cfg->btauto = 0;
        cfg->bhandler = "";
        cfg->ahandler = "";
        cfg->cbot = NULL;
    }
    wl_cfg = cfg;

    return cfg;
}

/**
 * per directory confiuguration.
 *
 * @param pool -> apache's memory pool or HTTPd in this case
 * @param context -> wl config's context
 */
inline static void* wl_dir_config(apr_pool_t* pool, char* context)
{
    context = context ? context : "";
    wl_config* cfg = apr_pcalloc(pool, sizeof(wl_config));

    if (cfg) {
        strcpy(cfg->context, context);
        cfg->enabled = 0;
        cfg->lenabled = 0;
        cfg->debug = 0;
        cfg->list = "";
        cfg->blist = "";
        cfg->btlist = "";
        cfg->btauto = 0;
        cfg->bot = "";
        cfg->btany = 0;
        cfg->bhandler = "";
        cfg->ahandler = "";
        cfg->cbot = NULL;
    }
    wl_cfg = cfg;

    return cfg; 
}

/**
 * directives enabled mod_wl
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_enabled(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->enabled = 1;
    else
            wl_cfg->enabled = 0;

    return NULL;
}

/**
 * directive enables white lists
 * 
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_enabled_list(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->lenabled = 1;
    else
            wl_cfg->lenabled = 0;

    return NULL;
}

/**
 * sets the bot(s) wl will be using
 * acceptable values are any user agent substring
 * this option can be given in a "|" delimited
 * string. ex:
 * Googlebot/2.1 | bingbot/2.1 | Yahoo Slurp!
 * or
 * Googlebot
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_bot(cmd_parms* cmd, void* cfg, const char* args)
{
    char* bots;
    wl_config* wl_cfg = (wl_config*) cfg;
    bots = ap_getword_conf(cmd->pool, &args);

    wl_strip_ip(bots, " "); 
    wl_cfg->bot = bots;

    char delims[] = "|";
    char* piece = NULL;

    piece = strtok(bots, delims);

    while (piece != NULL) {
        if (!strcasecmp(piece, "any")) {
            wl_cfg->btany = 1;
        }

        wl_cfg->cbot = (bitem*) wl_xmalloc(sizeof(bitem));
        wl_cfg->cbot->name = piece;
        wl_cfg->cbot->next = wl_cfg->chead;
        wl_cfg->chead = wl_cfg->cbot;
        piece = strtok(NULL, delims);
    }

    return NULL;
}


/** 
 * set the timeout for forward and reverse DNS
 * lookups
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_dns_timeout(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->dnstimeout = 1;
    else
            wl_cfg->dnstimeout = 0;

    return NULL;
}

/** 
 * set whether to set subprocess env based on
 * reverse, forward DNS lookups and the status
 * of the module
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_subprocess_env(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->spenv = 1;
    else
            wl_cfg->spenv = 0;

    return NULL;
}



/**
 * set if mod_wl should add new bots automatically
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_bot_auto_add(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->btauto = 1;
    else
            wl_cfg->btauto = 0;

    return NULL;
}


/**
 * set a file to read bots from
 * 
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_bot_list(cmd_parms* cmd, void* cfg, const char* args)
{
    wl_config* wl_cfg = (wl_config*) cfg;
    wl_cfg->btlist = (char*) args;

    return NULL;
}

/**
 * set a file to read existing whitelist entries from
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_list(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;
    wl_cfg->list = (char*) arg;

    return NULL;
}

/**
 * same as wl_set_list/2 for blacklists
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_blist(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;
    wl_cfg->blist = (char*) arg;

    return NULL;
}


/**
 * registers the hook in the Apache
 *
 * @param pool -> Apache's request pool
 */
static void wl_hooks(apr_pool_t* pool)
{
    ap_hook_post_read_request(wl_init, NULL, NULL, APR_HOOK_MIDDLE); // middle was present in initial version. 
}


/**
 * open the whitelist file and append a
 * ip address.
 *
 * @param fl -> file path
 * @param addr -> IPv4 address
 * @param rec -> Apache 2 request
 */
inline static void wl_append_list(char* fl, char* addr, request_rec* rec)
{
    apr_file_t* wl_file;
    apr_status_t wl_file_st;
    char* new_line;

    if (strcasecmp(fl, "") != 0) {
	    wl_file_st = apr_file_open(&wl_file, 
				       fl,
              APR_FOPEN_WRITE | APR_FOPEN_CREATE | APR_FOPEN_APPEND,
              APR_FPROT_UREAD | APR_FPROT_UWRITE | APR_FPROT_GREAD,
				      rec->pool);
	       

            if (!(wl_file_st == APR_SUCCESS)) {
              AP_LOG_INFO(rec, "Couldn't open list file %s", fl);
		return;
            }

	    wl_file_st = apr_file_lock(wl_file, 
				       APR_FLOCK_EXCLUSIVE | 
				       APR_FLOCK_NONBLOCK);


	    if (wl_file_st == APR_SUCCESS) {
        new_line = wl_concat(addr, "\n");
		    apr_file_puts(new_line, wl_file);
		    apr_file_close(wl_file);

#if WL_MODULE_DEBUG_MODE
      AP_LOG_INFO(rec, "Whitelist added: %s", addr);
#endif
		    return;
	    } 

            return;
#if WL_MODULE_DEBUG_MODE
      AP_LOG_INFO(rec, "Whitelist couldn't lock: %s, (status err): %d", addr, wl_file_st);
#endif
    }
#if WL_MODULE_DEBUG_MODE
    AP_LOG_INFO(rec, "Whitelist disabled not adding: %s to storage list", addr);
#endif
}

/** 
 * Apache configuration directives
 * either set the configuration for
 * access level configurations or
 * RCRF based configurations not both
 */
static const command_rec wl_directives[] = 
{
    AP_INIT_TAKE1("wlEnabled", wl_set_enabled, NULL, RSRC_CONF, "ENABLE OR DISABLE WL"),
    AP_INIT_TAKE1("wlList", wl_set_list, NULL, RSRC_CONF, "SET WL's WHITELIST"),
    AP_INIT_TAKE1("wlBlackList", wl_set_blist, NULL, RSRC_CONF, "SET WL'S BLACKLIST"),
    AP_INIT_TAKE1("wlBotList", wl_set_bot_list, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBotAutoAdd", wl_set_bot_auto_add, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlDnsTimeout", wl_set_dns_timeout, NULL, ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlSubprocessEnv", wl_set_subprocess_env, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_RAW_ARGS("wlBot", wl_set_bot, NULL, RSRC_CONF, "DEBUG MODE"),
    { NULL }
};

/* module definitions
 */
module AP_MODULE_DECLARE_DATA   wl_module =
{ 
    STANDARD20_MODULE_STUFF,
    wl_dir_config,          /* Per-directory configuration handler */
    NULL,                   /* Merge handler for per-directory configurations */
    wl_server_config,                   /* Per-server configuration handler */
    NULL,                   /* Merge handler for per-server configurations */
    wl_directives,          /* Any directives we may have for httpd */
    wl_hooks                /* Our hook registering function */
};
