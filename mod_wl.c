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

/* windows setup */
#ifdef WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>

/* linux setup */
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

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


#define WL_MODULE_CORE_PRIVATE 1
#define WL_MODULE_DEBUG_MODE 1 
#define WL_MODULE_ACCESS_CONFIG 1 
#define WL_MODULE_DEBUG_UNITTEST_AGENT_1				"Googlebot/2.1 (+http)"
#define WL_MODULE_DEBUG_UNITTEST_AGENT_2					  "bingbot/2.1"
#define WL_MODULE_DEBUG_UNITTEST_AGENT_3		 		         "Yahoo! Slurp"
#define WL_MODULE_DEBUG_UNITTEST_AGENT_4					       "Yandex"
#define WL_MODULE_GOOGLEBOT_CAPTION					        "googlebot.com"
#define WL_MODULE_YAHOOBOT_CAPTION					        "ac2.yahoo.com" 
#define WL_MODULE_BINGBOT_CAPTION					       "search.msn.com" 
#define WL_MODULE_YANDEXBOT_CAPTION						   "yandex.com"
#define WL_MODULE_STATUS_OKMSG						 	      "Success"
#define WL_MODULE_STATUS_FAILMSG							 "Fail"

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
    int			  interop;
    bitem*                   cbot;
    bitem*                  chead;
} wl_config;

module AP_MODULE_DECLARE_DATA   
wl_module;

unsigned char                 wl_bytes[4];
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
static int                    wl_in_wl(char* addr);
static int                    wl_in_bl(char* addr);
static void                   wl_load_wl(char* fl, request_rec* rec);
static void                   wl_load_bl(char* fl, request_rec* rec);
static void                   wl_load_bots(char* fl, request_rec* rec, wl_config* wl_cfg);
static void                   wl_blocked_handler(request_rec* rec, char* handler);
static void                   wl_accepted_handler(request_rec* rec, char* handler);
static void                   wl_strip_ip(char *addr, char* strip);
static char*                  wl_replace_ip(char* addr, char* rep, char* with);
const char*                   apr_table_get(const apr_table_t* t, const char* key);
static item*                  wl_element;
static item*                  bl_element;
inline static int             wl_assert(char* addr, char* constraint);
inline static void            wl_strip_append_bot(char* bot, wl_config* wl_cfg);
inline static int             wl_in_agents(char* agent, wl_config* wl_cfg);
inline static void            wl_append_bot(wl_config* wl_cfg, char* bot);
inline static void            wl_show_variables(wl_config* wl_cfg, request_rec* rec);
inline static void*           wl_server_config(apr_pool_t* pool, char* context);
inline static void*           wl_dir_config(apr_pool_t* pool, char* context);
inline static void            wl_append_block(char* addr, request_rec* rec);
inline static void            wl_append_accept(char* addr, request_rec* rec);
inline static void            wl_append_list(char* fl, char* addr, request_rec* rec);
const char*                   wl_set_enabled(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_list_enabled(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_block_handler(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_accept_handler(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_debug(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_bot(cmd_parms* cmd, void* cfg, const char* args);
const char*                   wl_set_list(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_blist(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_bot_auto_add(cmd_parms* cmd, void* cfg, const char* arg);
const char*                   wl_set_dns_timeout(cmd_parms* cmd, void* cfg, const char* arg);
const char*		      wl_concat(char* ip1, char* ip2);
static char*                  wl_pluck_agent(char* agent);
static const char*            wl_valid_domains[] = { WL_MODULE_GOOGLEBOT_CAPTION, WL_MODULE_YAHOOBOT_CAPTION, WL_MODULE_BINGBOT_CAPTION };
static int                    wl_wl_loaded = 0;
static int                    wl_bl_loaded = 0;
static int                    wl_bots_loaded = 0;
static item*                  wl_head = NULL;
static item*                  bl_head = NULL;


/* wl_fail is called whenever
 * an error happens throughout this module
 * @param what -> error message
 */
static void wl_fail(const char* what)
{
    fprintf(stderr, "wl_module: system call failed: %s: %s\n", what, what);
}

/* Domain specific malloc
 * report any error that arose from
 * wl's memory allocation
 * @param sz -> target allocation
 */
static void* wl_xmalloc(size_t sz)
{
    void* res = malloc(sz);
    if (res) return res;

    wl_fail((char*) "malloc");

    return (char*)"";
}

/* Reverse DNS a given address
 * @param addr -> ip address
 */
static char* wl_reverse_dns(char* addr)
{
    struct hostent* he;
    struct in_addr ipv4addr;
    
    inet_pton(AF_INET, addr, &ipv4addr);
    he = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
    
    return he->h_name;
}

/* Forward DNS a given address
 * @param addr -> ip address
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


/* Verify whether the address
 * is in one of the wl_domains
 * if the constraint is any of the 
 * bots, return success on a match.
 * Otherwise find the required bot
 * @param: addr -> ip address
 * @param: constraint -> bot delimiter
 */
inline static int wl_assert(char* addr, char* constraint)
{
    regex_t rgx;
    int rgx_state;
    size_t i;
    size_t matches;

    for (i = 0; i <= sizeof(wl_valid_domains) / 8; i ++) {
            rgx_state = regcomp(&rgx, wl_valid_domains[i], REG_EXTENDED);

            if (rgx_state)
                wl_fail("ERR: WL couldn't compile agaisnt expression");

            rgx_state = regexec(&rgx, addr, 0, NULL, 0);

            if (!rgx_state)
                matches ++;
    }

    if (matches > 1 && !strcasecmp(constraint, "any"))
        return 1;

    if (matches > 0)
        return 1;
      
    return 0; 
}


/* Verify if the user agent 
 * is one of the required ones 
 * This is used to verify whether
 * a user may be spoofing his agent or not.
 * Additionally this should be
 * called before any dns based functions.
 * @param: agent -> HTTP Agent Tag
 * @param: wl_cfg -> wl config's bots
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

/* Find a particular element
 * in the whitelist
 *
 * @param -> ip address
 */
static int wl_in_wl(char* addr)
{
    size_t found = 0;
    while (wl_element) {
        if (!strcasecmp(wl_element->addr, addr))
            found = 1;

        wl_element = wl_element->next;
    }

    wl_element = wl_head;
    return found;
}

/* Same as wl_in_wl/1
 * for blacklists
 * @param: addr -> ip address
 */
static int wl_in_bl(char* addr)
{
    size_t found = 0;
    while (bl_element) {
        if (!strcasecmp(bl_element->addr, addr))
            found = 1;

        bl_element = bl_element->next;
    }

    bl_element = bl_head;
    return found;
}

/* Append to the black list
 * and call the handler immediately after. 
 *
 * @param addr -> ip address
 * @param rec -> apache's request structure
 */
inline static void wl_append_block(char* addr, request_rec* rec)
{
    wl_append_bl(addr);
    wl_blocked_handler(rec, "");
}


/* Append to the whitelist
 * and call the accepted
 * handler
 * @param addr -> ip address
 * @param rec -> apache request structure
 */
inline static void wl_append_accept(char* addr, request_rec* rec)
{
    wl_append_wl(addr);
    wl_accepted_handler(rec, "");
}


/* Append to the whitelist
 * in memory
 * @param addr -> ip address
 */
static void wl_append_wl(char* addr)
{
    wl_element = (item*) wl_xmalloc(sizeof(item));
    wl_element->addr = addr;
    wl_element->next = wl_head;
    wl_head = wl_element;
}

/* Same as wl_append_wl/1
 * for blacklists
 * @param addr -> ip address
 */
static void wl_append_bl(char* addr)
{
    bl_element = (item*) wl_xmalloc(sizeof(item));
    bl_element->addr = addr;
    bl_element->next = bl_head;
    bl_head = bl_element;
}

/* Append a new bot to
 * WL's configuration.
 *
 * @param wl_cfg -> wl's configuration
 * @bot -> user agent substring (for bot). i.e: Yandex/2.1
 */
inline static void wl_append_bot(wl_config* wl_cfg, char* bot)
{
    wl_cfg->cbot = (bitem*) wl_xmalloc(sizeof(bitem));
    wl_cfg->cbot->name = bot;
    wl_cfg->cbot->next = wl_cfg->chead;
    wl_cfg->chead = wl_cfg->cbot;
}

/* Get rid of any extra
 * characters this ip addr
 * may have.
 * @param addr -> ip address
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

/* Concatenate two ip strings
 * this is used to set variables
 * in the setenv_variable collection
 * @param ip1 -> ip address
 * @param ip2 -> ip address
 */
const char* wl_concat(char* ip1, char* ip2)
{
    char *result = malloc(strlen(ip1)+strlen(ip2)+1); //+1 for the zero-terminator
    strcpy(result, ip1);
    strcat(result, ip2);

    return result;
}

/* Depending on the target list
 * we may need to strip any extranatous
 * characters from the ip string.
 * afterwards add it to the whitelist
 * @param addr -> ip address
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

/* Same as wl_strip_append_wl/1
 * for blacklists
 * @param addr -> ip address
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

/* Strip any whitespace from a bot's
 * substring, afterwards add it to 
 * the bot list.
 *
 * @param bot -> bot substring
 * @param wl_cfg -> wl's config
 */
inline static void wl_strip_append_bot(char* bot, wl_config* wl_cfg)
{
    wl_strip_ip(bot, " ");
    wl_strip_ip(bot, "\n");

    if (strcmp(bot, "") != -1)    
        wl_append_bot(wl_cfg, bot);
}

/* Replace a given ip to its raw 
 * reciprocal
 * @param addr -> ip address
 * @param rep -> port to transform
 * @param with -> transformation 
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


/* Load the specified 
 * whitelist file into
 * memory
 * @param fl -> whitelist file (loaded in config)
 * @param rec -> apache request structure
 */
static void wl_load_wl(char* fl, request_rec* rec)
{
    apr_file_t* wl_file;
    apr_status_t wl_st;
    apr_size_t datalen = 256;
    char data[256]; 

    wl_st = apr_file_open(&wl_file, fl, APR_FOPEN_CREATE | APR_FOPEN_READ, APR_OS_DEFAULT, rec->pool);

    while (apr_file_gets(data, datalen, wl_file) == APR_SUCCESS) 
        wl_strip_append_wl(data);

    wl_st = apr_file_close(wl_file);
    wl_wl_loaded = 1;
}

/* Load the specified
 * blacklist into 
 * memory
 *
 * @param fl -> whitelist file (loaded in config)
 * @param rec -> apache request structure
 */
static void wl_load_bl(char* fl, request_rec* rec)
{
    apr_file_t* wl_file;
    apr_status_t wl_st;
    apr_size_t datalen = 256;
    char data[256]; 

    wl_st = apr_file_open(&wl_file, fl, APR_FOPEN_CREATE | APR_FOPEN_READ, APR_OS_DEFAULT, rec->pool);

    while (apr_file_gets(data, datalen, wl_file) == APR_SUCCESS)
        wl_strip_append_bl(data);

    wl_st = apr_file_close(wl_file);
    wl_bl_loaded = 1;
}

/* Load a list of bots into memory
 * this should add to any existing bots
 * set in the configuration file
 *
 * @param fl -> whitelist file (loaded in config)
 * @param rec -> apache request structure
 */
static void wl_load_bots(char* fl, request_rec* rec, wl_config* wl_cfg)
{
    apr_file_t* wl_file;
    apr_status_t wl_st;
    apr_size_t datalen = 256;
    char data[256]; 
    char* bot;

    wl_st = apr_file_open(&wl_file, fl, APR_FOPEN_CREATE | APR_FOPEN_READ, APR_OS_DEFAULT, rec->pool);

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


/* Provided a full user agent string
 * pluck it down to its most important
 * substring. NOTE: This is not always
 * guarenteed to work and is experimental
 *
 * @param agent -> full user agent string.
 */
static char* wl_pluck_agent(char* agent)
{
    return agent;
}

/* Handle a request that has been
 * blocked. Usually this means we 
 * Don't allow the user agent
 * to view the content.
 * 
 * @param rec -> apache request structure
 * @param handler -> an anchor to go to
 */
static void wl_blocked_handler(request_rec* rec, char* handler)
{
    if (strcasecmp(handler, "")) {
            const char* user_agent = apr_table_get(rec->headers_in, "User-Agent");
            ap_rputs(DOCTYPE_HTML_3_2, rec);
            ap_rputs("<HTML>\n", rec);
            ap_rprintf(rec, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">", handler);
            ap_rprintf(rec, "%s", user_agent);
            ap_rputs("</HTML>\n", rec);
    }

#if WL_MODULE_DEBUG_MODE
   ap_rprintf(rec, "Request landed in blacklist");
#endif
}

/* Whenever a request
 * gets accepted
 * @param rec -> apache request structure
 */
static void wl_accepted_handler(request_rec* rec, char* handler)
{
    if (strcasecmp(handler, "")) {
            const char* user_agent = apr_table_get(rec->headers_in, "User-Agent");
            ap_rputs(DOCTYPE_HTML_3_2, rec);
            ap_rputs("<HTML>\n", rec);
            ap_rprintf(rec, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">", handler);
            ap_rprintf(rec, "%s", user_agent);
            ap_rputs("</HTML>\n", rec);
    }
#if WL_MODULE_DEBUG_MODE
    ap_rprintf(rec, "Request landed in whitelist");
#endif
}

/* Print out the variables found
 * in the wl configuration. This is
 * called whenever wl_debug is enabled
 * @param wl_cfg -> wl's config structure
 * @param rec -> apache request structure
 */
static void wl_show_variables(wl_config* wl_cfg, request_rec* rec)
{
    ap_set_content_type(rec, "text/plain");
    ap_rprintf(rec, "WLEnabled: %d\n", wl_cfg->enabled);
    ap_rprintf(rec, "WLDebug: %d\n", wl_cfg->debug);
    ap_rprintf(rec, "WLListEnabled: %d\n", wl_cfg->lenabled);
    ap_rprintf(rec, "WLBot: %s\n", wl_cfg->bot);
    ap_rprintf(rec, "WLList: %s\n", wl_cfg->list);
    ap_rprintf(rec, "WLBlacklist: %s\n", wl_cfg->blist);
    ap_rprintf(rec, "WLBotlist: %s\n", wl_cfg->btlist);
    ap_rprintf(rec, "WLBotAutoAdd: %d\n", wl_cfg->btauto);
    ap_rprintf(rec, "WLDNSTimeout: %d\n", wl_cfg->dnstimeout);
    ap_rprintf(rec, "WLInterop: %d\n", wl_cfg->interop);
    ap_rprintf(rec, "WLBlockedHandler: %s\n", wl_cfg->bhandler);
    ap_rprintf(rec, "WLAcceptedHandler: %s\n", wl_cfg->ahandler);
}

/* Start a wl instance. This
 * will basically assert where the request
 * lands in the config.
 * @param rec -> apache request structure
 */
static int wl_init(request_rec* rec)
{
    /* First we need to reverse dns the
     * addr.
     */
    char* addr;
    char* initial;
    char* agent;
    size_t bt_cnt;

    /* first check the confguration
     */

    wl_config* wl_cfg = (wl_config*) 
    ap_get_module_config(rec->per_dir_config, &wl_module);
     

    if (wl_cfg->interop == 1)
	apr_table_set(rec->subprocess_env, "MODWL_BOTS", wl_cfg->bot);


#if WL_MODULE_DEBUG_MODE
    if (wl_cfg->debug == 1)
        wl_show_variables(wl_cfg, rec);
#endif

     /* Check if the configuration
     * is enabled. If it isn't 
     * let the request by
     */ 

    if (wl_cfg->enabled != 1)
        return (OK);

    /* Load the whitelist
     * into memory
     */

    if (strcasecmp(wl_cfg->list, ""))
        if (wl_wl_loaded != 1)
            wl_load_wl(wl_cfg->list, rec);

    /* Load the black list into
     * memory.
     */
    if (strcasecmp(wl_cfg->blist, ""))
        if (wl_bl_loaded != 1)
            wl_load_bl(wl_cfg->blist, rec);
            

    /* Load the external bot list
     * into memory
     */
    if (strcasecmp(wl_cfg->btlist, ""))
        if (wl_bots_loaded != 1)
            wl_load_bots(wl_cfg->btlist, rec, wl_cfg);

#if AP_SERVER_MAJORVERSION_NUMBER >= 2 && AP_SERVER_MINORVERSION_NUMBER >= 4
    addr = initial = rec->connection->client_ip;
#else
    addr = initial = rec->connection->remote_ip;
#endif


    if (wl_cfg->interop == 1)
	apr_table_set(rec->subprocess_env, "MODWL_ORIGINAL", addr);

#if WL_MODULE_DEBUG_MODE
    if (wl_cfg->debug == 1)
        ap_rprintf(rec, "Original remote ip is: %s\n", addr);


    bt_cnt = 0;

    while (wl_cfg->cbot != NULL) {
        ap_rprintf(rec, "Initialized bot: %s\n", wl_cfg->cbot->name);
	
        wl_cfg->cbot = wl_cfg->cbot->next;
	bt_cnt ++;
    }

    wl_cfg->cbot = wl_cfg->chead;
#endif

    /* remote ip is in the whitelist
     * we don't need to do anything else
     */
    if (wl_in_wl(initial)) {
        wl_accepted_handler(rec, wl_cfg->ahandler);

	apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_OKMSG);
        return wl_close(OK);
    }

    /* Decline this request
     * if the ip is in the 
     * blacklist
     */
    if (wl_in_bl(initial)) {
        wl_blocked_handler(rec, wl_cfg->bhandler);

	apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_FAILMSG);
        return wl_close(DECLINED);
    }

    agent = wl_xmalloc(sizeof(char) * 256);
    strcpy(agent, (char*) apr_table_get(rec->headers_in, "User-Agent"));

    /* first check if the user
     * agent is in one of our required
     * user agents
     * when it isn't let the request
     * through
     */
#if WL_MODULE_DEBUG_MODE
    if (wl_cfg->debug == 1)
        ap_rprintf(rec,  "User agent is: %s\n", agent);
#endif
    
    if (wl_in_agents(agent, wl_cfg) != 1) {
#if WL_MODULE_DEBUG_MODE
        if (wl_cfg->debug == 1)
           ap_rprintf(rec, "Agent: %s did not match any needed user agents", agent);
#endif
	addr = wl_reverse_dns(addr);

    	if (wl_cfg->interop == 1)
		apr_table_set(rec->subprocess_env, "MODWL_REVERSE_DNS", addr);

	addr = wl_forward_dns(addr);

	if (wl_cfg->interop == 1)
		apr_table_set(rec->subprocess_env, "MODWL_FORWARD_DNS", addr);

	if (wl_cfg->interop == 1)
		apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_OKMSG);

    }

    addr = wl_reverse_dns(addr);

    if (wl_cfg->interop == 1)
	apr_table_set(rec->subprocess_env, "MODWL_REVERSE_DNS", addr);

#if WL_MODULE_DEBUG_MODE
    if (wl_cfg->debug == 1)
        ap_rprintf(rec, "Reverse dns is: %s\n", addr);
#endif

    /* if all goes well -- addr is from a good server
     * we should then need to forward this
     * dns
     */
    addr = wl_forward_dns(addr);

    if (wl_cfg->interop == 1)
	apr_table_set(rec->subprocess_env, "MODWL_FORWARD_DNS", addr);

#if WL_MODULE_DEBUG_MODE
    if (wl_cfg->debug == 1)
        ap_rprintf(rec, "Converted remote ip is: %s\n", addr);
#endif 

    /* finally we need to check
     * if addr is the initial
     * addr.
     * Strip any whitespace from both
     * initial and address before
     * trying to use strcmp
     */
    //wl_strip_ip(addr, " ");
  
    if (!strcasecmp(initial, addr)) {
        // add to white list

        wl_append_wl(initial);
        wl_append_list(wl_cfg->list, initial, rec);
        wl_accepted_handler(rec, wl_cfg->ahandler);
	apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_OKMSG);

        return wl_close(OK);
    } else {
        if (wl_cfg->btauto == 1)
            wl_append_bot(wl_cfg, wl_pluck_agent(agent));

        wl_append_bl(initial);
        wl_append_list(wl_cfg->blist, initial, rec);
        wl_blocked_handler(rec, wl_cfg->bhandler);
	apr_table_set(rec->subprocess_env, "MODWL_STATUS", WL_MODULE_STATUS_FAILMSG);
    }
   
    return wl_close(DECLINED);
}

/* cleanup any whitelist or
 * blacklist
 * @param status -> DECLINED | OK
 */
static int wl_close(int status)
{
    return (status);
}

/* Per server configuration.
 * Pending changes
 * For the configuration, 
 * we want to check if the
 * module has been enabled. Additionally 
 * verify which user agents
 * need to use the whitelist
 * module.
 *
 * @param pool -> apache's memory pool or HTTPd in this case
 * @param context -> wl config's context
 */
inline static void* wl_server_config(apr_pool_t* pool, char* context)
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
        cfg->bot = "";
        cfg->btany = 0;
        cfg->btauto = 0;
        cfg->bhandler = "";
        cfg->ahandler = "";
        cfg->cbot = NULL;
    }

    return cfg;
}

/* Per directory confiuguration.
 * same as wl_server_config/2 
 * Only this is directory based
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

    return cfg;
}


/* Directives for when
 * wl module is enabled
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

/* Enable whitelist
 * list functionality
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

/* Convention to turn the 
 * debug mode on or off
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_debug(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
        wl_cfg->debug = 1;
    else
        wl_cfg->debug = 0;

    return NULL;
}

/* set the bot wl will be using
 * acceptable values are any user agent substring
 * this option can be given in singular or plural
 * form. ex:
 * Googlebot/2.1 | bingbot/2.1 | Yahoo Slurp!
 * or
 * Googlebot
 *
 * also "any" can be used to match agaisnt any
 * useraagent
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
        if (!strcasecmp(piece, "any"))
            wl_cfg->btany = 1;

        wl_cfg->cbot = (bitem*) wl_xmalloc(sizeof(bitem));
        wl_cfg->cbot->name = piece;
        wl_cfg->cbot->next = wl_cfg->chead;
        wl_cfg->chead = wl_cfg->cbot;
        piece = strtok(NULL, delims);
    }

    return NULL;
}


/* Set whether we want to auto add new bots
 * to the bot list.
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

/* Set whether to allow interop or not
 * this will upstream all requests to 
 * higher level resources. Definitions for 
 * the interop can be found @ http://
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_interop(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;

    if (!strcasecmp(arg, "on"))
            wl_cfg->interop = 1;
    else
            wl_cfg->interop = 0;

    return NULL;
}



/* Set a bot wl module can automatically
 * use.
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


/* Read the desired bots from a file
 * file should be seperated by newlines
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

/* This sets an area where WLModule can find
 * the whitelist. Path should be absolute.
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

/* Set the Blacklist location
 * same as wl_set_list/1 (for blacklists)
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

/* Set the URL wl_module will go to
 * having received a bad request
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_blocked_handler(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;
    wl_cfg->bhandler = (char*) arg;

    return NULL;
}

/* Same as wl_set_blocked_handler/2 for
 * accepted requests.
 *
 * @param cmd -> configuration inherit from httpd.conf
 * @param cfg -> configuration structure
 * @param arg -> config set value
 */
const char* wl_set_accepted_handler(cmd_parms* cmd, void* cfg, const char* arg)
{
    wl_config* wl_cfg = (wl_config*) cfg;
    wl_cfg->ahandler = (char*) arg;

    return NULL;
}

/* Register the hook in the Apache
 * this basically tells Apache HTTPd to call
 * our handler whenever a request is made.
 *
 * @param pool -> Apache's request pool
 */
static void wl_hooks(apr_pool_t* pool)
{
    ap_hook_post_read_request(wl_init, NULL, NULL, APR_HOOK_MIDDLE); // middle was present in initial version. 
}


/* Open the whitelist file
 * and append to it given the received
 * ip address.
 *
 * @param fl -> file path and name
 * @param addr -> ip address
 * @param rec -> apache's request structure
 */
inline static void wl_append_list(char* fl, char* addr, request_rec* rec)
{
    apr_file_t* wl_file;
    apr_status_t wl_file_st;

    if (strcasecmp(fl, "")) {
	    wl_file_st = apr_file_open(&wl_file, 
				       fl,
				       APR_BUFFERED | // set buffered 
				       APR_BINARY |   // ignored in unix env 
				       APR_CREATE |   // allow file creation 
				       APR_WRITE |    // move to end of file on open
				       APR_APPEND,    // only append to this file 
				       APR_OS_DEFAULT,
				       rec->pool);
	       
	    wl_file_st = apr_file_lock(wl_file, 
				       APR_FLOCK_EXCLUSIVE | 
				       APR_FLOCK_NONBLOCK);

	    if (wl_file_st == APR_SUCCESS) {
		    apr_file_puts(addr, wl_file);
		    apr_file_close(wl_file);
#if WL_MODULE_DEBUG_MODE
	    ap_rprintf(rec, "Whitelist added: %s\n", addr);
#endif
		    return;
	    } else {
#if WL_MODULE_DEBUG_MODE
	    ap_rprintf(rec, "Whitelist couldn't add: %s, (status err): %d\n", addr, wl_file_st);
#endif
	    }
    } else {
#if WL_MODULE_DEBUG_MODE
	    ap_rprintf(rec, "Whitelist couldn't add: %s", addr);
#endif
    }
}

/* Apache configuration directives
 * either set the configuration for
 * access level configurations or
 * RCRF based configurations not both
 */
#ifdef WL_MODULE_ACCESS_CONFIG
static const command_rec wl_directives[] = 
{
    AP_INIT_TAKE1("wlEnabled", wl_set_enabled, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "ENABLE OR DISABLE WL"),
    AP_INIT_TAKE1("wlListEnabled", wl_set_list, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "SET WL's WHITELIST"),
    AP_INIT_TAKE1("wlList", wl_set_list, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "SET WL's WHITELIST"),
    AP_INIT_TAKE1("wlBlackList", wl_set_blist, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "SET WL'S BLACKLIST"),
    AP_INIT_TAKE1("wlDebug", wl_set_debug, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBlockedHandler", wl_set_blocked_handler, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlAcceptedHandler", wl_set_accepted_handler, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBotList", wl_set_bot_list, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBotAutoAdd", wl_set_bot_auto_add, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlDnsTimeout", wl_set_dns_timeout, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlInterop", wl_set_interop, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_RAW_ARGS("wlBot", wl_set_bot, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    { NULL }
};
#else
static const command_rec wl_directives[] = 
{
    AP_INIT_TAKE1("wlEnabled", wl_set_enabled, NULL, RSRC_CONF, "ENABLE OR DISABLE WL"),
    AP_INIT_TAKE1("wlListEnabled", wl_set_list, NULL, ACCESS_CONF, "SET WL's WHITELIST"),
    AP_INIT_TAKE1("wlList", wl_set_list, NULL, RSRC_CONF, "SET WL's WHITELIST"),
    AP_INIT_TAKE1("wlBlackList", wl_set_blist, NULL, RSRC_CONF, "SET WL'S BLACKLIST"),
    AP_INIT_TAKE1("wlDebug", wl_set_debug, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBlockedHandler", wl_set_blocked_handler, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlAcceptedHandler", wl_set_accepted_handler, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBotList", wl_set_bot_list, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlBotAutoAdd", wl_set_bot_auto_add, NULL, RSRC_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlDnsTimeout", wl_set_dns_timeout, NULL, ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_TAKE1("wlInterop", wl_set_interop, NULL, RSRC_CONF|OR_ALL|ACCESS_CONF, "DEBUG MODE"),
    AP_INIT_RAW_ARGS("wlBot", wl_set_bot, NULL, RSRC_CONF, "DEBUG MODE"),
    { NULL }
};
#endif

/* module definitions
 */
module AP_MODULE_DECLARE_DATA   wl_module =
{ 
    STANDARD20_MODULE_STUFF,
    wl_dir_config,          /* Per-directory configuration handler */
    NULL,                   /* Merge handler for per-directory configurations */
    NULL,                   /* Per-server configuration handler */
    NULL,                   /* Merge handler for per-server configurations */
    wl_directives,          /* Any directives we may have for httpd */
    wl_hooks                /* Our hook registering function */
};
