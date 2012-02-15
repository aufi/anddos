/*
 * HTTP anti-ddos nginx module
 *
 * Marek Aufart, aufi.cz@gmail.com, twitter @auficz
 * 
 * license: GNU GPL v3
 * 
 * resources: http://wiki.nginx.org/3rdPartyModules, http://www.evanmiller.org/nginx-modules-guide.html, http://blog.zhuzhaoyuan.com/2009/08/creating-a-hello-world-nginx-module/
 * 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static u_char ngx_anddos_fail_string[] = "<html><head><meta http-equiv='refresh' content='5'><title>Blocked by anddos</title></head><body><p>You have been blocked by anddos!</p></body></html>";

//function declarations
static ngx_int_t ngx_http_anddos_request_handler(ngx_http_request_t *r);
static char * ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_anddos_learn_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_anddos_filter_init(ngx_conf_t *cf);

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

//data store
//struct ngx_http_anddos_client;
//struct ngx_http_anddos_state;

//anddos internal functions
//static char * ngx_http_anddos_get_state();
//static char * ngx_http_anddos_get_client();

//datatypes
static ngx_command_t ngx_http_anddos_commands[] = {
    { ngx_string("anddos"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_anddos,
      0,
      0,
      NULL },
 
    ngx_null_command
};

static ngx_http_module_t  ngx_http_anddos_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_anddos_filter_init,                  /* postconfiguration */
    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */
    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_http_anddos_module = {
    NGX_MODULE_V1,
    &ngx_http_anddos_module_ctx,           /* module context */
    ngx_http_anddos_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

typedef struct {
    int score;
    ngx_str_t ip;
    ngx_str_t browser;
    ngx_uint_t request_count;
    ngx_uint_t notmod_count;
    float avg_time;
    ngx_uint_t avg_time_count;
} ngx_http_anddos_client_t;

typedef struct {
    int request_count;
    int notmod_count;
    float avg_time;
} ngx_http_anddos_state_t;


//data init
//static ngx_hash_t clients;
ngx_http_anddos_state_t ngx_http_anddos_state;


//function definitions
static ngx_int_t 
ngx_http_anddos_request_handler(ngx_http_request_t *r) {
    
    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "anddos processing request");
    
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
 
    //decide whether is request bot or not
    if (ngx_http_anddos_state.request_count % 3) return NGX_DECLINED;
    
    rc = ngx_http_discard_request_body(r);
 
    if (rc != NGX_OK) {
        return rc;
    }
 
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS: request blocked");
    
    //FIX necesarry ?
    /* set the 'Content-type' header */
    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
 
    /* send the header only, if the request type is http 'HEAD' */
    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = sizeof(ngx_anddos_fail_string) - 1;
        return ngx_http_send_header(r);
    }
 
    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
 
    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;
 
    /* adjust the pointers of the buffer */
    b->pos = ngx_anddos_fail_string;
    b->last = ngx_anddos_fail_string + sizeof(ngx_anddos_fail_string) - 1;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */
 
    /* set the status line */
    r->headers_out.status = NGX_HTTP_PRECONDITION_FAILED;       //for dev, FIX to NGX_HTTP_SERVICE_UNAVAILABLE in production 
    r->headers_out.content_length_n = sizeof(ngx_anddos_fail_string) - 1;
 
    /* send the headers of your response */
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
 
    //FIX improve fail responses
    ngx_http_complex_value_t  cv;
    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));
    cv.value.len = sizeof(ngx_anddos_fail_string) - 1;
    cv.value.data = ngx_anddos_fail_string;
    
    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, &out);
    //return ngx_http_send_response(r, r->headers_out.status, (ngx_str_t *) r->headers_out.content_type.data, &cv);
    
}

static ngx_int_t
ngx_http_anddos_learn_filter(ngx_http_request_t *r)
{   
    //struct ngx_http_anddos_client_t client;
    //client.browser = "sdfsdf";
    //r->headers_out.

    //server stats update
    ngx_http_anddos_state.request_count += 1;
    if (r->headers_out.status == 302) ngx_http_anddos_state.notmod_count += 1;
    
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS: learn");
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "request_count: %i; notmod_count: %i", ngx_http_anddos_state.request_count, ngx_http_anddos_state.notmod_count);

    return ngx_http_next_header_filter(r);
}

//initializers
static char *
ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{    
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_anddos_request_handler;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_anddos_filter_init(ngx_conf_t *cf)
{
    //FIX handles all requests (incl.blocked)!
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_anddos_learn_filter;
    
    ngx_http_anddos_state.notmod_count = 0;
    ngx_http_anddos_state.request_count = 0;
    
    return NGX_OK;
}
