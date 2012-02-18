/*
 * HTTP anti-ddos nginx module
 *
 * Marek Aufart, aufi.cz@gmail.com, http://twitter.com/auficz
 * 
 * license: GNU GPL v3
 * 
 * resources: http://wiki.nginx.org/3rdPartyModules, http://www.evanmiller.org/nginx-modules-guide.html, http://blog.zhuzhaoyuan.com/2009/08/creating-a-hello-world-nginx-module/
 * 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define COOKIENAME "anddos_key"
#define COOKIEKEYLEN 5

static u_char ngx_anddos_fail_string[] = "<html><head><meta http-equiv='refresh' content='10'><title>Blocked by anddos</title></head><body><p>You have been blocked by anddos!</p></body></html>";

//function declarations
static ngx_int_t ngx_http_anddos_request_handler(ngx_http_request_t *r);
static char * ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_anddos_learn_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_anddos_filter_init(ngx_conf_t *cf);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

ngx_int_t set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value);
static u_char * ngx_http_anddos_rnd_text();

//data store
//struct ngx_http_anddos_client;
//struct ngx_http_anddos_state;

//anddos internal functions
//static char * ngx_http_anddos_get_state();
//static char * ngx_http_anddos_get_client();

//datatypes
static ngx_command_t ngx_http_anddos_commands[] = {
    { ngx_string("anddos"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_anddos,
        0,
        0,
        NULL},

    ngx_null_command
};

static ngx_http_module_t ngx_http_anddos_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_anddos_filter_init, /* postconfiguration */
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

ngx_module_t ngx_http_anddos_module = {
    NGX_MODULE_V1,
    &ngx_http_anddos_module_ctx, /* module context */
    ngx_http_anddos_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

typedef struct {
    int score;
    //ngx_str_t ip;
    //ngx_str_t browser;
    int request_count;
    int notmod_count;
    //float avg_time;
    //ngx_uint_t avg_time_count;
} ngx_http_anddos_client_t;

typedef struct {
    int request_count;
    int notmod_count;
    //float avg_time;
} ngx_http_anddos_state_t;


//data init
ngx_hash_t * ngx_http_anddos_clients;
ngx_http_anddos_state_t ngx_http_anddos_state;


//function definitions

u_char *
ngx_http_anddos_rnd_text() {
    //srand(time(NULL));        //FIX commented in dev enviroment
    static u_char t[COOKIEKEYLEN+1];
    u_char * dict = (u_char *) "qwertzuXioadNfgh4jklyxcvbnCm12367890YVBMLKJpHGFDSAQW5EsRTZUIOP";
    int i;
    for (i = 0; i<COOKIEKEYLEN; i++) {
        t[i] = dict[rand()%strlen((char*)dict)];
    }
    //t[COOKIEKEYLEN] = '\0';
    return t;
}

//http://wiki.nginx.org/HeadersManagement
ngx_int_t
set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value) {
    ngx_table_elt_t   *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->key = *key;
    h->value = *value;
    h->hash = 1;
 
    return NGX_OK;
}

static ngx_int_t
ngx_http_anddos_request_handler(ngx_http_request_t *r) {

    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "anddos processing request");

    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    //decide whether is request bot or not
    if (ngx_http_anddos_state.request_count % 3) return NGX_DECLINED; //development ;-)

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS: request blocked");

    //FIX necessary ?
    /* set the 'Content-type' header */
    r->headers_out.content_type_len = sizeof ("text/html") - 1;
    r->headers_out.content_type.len = sizeof ("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    /* send the header only, if the request type is http 'HEAD' */
    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = sizeof (ngx_anddos_fail_string) - 1;
        return ngx_http_send_header(r);
    }

    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof (ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;

    /* adjust the pointers of the buffer */
    b->pos = ngx_anddos_fail_string;
    b->last = ngx_anddos_fail_string + sizeof (ngx_anddos_fail_string) - 1;
    b->memory = 1; /* this buffer is in memory */
    b->last_buf = 1; /* this is the last buffer in the buffer chain */

    /* set the status line */
    r->headers_out.status = NGX_HTTP_PRECONDITION_FAILED; //for dev, FIX to NGX_HTTP_SERVICE_UNAVAILABLE in production 
    r->headers_out.content_length_n = sizeof (ngx_anddos_fail_string) - 1;

    /* send the headers of your response */
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    //FIX improve fail responses
    ngx_http_complex_value_t cv;
    ngx_memzero(&cv, sizeof (ngx_http_complex_value_t));
    cv.value.len = sizeof (ngx_anddos_fail_string) - 1;
    cv.value.data = ngx_anddos_fail_string;

    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, &out);
    //return ngx_http_send_response(r, r->headers_out.status, (ngx_str_t *) r->headers_out.content_type.data, &cv);

}

static ngx_int_t
ngx_http_anddos_learn_filter(ngx_http_request_t *r) {
    //client stats update
    //struct ngx_http_anddos_client_t client;
    //client.browser = "sdfsdf";
    //r->headers_out.

    //cookie alg: set random text cookie and require it in next reqs (first n (8) reqs pass anyway), the goal is to stop non-waiting requests (eg. loic)

    //server stats update
    ngx_http_anddos_state.request_count += 1;
    if ((int) r->headers_out.status == 304) ngx_http_anddos_state.notmod_count += 1;

    //generate cookie key
    u_char * client_key = ngx_http_anddos_rnd_text();
    //FIX overflow?
    //char cookie_value_str[COOKIEKEYLEN+12+2];
    u_char cookie_value_str[18];
    
    ngx_sprintf(cookie_value_str, "%s=%s", COOKIENAME, client_key);
    ngx_str_t cookie_name = ngx_string("Set-Cookie");
    ngx_str_t cookie_value = ngx_string(cookie_value_str);
    
    //set a cookie
    ngx_int_t hr = set_custom_header_in_headers_out(r, &cookie_name, &cookie_value);
    if (hr != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS state: request_count: %i; notmod_count: %i, key: %s, Set-cookie: %s", ngx_http_anddos_state.request_count, ngx_http_anddos_state.notmod_count, client_key, cookie_value_str);
    
    return ngx_http_next_header_filter(r);
}

//initializers
static char *
ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_anddos_request_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_anddos_filter_init(ngx_conf_t *cf) {
    //FIX handles all requests (incl.blocked)!
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_anddos_learn_filter;

    //basic server stats
    ngx_http_anddos_state.notmod_count = 0;
    ngx_http_anddos_state.request_count = 0;
    /*
    //clients hashtable
    //http://xiqiao1229.iteye.com/blog/805332
    ngx_pool_t * pool;
    pool = ngx_create_pool(1024*100, NULL);
    ngx_http_anddos_clients = (ngx_hash_t*) ngx_pcalloc(pool, sizeof(ngx_http_anddos_clients));
    ngx_hash_init_t hash_init;
    hash_init.hash = ngx_http_anddos_clients;
    hash_init.key = &ngx_hash_key_lc;
    hash_init.max_size  = 1024*100;     //100K elts
    hash_init.bucket_size = 64; //(2) Number of entries in one bucket or bucket size in bytes ?
    hash_init.name = "ngx_http_anddos_clients";
    hash_init.pool = pool;
    hash_init.temp_pool = NULL;
    
    if (ngx_hash_init(&hash_init, NULL, 0)!=NGX_OK){
        return NGX_ERROR;
    }
    
    
    ngx_array_t * elements;
    ngx_hash_key_t * arr_node;
    
    elements = ngx_array_create(pool, 64, sizeof(ngx_hash_key_t));
    
    arr_node = (ngx_hash_key_t*) ngx_array_push(elements);
    ngx_str_t * sdf = ngx_string("asd");
    arr_node->key = sdf;
    arr_node->key_hash = ngx_hash_key_lc(arr_node->key.data, arr_node->key.len);
    arr_node->value = (void*) "aufart";
    
    
    
    ngx_hash_add_key(ngx_http_anddos_clients, sdf, "asdasd", );
    
    
    char * find;
    ngx_uint_t k;
    k    = ngx_hash_key_lc((u_char*) "marek", 6);
    printf("%s key is %d\n", "marek", 6);
    find = (char*) ngx_hash_find(ngx_http_anddos_clients, k, (u_char*) "marek", 6);

    if (find) {
        printf("get: %s\n", (char*) find);
    } else {
        printf("not found: %s\n", "marek");
    }
    
    //ngx_array_destroy(elements);
    //ngx_destroy_pool(pool);
    */
    return NGX_OK;
}
