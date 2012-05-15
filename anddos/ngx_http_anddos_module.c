/*
 * HTTP anti-ddos nginx module
 *
 * Marek Aufart, aufi.cz@gmail.com
 * 
 * Visit project page: https://github.com/aufi/anddos
 * 
 * license: GNU GPL v3
 * 
 * resources: http://wiki.nginx.org/3rdPartyModules, http://www.evanmiller.org/nginx-modules-guide.html, http://blog.zhuzhaoyuan.com/2009/08/creating-a-hello-world-nginx-module/
 * 
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
//#include "modules/ngx_http_proxy_module.c"

#define COOKIENAME "anddos_key"
#define HASHKEYLEN 150
#define HASHTABLESIZE 10240      //100k in production
#define STATE_FILE "/tmp/anddos_state"
#define SEQSIZE 32
#define INITTHRESHOLD 9999

static u_char ngx_anddos_fail_string[] = "<html><head><meta http-equiv='refresh' content='5'><title>Blocked!</title></head><body><p>You have been blocked by ANDDOS!</p></body></html>";

//function declarations
static ngx_int_t ngx_http_anddos_request_handler(ngx_http_request_t *r);
static char * ngx_http_anddos(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_anddos_learn_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_anddos_filter_init(ngx_conf_t *cf);

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

ngx_int_t set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value);
unsigned int ngx_http_anddos_get_client_index(ngx_http_request_t *r);

void ngx_http_anddos_get_client_text(u_char * text_key, ngx_http_request_t *r);
//static char * ngx_http_anddos_rnd_text();
//static int ngx_http_anddos_hash_get_adr(char * t); //or  ngx_hash_key(u_char *data, size_t len)

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

typedef struct { //FIX keep IP somewhere for blocking all clients from the IP
    unsigned char set; //->bool

    unsigned int request_count; //ensure that int overflow will not occur errors
    unsigned int notmod_count;
    unsigned int http1_count;
    unsigned int http2_count;
    unsigned int http3_count;
    unsigned int http4_count;
    unsigned int http5_count;
    unsigned int avg_time; //rounding is OK
    unsigned int html_avg_time;
    unsigned int key;

    //mimetypes count
    unsigned int html_count;
    unsigned int css_count; //or just text?
    unsigned int javascript_count;
    unsigned int image_count;
    unsigned int other_count; //FIX necesarry?
    
    //scores
    unsigned int httpcode_score;
    unsigned int mimetype_score;
    unsigned int time_score;
    unsigned int passeq_score;

    u_char pass_seq[SEQSIZE];
    u_char ua[HASHKEYLEN];

} ngx_http_anddos_client_t;

typedef struct {
    unsigned char level; //(0)Normal, (10)Attack, (100)Overload; not used yet

    unsigned int threshold;
    
    unsigned int request_count;
    unsigned int notmod_count;
    unsigned int http1_count;
    unsigned int http2_count;
    unsigned int http3_count;
    unsigned int http4_count;
    unsigned int http5_count;
    unsigned int client_count;
    unsigned int avg_time;
    unsigned int html_avg_time;

    //mimetypes count
    unsigned int html_count;
    unsigned int css_count;
    unsigned int javascript_count;
    unsigned int image_count;
    unsigned int other_count;

} ngx_http_anddos_state_t;


//data init
ngx_http_anddos_client_t ngx_http_anddos_clients[HASHTABLESIZE];
ngx_http_anddos_state_t ngx_http_anddos_state;


//http://wiki.nginx.org/HeadersManagement

ngx_int_t
set_custom_header_in_headers_out(ngx_http_request_t *r, ngx_str_t *key, ngx_str_t *value) {
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->key = *key;
    h->value = *value;
    h->hash = 1;

    return NGX_OK;
}
/*
static ngx_int_t
ngx_http_anddos_request_handler_create(ngx_http_request_t *r) {
    
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "anddos processing request CREATE");
    
    return NGX_OK;
}*/

static ngx_int_t
ngx_http_anddos_request_handler(ngx_http_request_t *r) {

    //disabled while using proxy_pass directive, due to nginx architecture        
    //this handler can block requests only for static content on local server
    //FIX spread blocking to all requests

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS processing request");

    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    //DECIDE whether is request bot or not
    //KISS, one condition, rest logic is moved to the learn_filter

    u_char text_key[HASHKEYLEN];
    memset(text_key, 0, HASHKEYLEN);
    ngx_http_anddos_get_client_text(text_key, r);
    unsigned int key = ngx_hash_key(text_key, ngx_strlen(text_key)) % HASHTABLESIZE;
    
    if (1 || (int) ngx_http_anddos_clients[key].set < 2) {      // 1 || -> only monitor
        
        return NGX_DECLINED;    // 0,1 OK;  2,3,.. BLOCK
    
    }
        
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS: request blocked");
    //FIX necessary ?
    /* set the 'Content-type' header */
    r->headers_out.content_type_len = sizeof ("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    //FIX remove or keep?
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

    //FIX ensure which return is faster
    //return ngx_http_output_filter(r, &out);
    return ngx_http_send_response(r, r->headers_out.status, (ngx_str_t *) r->headers_out.content_type.data, &cv);

}

void
ngx_http_anddos_get_client_text(u_char * text_key, ngx_http_request_t *r) {

    //FIX IP or UA header can be longer than HASHKEYLEN
    //only IP is used, np

    if (0) { //(r->headers_in.user_agent) {
        //user_agent HEADER
        u_char header_ua[HASHKEYLEN];
        memset(header_ua, 0, HASHKEYLEN);
        u_char header_ip[HASHKEYLEN];
        memset(header_ip, 0, HASHKEYLEN);
        ngx_snprintf(header_ip, (int) r->connection->addr_text.len, "%s", r->connection->addr_text.data);
        ngx_snprintf(header_ua, (int) r->headers_in.user_agent->value.len, "%s", r->headers_in.user_agent->value.data);
        ngx_snprintf(text_key, HASHKEYLEN, "%s%s", header_ip, header_ua);

    } else {
        //host IP
        ngx_snprintf(text_key, (int) r->connection->addr_text.len, "%s", r->connection->addr_text.data);
    }

    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS HASH TEXT KEY: %s, LEN: %d", text_key, ngx_strlen(text_key));

}

void
ngx_http_anddos_clients_stats(ngx_http_request_t *r) {

    //log
    int i;
    for (i = 0; i < HASHTABLESIZE; i++) {
        if (ngx_http_anddos_clients[i].set > 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS client[%d]: request_count: %d; http200_count: %d, key: %d, avg_time: %d, pass_seq: %s", i, ngx_http_anddos_clients[i].request_count, ngx_http_anddos_clients[i].http2_count, ngx_http_anddos_clients[i].key, ngx_http_anddos_clients[i].avg_time, (char *) ngx_http_anddos_clients[i].pass_seq);
        }
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS state[%d]: request_count: %d; http200_count: %d, client_count: %d, avg_time: %d", ngx_http_anddos_state.level, ngx_http_anddos_state.request_count, ngx_http_anddos_state.http2_count, ngx_http_anddos_state.client_count, ngx_http_anddos_state.avg_time);
    //ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS mimetypes: html: %d; css: %d, js: %d, images: %d, other: %d", ngx_http_anddos_state.html_count, ngx_http_anddos_state.css_count, ngx_http_anddos_state.javascript_count, ngx_http_anddos_state.image_count, ngx_http_anddos_state.other_count);

    //DEV logging anddos state to file (after 1/100reqs)
    if ((ngx_http_anddos_state.request_count % 10) != 2) return;

    //else stats to file
    FILE *f;
    if (!(f = freopen(STATE_FILE, "w", stdout))) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS error: save to file failed");
    } else {
        printf("ANDDOS state\nlevel threshold clients reqs 304cnt http1cnt http2cnt http3cnt http4cnt http5cnt avgtime htmlavgtime html css javascript image other\n");
        printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", 
                ngx_http_anddos_state.level, ngx_http_anddos_state.threshold, ngx_http_anddos_state.client_count, ngx_http_anddos_state.request_count, ngx_http_anddos_state.notmod_count, 
                ngx_http_anddos_state.http1_count, ngx_http_anddos_state.http2_count, ngx_http_anddos_state.http3_count, ngx_http_anddos_state.http4_count, ngx_http_anddos_state.http5_count, 
                ngx_http_anddos_state.avg_time, ngx_http_anddos_state.html_avg_time, ngx_http_anddos_state.html_count, ngx_http_anddos_state.css_count, ngx_http_anddos_state.javascript_count, ngx_http_anddos_state.image_count, ngx_http_anddos_state.other_count);

        printf("ANDDOS clients\nset index httpscore mimescore timescore seqscore reqs 304_cnt http1cnt http2cnt http3cnt http4cnt http5cnt avgtime htmlavgtime html css javascript images other pass_seq    ip_ua\n");
        for (i = 0; i < HASHTABLESIZE; i++) {
            if ((int) ngx_http_anddos_clients[i].set > 0) {
                printf("%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", 
                        (int) ngx_http_anddos_clients[i].set, i, ngx_http_anddos_clients[i].httpcode_score, ngx_http_anddos_clients[i].mimetype_score, ngx_http_anddos_clients[i].time_score, ngx_http_anddos_clients[i].passeq_score, 
                        ngx_http_anddos_clients[i].request_count, ngx_http_anddos_clients[i].notmod_count, ngx_http_anddos_clients[i].http1_count, ngx_http_anddos_clients[i].http2_count, ngx_http_anddos_clients[i].http3_count, ngx_http_anddos_clients[i].http4_count, ngx_http_anddos_clients[i].http5_count, 
                        ngx_http_anddos_clients[i].avg_time, ngx_http_anddos_clients[i].html_avg_time, ngx_http_anddos_clients[i].html_count, ngx_http_anddos_clients[i].css_count, ngx_http_anddos_clients[i].javascript_count, ngx_http_anddos_clients[i].javascript_count, ngx_http_anddos_clients[i].other_count, 
                        (char *) ngx_http_anddos_clients[i].pass_seq, (char *) ngx_http_anddos_clients[i].ua);
            }
        }
        fclose(f);
    }
}

void
ngx_http_anddos_set_cookie(ngx_http_request_t *r, int key) {

    u_char cookie_value_str[50];
    memset(cookie_value_str, 0, 50);

    //assemble cookie text
    ngx_snprintf(cookie_value_str, 50, "%s=%d", COOKIENAME, key);
    ngx_str_t cookie_name = ngx_string("Set-Cookie");
    ngx_str_t cookie_value = ngx_string(cookie_value_str);

    //set a cookie
    ngx_int_t hr = set_custom_header_in_headers_out(r, &cookie_name, &cookie_value);
    if (hr != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS client error: failed to set a cookie");
    }
}

int
ngx_http_anddos_get_msec(ngx_http_request_t *r) {
    //inspired by logmodule msec function
    int ms;
    ngx_time_t *tp;

    tp = ngx_timeofday();

    ms = ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = ngx_max(ms, 0);

    return ms;
}

inline void
ngx_http_anddos_set_mimetype_stats(ngx_http_request_t *r, int key, int request_time) {

    if ((int) r->headers_out.status >= 300 || (int) r->headers_out.status < 200) { //exclude no success (<>200) responses
        return;
    }

    int cnt = 0;
    u_char mime_type[32];
    memset(mime_type, 0, 32);
    ngx_snprintf(mime_type, r->headers_out.content_type.len, "%s", r->headers_out.content_type.data);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS mime: %s", mime_type);

    
    
    if (ngx_strstr(mime_type, "html") != NULL) {
        ngx_http_anddos_clients[key].html_count += 1;
        ngx_http_anddos_state.html_count += 1;
        
        ngx_http_anddos_state.html_avg_time = (ngx_http_anddos_state.html_avg_time * (ngx_http_anddos_state.html_count - 1) + request_time ) / ngx_http_anddos_state.html_count;
        ngx_http_anddos_clients[key].html_avg_time = (ngx_http_anddos_clients[key].html_avg_time * (ngx_http_anddos_clients[key].html_count - 1) + request_time ) / ngx_http_anddos_clients[key].html_count;
        
        
    } else {
        //not count all request_count, but only non 304 and non html
        //ngx_http_anddos_state.avg_time = ngx_http_anddos_state.avg_time * (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count - 1) / (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count) + request_time / (ngx_http_anddos_state.request_count - ngx_http_anddos_state.notmod_count);
        //ngx_http_anddos_clients[key].avg_time = ngx_http_anddos_clients[key].avg_time * (ngx_http_anddos_clients[key].request_count - 1) / ngx_http_anddos_clients[key].request_count + request_time / ngx_http_anddos_clients[key].request_count;
        //is better to risk overflow or rounding ? :)
        cnt = ngx_http_anddos_state.http2_count - ngx_http_anddos_state.html_count;
        if (cnt == 0) {
            ngx_http_anddos_state.avg_time = 0;
        } else {    
            ngx_http_anddos_state.avg_time = (ngx_http_anddos_state.avg_time * (cnt - 1) + request_time) / cnt;
        }
        cnt = ngx_http_anddos_clients[key].http2_count - ngx_http_anddos_clients[key].html_count;
        if (cnt == 0) {
            ngx_http_anddos_clients[key].avg_time = 0;
        } else {
            ngx_http_anddos_clients[key].avg_time = (ngx_http_anddos_clients[key].avg_time * (cnt - 1) + request_time ) / cnt;
        }
        
        //what about browser's cache, maybe understand to http headers ?
        
        if (ngx_strstr(mime_type, "image") != NULL) {
            ngx_http_anddos_clients[key].image_count += 1;
            ngx_http_anddos_state.image_count += 1;
        } else
            if (ngx_strstr(mime_type, "javascript") != NULL) {
            ngx_http_anddos_clients[key].javascript_count += 1;
            ngx_http_anddos_state.javascript_count += 1;
        } else
            if (ngx_strstr(mime_type, "css") != NULL) {
            ngx_http_anddos_clients[key].css_count += 1;
            ngx_http_anddos_state.css_count += 1;
        } else {
            ngx_http_anddos_clients[key].other_count += 1;
            ngx_http_anddos_state.other_count += 1;
        }
    }
}

inline void
ngx_http_anddos_set_httpcode_stats(ngx_http_request_t *r, int key) {
    
    //FIX 3xx or keep 304 as a special code, which proofs that client has a local cache? 2012-03-28 keep!
    
    int code = (int) r->headers_out.status;
    
    if (code == 304) {
        ngx_http_anddos_clients[key].notmod_count += 1;
        ngx_http_anddos_state.notmod_count += 1;
    }
    
    if (code < 200) { 
        ngx_http_anddos_clients[key].http1_count += 1;
        ngx_http_anddos_state.http1_count += 1;
    } else
        if (code < 300) {       //we keep all 3xx (incl.304)
        ngx_http_anddos_clients[key].http2_count += 1;
        ngx_http_anddos_state.http2_count += 1;
    } else
        if (code < 400) { 
        ngx_http_anddos_clients[key].http3_count += 1;
        ngx_http_anddos_state.http3_count += 1;
    } else
        if (code < 500) { 
        ngx_http_anddos_clients[key].http4_count += 1;
        ngx_http_anddos_state.http4_count += 1;
    } else { 
        ngx_http_anddos_clients[key].http5_count += 1;
        ngx_http_anddos_state.http5_count += 1;
    }

}

inline float
ngx_http_anddos_count_fdiff(float global, float client) {
    //what about attack by many very fast and not "heavy" reqs ..no reason to do that, but better block both extrems
    
    if (global == 0) return 0;
    
    if (client > global)
        return (client - global) / global;       //or non-linear math function => exp ?
    else
        return (global - client) / global;
}

inline unsigned int
ngx_http_anddos_count_diff(unsigned int global, unsigned int client) {
     
    //if (global == 0) return 0;
    //return abs(client - global) / global;       //or non-linear math function - log/exp ?
    
    return (int) 100 * ngx_http_anddos_count_fdiff((float) global, (float) client);
}

void
ngx_http_anddos_undo_stats(int key) {
   //FIX before production deployment
}

int
ngx_http_anddos_decide(ngx_http_request_t *r, int key) {
    //make a decision
    //if client's param differs to global param by more than threshold, block
    //threshold depends on reqs count, global state, statistic function
    //scores are kept from time, when last request was served (->first client)
    
    int dec;
    dec = 1;
    
    unsigned int score = ngx_http_anddos_clients[key].httpcode_score + ngx_http_anddos_clients[key].mimetype_score + ngx_http_anddos_clients[key].time_score;
    
    if (score > ngx_http_anddos_state.threshold && ngx_http_anddos_clients[key].request_count > 5) dec = 2;

    //when block some client compensate global stats by opposite values of his params
    if (ngx_http_anddos_clients[key].set == 1 && dec == 2) {
        ngx_http_anddos_undo_stats(key);
    }
    
    return dec;
}


inline unsigned int
ngx_http_anddos_count_score_time(unsigned int c_avg, unsigned int c_html) {
        return (int) ((ngx_http_anddos_count_diff(ngx_http_anddos_state.avg_time, c_avg) + ngx_http_anddos_count_diff(ngx_http_anddos_state.html_avg_time, c_html)) / 2 );
}

inline unsigned int
ngx_http_anddos_count_score_mimetype(unsigned int cnt, unsigned int html, unsigned int css, unsigned int javascript, unsigned int image, unsigned int other) {

    float w1 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.html_count / ngx_http_anddos_state.request_count, (float)html / cnt);
    float w2 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.css_count / ngx_http_anddos_state.request_count, (float)css / cnt);
    float w3 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.javascript_count / ngx_http_anddos_state.request_count, (float)javascript / cnt);
    float w4 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.image_count / ngx_http_anddos_state.request_count, (float)image / cnt);
    float w5 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.other_count / ngx_http_anddos_state.request_count, (float)other / cnt);
    
    //or weighted sum ?
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS score[%d]: %d %d %d %d %d", w1, w2, w3, w4, w5);
    
    return (int) (100 * (w1 + w2 + w3 + w4 + w5));      //lost precision?
}

inline unsigned int
ngx_http_anddos_count_score_httpcode(unsigned int cnt, unsigned int c1, unsigned int c2, unsigned int c3, unsigned int c4, unsigned int c5) {

    float w1 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.http1_count / ngx_http_anddos_state.request_count, (float)c1 / cnt);
    float w2 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.http2_count / ngx_http_anddos_state.request_count, (float)c2 / cnt);
    float w3 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.http3_count / ngx_http_anddos_state.request_count, (float)c3 / cnt);
    float w4 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.http4_count / ngx_http_anddos_state.request_count, (float)c4 / cnt);
    float w5 = ngx_http_anddos_count_fdiff((float)ngx_http_anddos_state.http5_count / ngx_http_anddos_state.request_count, (float)c5 / cnt);
    
    //or weighted sum ?
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ANDDOS score[%d]: %d %d %d %d %d", w1, w2, w3, w4, w5);
    
    return (int) (100 * (w1 + w2 + w3 + w4 + w5));      //lost precision?
}    

void
ngx_http_anddos_count_scores(ngx_http_request_t *r, int key) {
    
    //httpcode
    ngx_http_anddos_clients[key].httpcode_score = ngx_http_anddos_count_score_httpcode(
            ngx_http_anddos_clients[key].request_count, ngx_http_anddos_clients[key].http1_count, ngx_http_anddos_clients[key].http2_count, 
            ngx_http_anddos_clients[key].http3_count, ngx_http_anddos_clients[key].http4_count, ngx_http_anddos_clients[key].http5_count
        );
    
    //mimetype
    ngx_http_anddos_clients[key].mimetype_score = ngx_http_anddos_count_score_mimetype(
            ngx_http_anddos_clients[key].request_count, ngx_http_anddos_clients[key].html_count, ngx_http_anddos_clients[key].css_count, 
            ngx_http_anddos_clients[key].javascript_count, ngx_http_anddos_clients[key].image_count, ngx_http_anddos_clients[key].other_count
        );
    
    //time
    ngx_http_anddos_clients[key].time_score = ngx_http_anddos_count_score_time( ngx_http_anddos_clients[key].avg_time, ngx_http_anddos_clients[key].html_avg_time );
    
    //passeq
    //count of unique paths, what globally??
}

inline int
ngx_http_anddos_count_threshold() {
    
    if (ngx_http_anddos_state.request_count < 37 || ngx_http_anddos_state.client_count < 5) return INITTHRESHOLD;
    
    int i, min, max, clients;
    float avg;
    min = INITTHRESHOLD;
    max = 0;
    avg = 0;
    clients = 0;
    
    for (i = 0; i < HASHTABLESIZE; i++) {
        
        if ((int) ngx_http_anddos_clients[i].set == 1 && (int) ngx_http_anddos_clients[i].request_count > 1) {
            clients += 1;
            int score = ngx_http_anddos_clients[i].httpcode_score + ngx_http_anddos_clients[i].mimetype_score + ngx_http_anddos_clients[i].time_score;
            if (score < min) min = score;
            if (score > max) max = score;
            avg = (avg * (clients - 1) + score) / clients;
        }
    }
    //FIX maybe naive?
    //FIX2 also global state (normal/attack) can be concerned
    return 150 + avg;     // 2x is too much, 100+ seems to be ok, update: 150 + avg seems to be the best (measures) 
    
}

static ngx_int_t
ngx_http_anddos_learn_filter(ngx_http_request_t *r) {

    //the client data
    u_char text_key[HASHKEYLEN];
    memset(text_key, 0, HASHKEYLEN);
    ngx_http_anddos_get_client_text(text_key, r);
    unsigned int key = ngx_hash_key(text_key, ngx_strlen(text_key)) % HASHTABLESIZE;
    int request_time = ngx_http_anddos_get_msec(r);

    //server stats update
    ngx_http_anddos_state.request_count += 1;
    
        //r->headers_in.cookies.elts //FIX find clients cookie
        //FIX compare cookie content
        //first req let pass (in normal conditions)

    
    if ((int) ngx_http_anddos_clients[key].set == 0) {
        //generate cookie key ---------disabled---------
        //int client_key = rand(); //FIX predictable
        //send a cookie key
        //ngx_http_anddos_set_cookie(r, client_key);

        //setup in client hashtable
        ngx_http_anddos_clients[key].set = 1;
        ngx_http_anddos_clients[key].request_count = 1;
        //ngx_http_anddos_clients[key].key = client_key;
        ngx_http_anddos_get_client_text(ngx_http_anddos_clients[key].ua, r);
        ngx_http_anddos_clients[key].pass_seq[0] = (u_char) (ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33); //printable chars from ascii //circ.register will differ same sequentions (longer than SEQSTEPS)

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS client[%d]: step id: %c for uri: %s", 
                key, 
                (char) ngx_http_anddos_clients[key].pass_seq[0],
                (char*) r->uri.data);

        ngx_http_anddos_set_httpcode_stats(r, key);
        
        ngx_http_anddos_set_mimetype_stats(r, key, request_time);

        ngx_http_anddos_state.client_count += 1;

    } else {

        //dont count to stats already blocked clients
        //FIX (should not be here in production, but useful for development and testing purposes)
        if (ngx_http_anddos_clients[key].set > 1) return ngx_http_next_header_filter(r); //DEV FIX
        
        
        //web-pass sequence
        //ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count % (SEQSIZE - 1)] = (u_char) (ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33);    //circ.register will differ same sequentions (longer than SEQSTEPS)
        if (ngx_http_anddos_clients[key].request_count < (SEQSIZE - 1)) { //register for first n requested url hashes
            ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count] = (u_char) (ngx_hash_key(r->uri.data, r->uri.len) % 94 + 33);
        }

        ngx_http_anddos_clients[key].request_count += 1;

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "ANDDOS client[%d]: step id: %c for uri: %s", 
                key, 
                (char) ngx_http_anddos_clients[key].pass_seq[ngx_http_anddos_clients[key].request_count % SEQSIZE], 
                (char*) r->uri.data);

        ngx_http_anddos_set_httpcode_stats(r, key);
        
        ngx_http_anddos_set_mimetype_stats(r, key, request_time);
        
        ngx_http_anddos_count_scores(r, key);
        
        //DECIDE to BLOCK
        //and export blocked IP somewhere?
        ngx_http_anddos_clients[key].set = ngx_http_anddos_decide(r, key);

    }
    
    //if ((ngx_http_anddos_state.request_count % 100) != 37) 
    ngx_http_anddos_state.threshold = ngx_http_anddos_count_threshold();  //always in dev/test env
    
    ngx_http_anddos_clients_stats(r);

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

    //dont reinit table in case of worker process fail
    if ((int) ngx_http_anddos_state.client_count > 0) {
        return NGX_OK;
    }
    
    //basic server stats
    ngx_http_anddos_state.level = 0;
    ngx_http_anddos_state.threshold = INITTHRESHOLD;
    ngx_http_anddos_state.client_count = 0;
    /*
    ngx_http_anddos_state.notmod_count = 0;
    ngx_http_anddos_state.request_count = 0;
    ngx_http_anddos_state.avg_time = 0;
    ngx_http_anddos_state.html_avg_time = 0;
    ngx_http_anddos_state.html_count = 0;
    ngx_http_anddos_state.css_count = 0;
    ngx_http_anddos_state.javascript_count = 0;
    ngx_http_anddos_state.image_count = 0;
    ngx_http_anddos_state.other_count = 0;*/

    //clean clients list
    int i;
    for (i = 0; i < HASHTABLESIZE; i++) {
        ngx_http_anddos_clients[i].set = 0;
        /*
        ngx_http_anddos_clients[i].request_count = 0;
        ngx_http_anddos_clients[i].notmod_count = 0;
        ngx_http_anddos_clients[i].avg_time = 0;
        ngx_http_anddos_clients[i].html_avg_time = 0;
        ngx_http_anddos_clients[i].key = 0;*/
        memset(ngx_http_anddos_clients[i].ua, 0, HASHKEYLEN);
        memset(ngx_http_anddos_clients[i].pass_seq, 0, SEQSIZE);
        /*ngx_http_anddos_clients[i].html_count = 0;
        ngx_http_anddos_clients[i].css_count = 0;
        ngx_http_anddos_clients[i].javascript_count = 0;
        ngx_http_anddos_clients[i].image_count = 0;
        ngx_http_anddos_clients[i].other_count = 0;*/
    }

    //dev print hashtable size
    printf("ANDDOS hashtable size: %ld B\n", (long int) sizeof (ngx_http_anddos_clients));

    return NGX_OK;
}
