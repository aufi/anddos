/* 
 * File:   test_ngx_http_anddos.c
 * Author: aufi
 *
 * Created on 20. únor 2012, 18:34
 * /

#include <stdio.h>
#include <stdlib.h>
#define HASHKEYLEN 50

#define ngx_hash(key, c)   


unsigned int
ngx_hash_key(char *data, size_t len)
 {
     unsigned int  i, key;
 
     key = 0;
 
     for (i = 0; i < len; i++) {
         key = ((unsigned int) key * 31 + data[i]);
     }
 
     return key;
 }

typedef struct {
    int set; //bool
    int score;
    //ngx_str_t browser;
    int request_count;
    int notmod_count;
    //float avg_time;
    //ngx_uint_t avg_time_count;
    char key[6];
} ngx_http_anddos_client_t;

typedef struct {
    int request_count;
    int notmod_count;
    //float avg_time;
} ngx_http_anddos_state_t;

    


//data init
ngx_http_anddos_client_t *ngx_http_anddos_clients;
ngx_http_anddos_state_t ngx_http_anddos_state;

/*
 * 
 */
int main(int argc, char** argv) {

    
    //client stats update
    char text_key[HASHKEYLEN];
    //host IP
    strncpy(text_key, "asdasd", strlen("asdasd"));
    //user_agent header
    if (0) {
        int ua_max_len;
        if (HASHKEYLEN >= r->headers_in.user_agent->value.len + r->connection->addr_text.len) {
            ua_max_len = r->headers_in.user_agent->value.len;
        } else {
            ua_max_len = HASHKEYLEN - r->connection->addr_text.len;
        }
        strncpy(text_key, r->headers_in.user_agent->value.data, ua_max_len);
    }
    
    
    
    printf("nazdar\n");
    
    ngx_http_anddos_clients = (ngx_http_anddos_client_t *) calloc(1000, sizeof(ngx_http_anddos_client_t));
    
    char * t = "asdasd";
    char * tu = "asd";
    
    printf("hash key: %u\n", ngx_hash_key(t, sizeof(t)));
    
    printf("hash key charc: %u\n", ngx_hash_key(t, sizeof(t)/sizeof(char)));
    
    printf("hash key u: %u\n", ngx_hash_key(tu, sizeof(tu)));
    
    printf("hash key charc u: %u\n", ngx_hash_key(tu, sizeof(tu)/sizeof(char)));
    
    printf("ngx_http_anddos_client_t: %lu\n", sizeof(ngx_http_anddos_client_t));
    
    printf("ngx_http_anddos_clients: %lu\n", sizeof(ngx_http_anddos_clients));
    
    printf("ngx_http_anddos_clients[0].key: %lu\n", sizeof(ngx_http_anddos_clients[0].key));
    
    printf("ngx_http_anddos_clients[0].key[0]: %lu\n", sizeof(ngx_http_anddos_clients[0].key[0]));
    
    printf("ngx_http_anddos_state: %lu\n", sizeof(ngx_http_anddos_state));
    
    printf("ngx_http_anddos_state_t: %lu\n", sizeof(ngx_http_anddos_state_t));
    
    printf("ngx_http_anddos_state.request_count: %lu\n", sizeof(ngx_http_anddos_state.request_count));
    
    printf("*ngx_http_anddos_state.request_count: %lu\n", sizeof(&ngx_http_anddos_state.request_count));
    
    
    
    return (EXIT_SUCCESS);
}

*/