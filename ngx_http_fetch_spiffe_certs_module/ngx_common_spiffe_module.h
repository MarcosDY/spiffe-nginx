#ifndef __NGX_COMMON_SPIFFE_H_INCLUDED__
#define __NGX_COMMON_SPIFFE_H_INCLUDED__

#define INITIAL_DELAY 1000000 // microseconds
#define MAX_DELAY INITIAL_DELAY * 60

#include <string>
#include <sstream>
#include "c-spiffe.h"

typedef struct {
    ngx_ssl_t   **ngx_ssl;
    bool is_client_certificate = false;
    ngx_int_t depth;
    bool svids_updated = false;
    useconds_t retry_delay_svids = INITIAL_DELAY;
    ngx_log_t *log;
} ngx_ssl_thread_config_t;

void spiffe_log(ngx_uint_t log_level, ngx_log_t *log, std::string message);
void spiffe_log(ngx_uint_t log_level, ngx_log_t *log, std::string message, std::string arg);
void svid_updated_callback(X509SVIDResponse x509SVIDResponse, ngx_ssl_thread_config_t *config);
void fetch_svids(ngx_ssl_t *ssl, ngx_ssl_thread_config_t *config, spiffe::WorkloadAPIClient *workloadClient, ngx_str_t *ssl_spiffe_sock);
::std::string get_bundle(X509SVIDResponse x509SVIDResponse, ngx_ssl_thread_config_t *config);

#endif // __NGX_COMMON_SPIFFE_H_INCLUDED__
