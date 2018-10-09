extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_stream.h>
}

#include <thread>

#include "c-spiffe.h"
#include "ngx_common_spiffe_module.h"

void svid_stream_updated_callback(X509SVIDResponse x509SVIDResponse);

spiffe::WorkloadAPIClient workloadClient_stream(svid_stream_updated_callback);

extern "C" ngx_int_t create_stream_spiffe_thread(ngx_ssl_t *ssl, ngx_flag_t is_client, ngx_int_t depth);
extern "C" ngx_int_t is_stream_certificates_updated();

static ngx_ssl_thread_config_t ngx_stream_ssl_thread_config;

typedef struct {
    ngx_str_t ssl_spiffe_sock;
} ngx_stream_fetch_spiffe_certs_srv_conf_t;

ngx_stream_fetch_spiffe_certs_srv_conf_t stream_configuration;

static ngx_command_t ngx_stream_fetch_spiffe_certs_commands[] = {
    { ngx_string("ssl_spiffe_sock"),
        NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_stream_fetch_spiffe_certs_srv_conf_t, ssl_spiffe_sock),
        NULL },
      ngx_null_command
};

static void * ngx_stream_fetch_spiffe_certs_create_conf(ngx_conf_t *cf)
{
    ngx_stream_fetch_spiffe_certs_srv_conf_t  *scf;
    scf = (ngx_stream_fetch_spiffe_certs_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_stream_fetch_spiffe_certs_srv_conf_t));
    return scf;
}

void svid_stream_updated_callback(X509SVIDResponse x509SVIDResponse) {
    svid_updated_callback(x509SVIDResponse, &ngx_stream_ssl_thread_config);
}

void fetch_stream_svids(ngx_ssl_t *ssl) {
    fetch_svids(ssl, &ngx_stream_ssl_thread_config, &workloadClient_stream, &stream_configuration.ssl_spiffe_sock);
}

/**
 * return NGX_OK in case certificate was reloaded into SSL_CTX.
 */
ngx_int_t is_stream_certificates_updated() {
    if (ngx_stream_ssl_thread_config.svids_updated) {
        return NGX_OK;
    }

    return NGX_AGAIN;
}

/**
 *  Create a thread to automatically consume gRPC and load certificates into SSL_CTX
 */
ngx_int_t create_stream_spiffe_thread(ngx_ssl_t *ssl, ngx_flag_t is_client, ngx_int_t depth) {
    spiffe_log(NGX_LOG_INFO, ngx_stream_ssl_thread_config.log, "creating threads to fetch updates from SPIFFE Workload API");

    ngx_stream_ssl_thread_config.svids_updated = false;
    ngx_stream_ssl_thread_config.is_client_certificate = (is_client == 1);
    ngx_stream_ssl_thread_config.depth = depth;

    std::thread fetch_svids_thread(fetch_stream_svids, ssl);
    fetch_svids_thread.detach();

    return NGX_OK;
}

static char * ngx_stream_fetch_spiffe_certs_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_fetch_spiffe_certs_srv_conf_t *prev = (ngx_stream_fetch_spiffe_certs_srv_conf_t*)parent;
    ngx_stream_fetch_spiffe_certs_srv_conf_t *conf = (ngx_stream_fetch_spiffe_certs_srv_conf_t*)child;

    ngx_stream_ssl_thread_config.log = &cf->cycle->new_log;

    ngx_conf_merge_str_value(conf->ssl_spiffe_sock, prev->ssl_spiffe_sock, "");
    
    if (conf->ssl_spiffe_sock.len < 1) {
        spiffe_log(NGX_LOG_ERR, ngx_stream_ssl_thread_config.log, "ssl_spiffe_sock was no provided.");
    }
    stream_configuration.ssl_spiffe_sock = conf->ssl_spiffe_sock;
    
    return NGX_CONF_OK;
}

static ngx_stream_module_t ngx_stream_fetch_spiffe_certs_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    ngx_stream_fetch_spiffe_certs_create_conf,    /* create server configuration */
    ngx_stream_fetch_spiffe_certs_merge_srv_conf, /* merge server configuration */
};

ngx_module_t ngx_stream_fetch_spiffe_certs_module = {
    NGX_MODULE_V1,
    &ngx_stream_fetch_spiffe_certs_module_ctx,  /* module context */
    ngx_stream_fetch_spiffe_certs_commands,     /* module directives */
    NGX_STREAM_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};
