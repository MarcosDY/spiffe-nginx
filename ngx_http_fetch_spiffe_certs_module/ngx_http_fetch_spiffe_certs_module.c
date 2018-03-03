#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t ssl_spiffe_sock;
    ngx_str_t svid_file_path;
    ngx_str_t svid_key_file_path;
    ngx_str_t svid_bundle_file_path;
} ngx_http_ssl_spiffe_srv_conf_t;

static ngx_command_t ngx_http_fetch_spiffe_certs_commands[] = {
    { ngx_string("ssl_spiffe_sock"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_spiffe_srv_conf_t, ssl_spiffe_sock),
        NULL },
    { ngx_string("svid_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_spiffe_srv_conf_t, svid_file_path),
        NULL },
    { ngx_string("svid_key_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_spiffe_srv_conf_t, svid_key_file_path),
        NULL },
    { ngx_string("svid_bundle_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_ssl_spiffe_srv_conf_t, svid_bundle_file_path),
        NULL },
      ngx_null_command
};

static void * ngx_http_fetch_spiffe_certs_create_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_spiffe_srv_conf_t  *scf;

    scf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_spiffe_srv_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    return scf;
}

static ngx_int_t ngx_http_fetch_spiffe_certs(ngx_http_ssl_spiffe_srv_conf_t *conf) {
    void *go_module = dlopen("ngx_http_fetch_spiffe_certs_module.so", RTLD_LAZY);
    if (!go_module) {
        fprintf(stderr, "go module not found");
        return NGX_ERROR;
    }

    int (*fun)(u_char *, u_char *, u_char *, u_char *) = (int (*)(u_char *, u_char *, u_char *, u_char *)) dlsym(go_module, "FetchSvids");
    fun(conf->ssl_spiffe_sock.data,
                            conf->svid_file_path.data,
                            conf->svid_key_file_path.data,
                            conf->svid_bundle_file_path.data);

    return NGX_OK;
}

static char * ngx_http_fetch_spiffe_certs_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssl_spiffe_srv_conf_t *prev = parent;
    ngx_http_ssl_spiffe_srv_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->ssl_spiffe_sock, prev->ssl_spiffe_sock, "");
    ngx_conf_merge_str_value(conf->svid_file_path, prev->svid_file_path, "");
    ngx_conf_merge_str_value(conf->svid_key_file_path, prev->svid_key_file_path, "");
    ngx_conf_merge_str_value(conf->svid_bundle_file_path, prev->svid_bundle_file_path, "");

    ngx_http_fetch_spiffe_certs(conf);
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_fetch_spiffe_certs_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    ngx_http_fetch_spiffe_certs_create_conf,    /* create server configuration */
    ngx_http_fetch_spiffe_certs_merge_srv_conf, /* merge server configuration */
    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};

ngx_module_t ngx_http_fetch_spiffe_certs_module = {
    NGX_MODULE_V1,
    &ngx_http_fetch_spiffe_certs_module_ctx,  /* module context */
    ngx_http_fetch_spiffe_certs_commands,     /* module directives */
    NGX_HTTP_MODULE,                          /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    NULL,                                     /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};
