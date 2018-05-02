extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
}

#include <thread>
#include <mutex>
#include <signal.h>
#include <sstream>

#include "c-spiffe.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;

#define INITIAL_DELAY 1000000 // microseconds
#define MAX_DELAY INITIAL_DELAY * 60
useconds_t retry_delay = INITIAL_DELAY;

bool firstFetch = true;
void updatedCallback(X509SVIDResponse x509SVIDResponse);
spiffe::WorkloadAPIClient workloadClient(updatedCallback);
static void log(std::string message, std::string arg);
static void log(std::string message);
static int xname_cmp(const X509_NAME * const *a, const X509_NAME * const *b);
                     
extern "C" ngx_int_t create_spiffe_thread(ngx_ssl_t *ssl, ngx_flag_t is_client, ngx_int_t depth);
extern "C" ngx_int_t is_certificates_updated();
ngx_int_t ngx_ssl_spiffe_reload_certificate(ngx_ssl_t *ngx_ssl, std::string cert_der, std::string key_der);
ngx_int_t ngx_ssl_spiffe_reload_client_certificate(ngx_ssl_t *ngx_ssl, std::string bundle_der);
ngx_int_t ngx_ssl_spiffe_reload_trusted_certificate(ngx_ssl_t *ngx_ssl, std::string bundle_der);
ngx_int_t ngx_ssl_spiffe_add_all_ca(ngx_ssl_t *ngx_ssl, std::string bundle_der);

typedef struct {
    ngx_ssl_t   **ngx_ssl;
    bool is_client_certificate = false;
    ngx_int_t depth;
    bool updated = false;
} ngx_ssl_thread_config_t;

static ngx_ssl_thread_config_t ngx_ssl_thread_config;

typedef struct {
    ngx_str_t ssl_spiffe_sock;
} ngx_http_fetch_spiffe_certs_srv_conf_t;

ngx_http_fetch_spiffe_certs_srv_conf_t configuration;

static ngx_command_t ngx_http_fetch_spiffe_certs_commands[] = {
    { ngx_string("ssl_spiffe_sock"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_fetch_spiffe_certs_srv_conf_t, ssl_spiffe_sock),
        NULL },
      ngx_null_command
};

static void * ngx_http_fetch_spiffe_certs_create_conf(ngx_conf_t *cf)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t  *scf;
    scf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_fetch_spiffe_certs_srv_conf_t));
    return scf;
}

void updatedCallback(X509SVIDResponse x509SVIDResponse) {
    log("fetched X509SVID with SPIFFE ID: ", x509SVIDResponse.svids(0).spiffe_id());
    ngx_ssl_thread_config.updated = false;
    
    // Successfull response received. Reset delay
    retry_delay = INITIAL_DELAY;

    ngx_ssl_t *ngx_ssl = *ngx_ssl_thread_config.ngx_ssl;

    // reload certificate and key into SSL_CTX
    ngx_ssl_spiffe_reload_certificate(ngx_ssl, x509SVIDResponse.svids(0).x509_svid(), x509SVIDResponse.svids(0).x509_svid_key());

    // reload trusted or client certificate into SSL_CTX
    if (ngx_ssl_thread_config.is_client_certificate) {
        ngx_ssl_spiffe_reload_client_certificate(ngx_ssl,  x509SVIDResponse.svids(0).bundle());
    } else {
        ngx_ssl_spiffe_reload_trusted_certificate(ngx_ssl, x509SVIDResponse.svids(0).bundle());
    }

    if (!firstFetch) {
        workloadClient.StopFetchingX509SVIDs();
    }
    firstFetch = false;
    ngx_ssl_thread_config.updated = true;
}

void fetch_svids(ngx_ssl_t *ssl) {
    log("fetching SVIDs");
    
    // update thread config with provided ssl
    ngx_ssl_thread_config.ngx_ssl = &ssl;
    
    firstFetch = true;
    retry_delay = INITIAL_DELAY;
    std::string socket_address = (const char*)configuration.ssl_spiffe_sock.data;
    std::string const SOCKET_PATH_ERR = "Invalid socket path for Workload API endpoint: ";
    if (socket_address.length() == 0) {
        log(SOCKET_PATH_ERR, "empty path");
        return;
    }

    if (socket_address.at(0) != '/') {
        log(SOCKET_PATH_ERR, "path not absolute");
        return;
    }    
    workloadClient.SetSocketAddress("unix:" + socket_address);

    Start:
    workloadClient.FetchX509SVIDs();
    if (!workloadClient.GetFetchX509SVIDsStatus().ok()) {
        std::stringstream msg;
        msg << "FetchX509SVID rpc failed. Error code: " <<
            workloadClient.GetFetchX509SVIDsStatus().error_code() <<
            ". Error message: " <<
            workloadClient.GetFetchX509SVIDsStatus().error_message();
        log(msg.str());
        usleep(retry_delay);
        if (retry_delay < MAX_DELAY) {
            retry_delay += retry_delay;
        }
        goto Start;
    }

    kill(::getpid(), SIGHUP);
}

/**
 * return NGX_OK in case certificate was reloaded into SSL_CTX.
 */
ngx_int_t is_certificates_updated() {

    if (ngx_ssl_thread_config.updated) {
        return NGX_OK;
    }

    return NGX_AGAIN;
}

/**
 *  Create a thread to automatically consume gRPC and load certificates into SSL_CTX
 */
ngx_int_t create_spiffe_thread(ngx_ssl_t *ssl, ngx_flag_t is_client, ngx_int_t depth) {
    
    ngx_ssl_thread_config.updated = false;
    
    ngx_ssl_thread_config.is_client_certificate = (is_client == 1);
    ngx_ssl_thread_config.depth = depth;

    std::thread fetch_svids_thread(fetch_svids, ssl);
    fetch_svids_thread.detach();

    return NGX_OK;
}


static char * ngx_http_fetch_spiffe_certs_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t *prev = (ngx_http_fetch_spiffe_certs_srv_conf_t*)parent;
    ngx_http_fetch_spiffe_certs_srv_conf_t *conf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)child;

    ngx_conf_merge_str_value(conf->ssl_spiffe_sock, prev->ssl_spiffe_sock, "");
   
    configuration.ssl_spiffe_sock = conf->ssl_spiffe_sock;
    
    return NGX_CONF_OK;
}

static void log(std::string message)
{
    log(message, "");
}

static void log(std::string message, std::string arg)
{
    time_t ctt = time(0);
    char now[30];
    strftime(now, 30, "%Y/%m/%d %H:%M:%S", localtime(&ctt));
    std::cout << now << " [spiffe] " << getpid() << ": " << message << arg << std::endl;
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

/**
 * Reload certificate and key into SSL_CTX, use provided der and transform them into x509 and EVP_PKEY.
 */
ngx_int_t
ngx_ssl_spiffe_reload_certificate(ngx_ssl_t *ngx_ssl, std::string cert_der, std::string key_der)
{
    X509        *x509;
    EVP_PKEY *evp;
    ngx_str_t   *pwd;
    ngx_uint_t   tries;
    ngx_ssl_t *ssl;
    unsigned char *buf, *p;

    // Set ssl with provided ngx_ssl
    //
    ssl = ngx_ssl;
    
    // Parse der to x509
    //
    int len = cert_der.size();
    buf = (unsigned char *)cert_der.c_str();
    p = buf;
    x509 = d2i_X509(NULL, (const unsigned char**)&p, len);
    if (x509 == NULL) {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                    (char *) "Could not extract certificate from svid");
        
        return NGX_ERROR;
    }
    
    // Use provided x509 certificate.
    //
    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {     
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      (char *) "SSL_CTX_use_certificate failed");
                      
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set certificate name.
    //
    ngx_str_t certificateName = ngx_string("SPIFFE SVID certificate");
    if (X509_set_ex_data(x509, ngx_ssl_certificate_name_index, certificateName.data)
        == 0)
    {
        
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, (char *) "X509_set_ex_data() failed");
        
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set next certificate 
    //
    if (X509_set_ex_data(x509, ngx_ssl_next_certificate_index,
                      SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index))
        == 0)
    { 
        
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0, (char *) "X509_set_ex_data() failed");
        
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set extra data for certificate
    //
    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, x509)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      (char *) "SSL_CTX_set_ex_data() failed");
                    
        X509_free(x509);
        return NGX_ERROR;
    }

    tries = 1;
#if (NGX_SUPPRESS_WARN)
    pwd = NULL;
#endif
    
    buf = (unsigned char *)key_der.c_str();
    p = buf;
    len = key_der.size();

    for ( ;; ) {
        // Transform DER to EVP_KEY
        //
        evp =  d2i_AutoPrivateKey(NULL, (const unsigned char**)&p,
                                len);
        if (evp == NULL) {
            log("could not extract evp key for");
            return NGX_ERROR;
        }
        
        if (SSL_CTX_use_PrivateKey(ssl->ctx, evp)
            != 0)
        {
            break;
        }

        if (--tries) {
            ERR_clear_error();
            SSL_CTX_set_default_passwd_cb_userdata(ssl->ctx, ++pwd);
            continue;
        }
  
        ngx_ssl_error(NGX_LOG_EMERG, ssl->log, 0,
                      (char *) "SSL_CTX_use_PrivateKey() failed");
                    
        return NGX_ERROR;
    }
    
    SSL_CTX_set_default_passwd_cb(ssl->ctx, NULL);

    return NGX_OK;
}

/**
 * verify_callback method, as nginx it's used only for debug porpuses.
 */
static int
ngx_ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
    return 1;
}

/**
 * Reload all client certificates into SSL_CTX using provided bundle_der.
 */
ngx_int_t
ngx_ssl_spiffe_reload_client_certificate(ngx_ssl_t *ngx_ssl, std::string bundle_der)
{ 
    ngx_ssl_t *ssl;
    X509_NAME *xn = NULL;
    X509 *x509;
    unsigned char *buf, *p;
    STACK_OF(X509_NAME) *sk;

    ssl = ngx_ssl;
    sk = sk_X509_NAME_new(xname_cmp);

    // Set verify methods.
    //
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
    SSL_CTX_set_verify_depth(ssl->ctx, ngx_ssl_thread_config.depth);

    // Add all CAs into SSL_CTX
    //
	ngx_ssl_spiffe_add_all_ca(ssl, bundle_der);
 
    int len = bundle_der.size();
    buf = (unsigned char *)bundle_der.c_str();
    p = buf;

    // Extract all X509_NAME from certificates inside bundle der and push them into STACK_OF(X509_NAME)
    //
    while ((x509 = d2i_X509(NULL, (const unsigned char**)&p, len)) != NULL) {
        if (x509 == NULL) {
            log("d2i_X509 error. ");
            X509_free(x509);    
            return NGX_ERROR;
        }
        xn = X509_get_subject_name(x509);
        if (sk_X509_NAME_find(sk, xn) >= 0) {
			X509_NAME_free(xn);
        }
		else {
			sk_X509_NAME_push(sk, xn);
		}
    }
    X509_free(x509);

    // Set all client CAs from STACK
    //
    SSL_CTX_set_client_CA_list(ssl->ctx, sk);
    return NGX_OK;
}

/**
 * Reload all trusted certificates into SSL_CTX using provided bundle_der.
 */
ngx_int_t
ngx_ssl_spiffe_reload_trusted_certificate(ngx_ssl_t *ngx_ssl, std::string bundle_der)
{
    ngx_ssl_t *ssl;
    ssl = ngx_ssl;

    // Set verify methods.
    //
    SSL_CTX_set_verify_depth(ssl->ctx, ngx_ssl_thread_config.depth);
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
    
    // Add all CAs into SSL_CTX
    //
	ngx_ssl_spiffe_add_all_ca(ssl, bundle_der);

    ERR_clear_error();

    return NGX_OK;
}

/**
 * Add all CA certificates from bundle_der into SSL_CTX
 */
ngx_int_t
ngx_ssl_spiffe_add_all_ca(ngx_ssl_t *ngx_ssl, std::string bundle_der) {
    ngx_ssl_t *ssl;
    X509_STORE *store = NULL;
    X509 *x509;
    unsigned char *buf, *p;

    ssl = ngx_ssl;

    int len = bundle_der.size();
    buf = (unsigned char *)bundle_der.c_str();
    p = buf;
   
    // Get certificate store, to push all CAs.
    //
    store = SSL_CTX_get_cert_store(ssl->ctx);
    
    if(!store) {
        log("could not get store");    
        return NGX_ERROR;
    }

    // Consume all certificates into bundle and push inside X509_STORE
    //
    while ((x509 = d2i_X509(NULL, (const unsigned char**)&p, len)) != NULL) {
        if (x509 == NULL) {
            log("d2i_X509 error. ");
            X509_free(x509);    
            return NGX_ERROR;
        }

        if(!X509_STORE_add_cert(store, x509)) {
            log("could not X509_STORE_add_cert");    
            X509_free(x509); 
            return NGX_ERROR;
            
        }

        X509_free(x509);
    }

    return NGX_OK;
}


/**
 * Compare provided X509_NAMEs.
 */
static int
xname_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
{
	return (X509_NAME_cmp(*a, *b));
}