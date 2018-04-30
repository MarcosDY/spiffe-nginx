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
static bool is_certificate_updated(const char *cert_path, ngx_conf_t *cf);
void updatedCallback(X509SVIDResponse x509SVIDResponse);
spiffe::WorkloadAPIClient workloadClient(updatedCallback);
static void log(std::string message, std::string arg);
static void log(std::string message);

typedef struct {
    ngx_str_t ssl_spiffe_sock;
    ngx_str_t svid_file_path;
    ngx_str_t svid_key_file_path;
    ngx_str_t svid_bundle_file_path;
} ngx_http_fetch_spiffe_certs_srv_conf_t;

ngx_http_fetch_spiffe_certs_srv_conf_t configuration;

static ngx_command_t ngx_http_fetch_spiffe_certs_commands[] = {
    { ngx_string("ssl_spiffe_sock"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_fetch_spiffe_certs_srv_conf_t, ssl_spiffe_sock),
        NULL },
    { ngx_string("svid_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_fetch_spiffe_certs_srv_conf_t, svid_file_path),
        NULL },
    { ngx_string("svid_key_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_fetch_spiffe_certs_srv_conf_t, svid_key_file_path),
        NULL },
    { ngx_string("svid_bundle_file_path"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_fetch_spiffe_certs_srv_conf_t, svid_bundle_file_path),
        NULL },
      ngx_null_command
};

static void * ngx_http_fetch_spiffe_certs_create_conf(ngx_conf_t *cf)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t  *scf;
    scf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_fetch_spiffe_certs_srv_conf_t));
    return scf;
}


static void der_key_to_pem(std::string der, const char* pem_file_path) {
    unsigned char *buf, *p;
    FILE* fd = NULL;
    EC_KEY    *ec;
    EVP_PKEY *evp;

    buf = (unsigned char *)der.c_str();
    p = buf;

    int len = der.size();

    // transform DER to EVP_KEY
    evp =  d2i_AutoPrivateKey(NULL, (const unsigned char**)&p,
                             len);
    if (evp == NULL) {
        log("could not extract evp key for: ", pem_file_path);
        return;
    }

    // get EC from EVP
    ec = EVP_PKEY_get1_EC_KEY(evp);

    if (ec == NULL) {
        log("could not get EC key for '%s'", pem_file_path);
        return;
    }

    // create or clean file if it exists
    fd = fopen(pem_file_path,"w+");
    if (fd) {
        PEM_write_ECPrivateKey(fd, ec, NULL, NULL, 0, 0, NULL);
        fclose(fd);
        return;
    }
    else {
        log("can't open file: ':%s'", pem_file_path);
    }
}

static void der_to_pem(std::string der, const char* pem_file_path) {
    X509 *x509;
    unsigned char *buf, *p;
    FILE* fd = NULL;

    int len = der.size();
    buf = (unsigned char *)der.c_str();
    p = buf;
    x509 = d2i_X509(NULL, (const unsigned char**)&p, len);
    if (x509 == NULL) {
        log("d2i_X509 error. Output file is: '%s'", pem_file_path);
        return;
    }
    fd = fopen(pem_file_path,"w+");
    if (fd) {
        PEM_write_X509(fd, x509);
        fclose(fd);
    }
    else {
         log("can't open file: '%s'", pem_file_path);
    }
}

static void der_bundle_to_pem(std::string der, const char* pem_file_path) {
    X509 *x509;
    unsigned char *buf, *p;
    FILE* fd = NULL;

    int len = der.size();
    buf = (unsigned char *)der.c_str();
    p = buf;

    fd = fopen(pem_file_path,"w+");

    while ((x509 = d2i_X509(NULL, (const unsigned char**)&p, len)) != NULL) {
        if (x509 == NULL) {
            log("d2i_X509 error. Output file is: '%s'", pem_file_path);
            X509_free(x509);    
            return;
        }

        if (fd) {
            PEM_write_X509(fd, x509);   
        }
        else {
            log("can't open file: '%s'", pem_file_path);
        }
        X509_free(x509);        
    }
    fclose(fd);
}

void updatedCallback(X509SVIDResponse x509SVIDResponse) {
    log("fetched X509SVID with SPIFFE ID: ", x509SVIDResponse.svids(0).spiffe_id());

    // Successfull response received. Reset delay
    retry_delay = INITIAL_DELAY;

    der_key_to_pem(x509SVIDResponse.svids(0).x509_svid_key(), (const char *)configuration.svid_key_file_path.data);
    der_bundle_to_pem(x509SVIDResponse.svids(0).bundle(), (const char *)configuration.svid_bundle_file_path.data);
    der_to_pem(x509SVIDResponse.svids(0).x509_svid(), (const char *)configuration.svid_file_path.data);

    if (!firstFetch) {
        workloadClient.StopFetchingX509SVIDs();
    }
    firstFetch = false;
}

void fetch_svids() {
    log("fetching SVIDs");
    firstFetch = true;
    retry_delay = INITIAL_DELAY;
    std::string socket_address = (const char*)configuration.ssl_spiffe_sock.data;
    std::string const SPIRE_AGENT_ERR = "Invalid socket path of SPIRE Agent: ";
    if (socket_address.length() == 0) {
        log(SPIRE_AGENT_ERR, "empty path");
        return;
    }

    if (socket_address.at(0) != '/') {
        log(SPIRE_AGENT_ERR, "path not absolute");
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

static char * ngx_http_fetch_spiffe_certs_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t *prev = (ngx_http_fetch_spiffe_certs_srv_conf_t*)parent;
    ngx_http_fetch_spiffe_certs_srv_conf_t *conf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)child;

    ngx_conf_merge_str_value(conf->ssl_spiffe_sock, prev->ssl_spiffe_sock, "");
    ngx_conf_merge_str_value(conf->svid_file_path, prev->svid_file_path, "");
    ngx_conf_merge_str_value(conf->svid_key_file_path, prev->svid_key_file_path, "");
    ngx_conf_merge_str_value(conf->svid_bundle_file_path, prev->svid_bundle_file_path, "");

    configuration.ssl_spiffe_sock = conf->ssl_spiffe_sock;
    configuration.svid_file_path = conf->svid_file_path;
    configuration.svid_key_file_path = conf->svid_key_file_path;
    configuration.svid_bundle_file_path = conf->svid_bundle_file_path;
    
    std::thread fetch_svids_thread(fetch_svids);
    fetch_svids_thread.detach();

    unsigned t0;
    t0 = clock();
    const int timeout = 30;
    
    // wait until certs are updated to continue
    while (!is_certificate_updated((const char*)conf->svid_file_path.data, cf) 
            && (double(clock()-t0)/CLOCKS_PER_SEC) < timeout) {
                // wait until certificate is updated or the timeout is reached
    }
    if ((double(clock()-t0)/CLOCKS_PER_SEC) >= timeout) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "certificates could not be updated");
    }

    return NGX_CONF_OK;
}

static bool is_certificate_updated(const char *cert_path, ngx_conf_t *cf)
{
    BIO         *bio;
    X509        *x509;
    bio = BIO_new_file(cert_path, "r");
    if (bio == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "certificate could not be loaded: '%s'", cert_path);
   
        return false;
    }
   
    while ((x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)) != NULL) {
        if (X509_cmp_current_time(X509_get_notAfter(x509)) > 0) {
            X509_free(x509);
            BIO_free(bio);
            return true;
        }
       X509_free(x509);
    }
    
    BIO_free(bio);
    return false;
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
