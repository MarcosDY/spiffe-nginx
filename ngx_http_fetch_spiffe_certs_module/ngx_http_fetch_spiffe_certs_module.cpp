extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
}
#include <thread>
#include <csignal>
#include <fstream>
#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "workload.grpc.pb.h"

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

typedef struct {
    ngx_str_t ssl_spiffe_sock;
    ngx_str_t svid_file_path;
    ngx_str_t svid_key_file_path;
    ngx_str_t svid_bundle_file_path;
} ngx_http_fetch_spiffe_certs_srv_conf_t;

ngx_http_fetch_spiffe_certs_srv_conf_t spiffeConf;

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

static void derToPem(std::string der, const char* pemFileName) {
    X509 *x509;
    unsigned char *buf, *p;
    FILE* fd = NULL;

    int len = der.size();
    buf = (unsigned char *)der.c_str();
    p = buf;
    x509 = d2i_X509(NULL, (const unsigned char**)&p, len);
    if (x509 == NULL) {
         std::cout << "d2i_X509 error. Output file is: '" << pemFileName << "'" << std::endl;
        return;
    }
    fd = fopen(pemFileName,"w+");
    if (fd) {
        PEM_write_X509(fd, x509);
        fclose(fd);
    }
    else {
        std::cout << "can't open file: '" << pemFileName << "'" << std::endl;
    }
}

static void fetchSvids(ngx_http_fetch_spiffe_certs_srv_conf_t *conf) {
    bool sendSigHup = false;
    while (true) {
        std::unique_ptr<SpiffeWorkloadAPI::Stub> stub_;
        std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel("unix:/tmp/agent.sock", grpc::InsecureChannelCredentials());
        stub_ = SpiffeWorkloadAPI::NewStub(channel);

        std::cout << "Fetching SVIDs" << std::endl;

        X509SVIDRequest x509SVIDRequest;
        X509SVIDResponse x509SVIDResponse;
        ClientContext context;
        context.AddMetadata("workload.spiffe.io", "true");

        std::unique_ptr<ClientReader<X509SVIDResponse> > reader(
            stub_->FetchX509SVID(&context, x509SVIDRequest));

        while (reader->Read(&x509SVIDResponse)) {
            std::cout << "Found X509SVID with SPIFFE ID: " << x509SVIDResponse.svids(0).spiffe_id() << std::endl;

            derToPem(x509SVIDResponse.svids(0).x509_svid(), (const char*)conf->svid_file_path.data);
            derToPem(x509SVIDResponse.svids(0).x509_svid_key(), (const char*)conf->svid_key_file_path.data);
            derToPem(x509SVIDResponse.svids(0).bundle(), (const char*)conf->svid_bundle_file_path.data);
        }

        if (sendSigHup) {
            reader->Finish();
            std::cout << "Sending SIGHUP signal" << std::endl;
            std::raise(SIGHUP);
        }
        else {
            sendSigHup = true;
        }
    }
}

static ngx_int_t ngx_http_fetch_spiffe_certs(ngx_http_fetch_spiffe_certs_srv_conf_t *conf) {
    std::thread fetchSvidsThread(fetchSvids, conf);
    fetchSvidsThread.detach();

    return NGX_OK;
}

static char * ngx_http_fetch_spiffe_certs_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t *prev = (ngx_http_fetch_spiffe_certs_srv_conf_t*)parent;
    ngx_http_fetch_spiffe_certs_srv_conf_t *conf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)child;

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
