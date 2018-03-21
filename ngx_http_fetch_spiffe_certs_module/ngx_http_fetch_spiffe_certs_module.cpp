extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
}
#include <csignal>
#include <grpc/grpc.h>
#include <grpc++/channel.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/security/credentials.h>
#include "workload.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::ClientWriter;
using grpc::Status;

class SpiffeWorkloadAPIClient {
 public:
  SpiffeWorkloadAPIClient(std::shared_ptr<Channel> channel)
      : stub_(SpiffeWorkloadAPI::NewStub(channel)) {}

  void FetchX509SVID() {
    std::cout << "Fetching SVIDs" << std::endl;

    X509SVIDRequest x509SVIDRequest;
    X509SVIDResponse x509SVIDResponse;
    ClientContext context;
    context.AddMetadata("workload.spiffe.io", "true");

    std::unique_ptr<ClientReader<X509SVIDResponse> > reader(
        stub_->FetchX509SVID(&context, x509SVIDRequest));

    while (reader->Read(&x509SVIDResponse)) {
      std::cout << "Found X509SVID with SPIFFE ID: " << x509SVIDResponse.svids(0).spiffe_id() << std::endl;
    }

    Status status = reader->Finish();
    if (status.ok()) {
      std::cout << "FetchX509SVID rpc succeeded." << std::endl;
    } else {
      std::cout << "FetchX509SVID rpc failed." << std::endl;
    }
    //std::raise(SIGHUP);
  }

 private:
  std::unique_ptr<SpiffeWorkloadAPI::Stub> stub_;
};

typedef struct {
    int    foo;
} my_thread_ctx_t;

typedef struct {
    ngx_str_t ssl_spiffe_sock;
    ngx_str_t svid_file_path;
    ngx_str_t svid_key_file_path;
    ngx_str_t svid_bundle_file_path;
} ngx_http_fetch_spiffe_certs_srv_conf_t;

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

static void my_thread_func(void *data, ngx_log_t *log)
{
}

static void my_thread_completion(ngx_event_t *ev)
{
}

ngx_int_t fetch_svids_task(ngx_conf_t *conf)
{
    my_thread_ctx_t    *ctx;
    ngx_thread_task_t  *task;

    ngx_str_t name = ngx_string("spiffe_workload_api");
    ngx_thread_pool_t *tp;

    tp = ngx_thread_pool_add(conf, &name);
    if (tp == NULL) {
        return NGX_ERROR;
    }
    task = ngx_thread_task_alloc(conf->pool, sizeof(my_thread_ctx_t));
    if (task == NULL) {
        return NGX_ERROR;
    }

    ctx = (my_thread_ctx_t*)task->ctx;
    ctx->foo = 42;
    task->handler = my_thread_func;
    task->event.handler = my_thread_completion;
    task->event.data = ctx;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void * ngx_http_fetch_spiffe_certs_create_conf(ngx_conf_t *cf)
{
    ngx_http_fetch_spiffe_certs_srv_conf_t  *scf;
    scf = (ngx_http_fetch_spiffe_certs_srv_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_fetch_spiffe_certs_srv_conf_t));
    return scf;
}

static ngx_int_t ngx_http_fetch_spiffe_certs(ngx_http_fetch_spiffe_certs_srv_conf_t *conf) {
    std::shared_ptr<grpc::Channel> ch = grpc::CreateChannel("unix:/tmp/agent.sock", grpc::InsecureChannelCredentials());
    SpiffeWorkloadAPIClient wlclient(ch);
    wlclient.FetchX509SVID();

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
