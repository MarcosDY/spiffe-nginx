extern "C" {
    #include <ngx_config.h>
    #include <ngx_core.h>
}

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "ngx_common_spiffe_module.h"

static ngx_int_t ngx_ssl_spiffe_reload_certificates(ngx_ssl_t *ngx_ssl, std::string cert_der, std::string key_der, ngx_ssl_thread_config_t *config);
static ngx_int_t ngx_ssl_spiffe_reload_client_certificates(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config);
static ngx_int_t ngx_ssl_spiffe_reload_trusted_certificates(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config);

static ngx_int_t ngx_ssl_spiffe_add_all_cas(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config);
static int xname_cmp(const X509_NAME * const *a, const X509_NAME * const *b);


/**
 * Reload certificate and key into SSL_CTX, use provided der and transform them into x509 and EVP_PKEY.
 */
static ngx_int_t
ngx_ssl_spiffe_reload_certificates(ngx_ssl_t *ngx_ssl, std::string cert_der, std::string key_der, ngx_ssl_thread_config_t *config)
{
    X509        *x509;
    EVP_PKEY *evp;
    ngx_str_t   *pwd;
    ngx_uint_t   tries;
    ngx_ssl_t *ssl;
    unsigned char *buf, *p;

    spiffe_log(NGX_LOG_DEBUG, config->log, "reloading certificates");
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
        spiffe_log(NGX_LOG_ERR, config->log, "could not extract certificate from svid");
        
        return NGX_ERROR;
    }
    
    // Use provided x509 certificate.
    //
    if (SSL_CTX_use_certificate(ssl->ctx, x509) == 0) {     
        spiffe_log(NGX_LOG_ERR, config->log, "SSL_CTX_use_certificate failed");
                      
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set certificate name.
    //
    ngx_str_t certificateName = ngx_string("SPIFFE SVID certificate");
    if (X509_set_ex_data(x509, ngx_ssl_certificate_name_index, certificateName.data)
        == 0)
    {
        spiffe_log(NGX_LOG_ERR, config->log, "X509_set_ex_data() failed");
        
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set next certificate 
    //
    if (X509_set_ex_data(x509, ngx_ssl_next_certificate_index,
                      SSL_CTX_get_ex_data(ssl->ctx, ngx_ssl_certificate_index))
        == 0)
    { 
        spiffe_log(NGX_LOG_ERR, config->log, "X509_set_ex_data() failed");
        
        X509_free(x509);
        return NGX_ERROR;
    }

    // Set extra data for certificate
    //
    if (SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, x509)
        == 0)
    {
        spiffe_log(NGX_LOG_ERR, config->log, "SSL_CTX_set_ex_data() failed");
                     
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
        spiffe_log(NGX_LOG_DEBUG, config->log, "reloading keys");

        // Transform DER to EVP_KEY
        //
        evp =  d2i_AutoPrivateKey(NULL, (const unsigned char**)&p,
                                len);
        if (evp == NULL) {
            spiffe_log(NGX_LOG_ERR, config->log, "could not extract evp key for");
            return NGX_ERROR;
        }
        
        if (SSL_CTX_use_PrivateKey(ssl->ctx, evp)
            != 0)
        {
            break;
        }

        if (--tries) {
            spiffe_log(NGX_LOG_ERR, config->log, "SSL_CTX_use_PrivateKey() failed, retrying");
            ERR_clear_error();
            SSL_CTX_set_default_passwd_cb_userdata(ssl->ctx, ++pwd);
            continue;
        }
        spiffe_log(NGX_LOG_ERR, config->log, "SSL_CTX_use_PrivateKey() failed");
                   
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
static ngx_int_t
ngx_ssl_spiffe_reload_client_certificates(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config)
{ 
    ngx_ssl_t *ssl;
    X509_NAME *xn = NULL;
    X509 *x509;
    unsigned char *buf, *p;
    STACK_OF(X509_NAME) *sk;

    spiffe_log(NGX_LOG_DEBUG, config->log, "reloading client certificate");

    ssl = ngx_ssl;
    sk = sk_X509_NAME_new(xname_cmp);

    // Set verify methods.
    //
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
    SSL_CTX_set_verify_depth(ssl->ctx, config->depth);

    // Add all CAs into SSL_CTX
    //
	ngx_ssl_spiffe_add_all_cas(ssl, bundle_der, config);
 
    int len = bundle_der.size();
    buf = (unsigned char *)bundle_der.c_str();
    p = buf;

    // Extract all X509_NAME from certificates inside bundle der and push them into STACK_OF(X509_NAME)
    //
    while ((x509 = d2i_X509(NULL, (const unsigned char**)&p, len)) != NULL) {
        if (x509 == NULL) {
            spiffe_log(NGX_LOG_ERR, config->log, "d2i_X509 error. ");
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
static ngx_int_t
ngx_ssl_spiffe_reload_trusted_certificates(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config)
{
    ngx_ssl_t *ssl;
    ssl = ngx_ssl;
    spiffe_log(NGX_LOG_DEBUG, config->log, "reloading trusted certificate");

    // Set verify methods.
    //
    SSL_CTX_set_verify_depth(ssl->ctx, config->depth);
    SSL_CTX_set_verify(ssl->ctx, SSL_VERIFY_PEER, ngx_ssl_verify_callback);
    
    // Add all CAs into SSL_CTX
    //
	ngx_ssl_spiffe_add_all_cas(ssl, bundle_der, config);

    ERR_clear_error();

    return NGX_OK;
}

/**
 * Add all CA certificates from bundle_der into SSL_CTX
 */
static ngx_int_t
ngx_ssl_spiffe_add_all_cas(ngx_ssl_t *ngx_ssl, std::string bundle_der, ngx_ssl_thread_config_t *config) {
    ngx_ssl_t *ssl;
    X509_STORE *store = NULL;
    X509 *x509;
    unsigned char *buf, *p;
    
    spiffe_log(NGX_LOG_DEBUG, config->log, "adding certificates from bundle");
    ssl = ngx_ssl;

    int len = bundle_der.size();
    buf = (unsigned char *)bundle_der.c_str();
    p = buf;
   
    // Get certificate store, to push all CAs.
    //
    store = SSL_CTX_get_cert_store(ssl->ctx);
    
    if(!store) {
        spiffe_log(NGX_LOG_ERR, config->log, "could not get cert store");    
        return NGX_ERROR;
    }

    // Consume all certificates into bundle and push inside X509_STORE
    //
    while ((x509 = d2i_X509(NULL, (const unsigned char**)&p, len)) != NULL) {
        if (x509 == NULL) {
            spiffe_log(NGX_LOG_ERR, config->log, "d2i_X509 error");
            X509_free(x509);    
            return NGX_ERROR;
        }

        if(!X509_STORE_add_cert(store, x509)) {
            auto error = ERR_get_error();
            // Check for duplicate root certificate
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                spiffe_log(NGX_LOG_ERR, config->log, "could not add root certificate to ssl context");
            X509_free(x509);
            return NGX_ERROR;
            }
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

/** 
 * Log message into stderr configured for nginx
 */
void spiffe_log(ngx_uint_t log_level, ngx_log_t *log, std::string message)
{
    spiffe_log(log_level, log, message, "");
}

/**
 * Log message into stderr configured for nginx
 */
void spiffe_log(ngx_uint_t log_level, ngx_log_t *log, std::string message, std::string arg)
{
    if(!log) {
        return;
    }

    if (log_level > log->log_level) {
        return;
    }
    static const char *severities[] = {"stderr", "emerg", "alert", "crit",
        "error", "warn", "notice", "info", "debug", NULL};

    time_t ctt = time(0);
    char now[30];
    strftime(now, 30, "%Y/%m/%d %H:%M:%S", localtime(&ctt));
fprintf(stderr, "%s [spiffe-%s] %i: %s %s \n", now, severities[log_level], getpid(), message.c_str(), arg.c_str());
}

/**
 * Update ssl context in provided config using GRPC response. 
 */
void svid_updated_callback(X509SVIDResponse x509SVIDResponse, ngx_ssl_thread_config_t *config) {
    spiffe_log(NGX_LOG_DEBUG, config->log, "fetched X509SVID with SPIFFE ID: ", x509SVIDResponse.svids(0).spiffe_id());
    config->svids_updated = false;

    // Successfull response received. Reset delay
    config->retry_delay_svids = INITIAL_DELAY;

    ngx_ssl_t *ngx_ssl = *config->ngx_ssl;

    int svids_size = x509SVIDResponse.svids_size();
    
    if (svids_size < 1) {
        spiffe_log(NGX_LOG_ERR, config->log, "no SVID was returned");
    }

    if (svids_size > 1) {
        spiffe_log(NGX_LOG_WARN, config->log, "only first SVID will be used from multiple svids returned");
    }

    // reload certificate and key into SSL_CTX
    ngx_ssl_spiffe_reload_certificates(ngx_ssl, x509SVIDResponse.svids(0).x509_svid(), x509SVIDResponse.svids(0).x509_svid_key(), config);

    // Concatenate all bundles into a single bundle
    ::std::string bundle = get_bundle(x509SVIDResponse, config);
   
    // reload trusted or client certificate into SSL_CTX
    if (config->is_client_certificate) {
        ngx_ssl_spiffe_reload_client_certificates(ngx_ssl,  bundle, config);
    } else {
        ngx_ssl_spiffe_reload_trusted_certificates(ngx_ssl, bundle, config);
    }

    config->svids_updated = true; 
}

/**
 * Fetch svids calling the Workload API.
 */
void fetch_svids(ngx_ssl_t *ssl, ngx_ssl_thread_config_t *config, spiffe::WorkloadAPIClient *workloadClient, ngx_str_t *ssl_spiffe_sock) {
    spiffe_log(NGX_LOG_DEBUG, config->log, "fetching SVIDs");
   
    // update thread config with provided ssl
    config->ngx_ssl = &ssl;
    
    config->retry_delay_svids = INITIAL_DELAY;
    
    std::string socket_address = (const char*)ssl_spiffe_sock->data;
    std::string const SOCKET_PATH_ERR = "Invalid socket path for Workload API endpoint: ";
    if (socket_address.length() == 0) {
        spiffe_log(NGX_LOG_ERR, config->log, SOCKET_PATH_ERR, "empty path");
        return;
    }

    if (socket_address.at(0) != '/') {
        spiffe_log(NGX_LOG_ERR, config->log, SOCKET_PATH_ERR, "path not absolute");
        return;
    }    
    workloadClient->SetSocketAddress("unix:" + socket_address);

    Start:
    workloadClient->FetchX509SVIDs();
    if (!workloadClient->GetFetchX509SVIDsStatus().ok()) {
        std::stringstream msg;
        msg << "FetchX509SVID rpc failed. Error code: " <<
            workloadClient->GetFetchX509SVIDsStatus().error_code() <<
            ". Error message: " <<
            workloadClient->GetFetchX509SVIDsStatus().error_message();
        spiffe_log(NGX_LOG_ERR, config->log, msg.str());
        usleep(config->retry_delay_svids);
        config->retry_delay_svids += config->retry_delay_svids;
        if (config->retry_delay_svids > MAX_DELAY) {
            config->retry_delay_svids = MAX_DELAY;
        }
        goto Start;
    }
}

/**
 * Get a bundle that contains svid's bundle and all federated bundles that svid is federated with.
 */
::std::string get_bundle(X509SVIDResponse x509SVIDResponse, ngx_ssl_thread_config_t *config) {
    ::std::string bundle = "";
    ::std::string federatedBundle = "";
    ::google::protobuf::Map< ::std::string, ::std::string >::iterator it;

    ::google::protobuf::Map< ::std::string, ::std::string > federatedBundles = x509SVIDResponse.federated_bundles();
    ::X509SVID svid = x509SVIDResponse.svids(0);

    // Add svid bundle
    bundle += svid.bundle();

    // Iterate federateds with vector and add bundles to returned bundle.
    for (std::string federated : svid.federates_with()) {
        it = federatedBundles.find(federated);
        
        std::stringstream searchingMsg;
        searchingMsg << "searching federated bundle " << federated;
        spiffe_log(NGX_LOG_DEBUG, config->log, searchingMsg.str());

        if (it == federatedBundles.end()) {
            std::stringstream msg;
            msg << "federated bundle " << federated << " does not exist ";
            spiffe_log(NGX_LOG_WARN, config->log, msg.str());
            continue;
        } 
        bundle += it->second;
    }
    return bundle;
}