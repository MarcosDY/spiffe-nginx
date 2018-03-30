#include <grpc++/create_channel.h>
#include "workload.grpc.pb.h"

using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

namespace spiffe {
    typedef std::function<void(X509SVIDResponse)> SVIDsUpdatedCallback;

    class WorkloadAPIClient {
        public:
        WorkloadAPIClient(const std::string socket_address, SVIDsUpdatedCallback updatedCallback) {
            this->socket_address = socket_address;
            this->updatedCallback = updatedCallback;
        }

        void Start() {
            this->stop = false;
            fetchSVIDs();
        }

        void Stop() {
            this->stop = true;
        }

        Status GetStatus() {
            return status;
        }

        private:
        SVIDsUpdatedCallback updatedCallback;
        std::string socket_address;
        Status status;
        bool stop;

        void fetchSVIDs() {
            std::unique_ptr<SpiffeWorkloadAPI::Stub> stub;
            std::shared_ptr<grpc::Channel> channel = grpc::CreateChannel(socket_address, grpc::InsecureChannelCredentials());

            stub = SpiffeWorkloadAPI::NewStub(channel);

            X509SVIDRequest x509SVIDRequest;
            X509SVIDResponse x509SVIDResponse;
            ClientContext context;
            context.AddMetadata("workload.spiffe.io", "true");
            
            std::unique_ptr<ClientReader<X509SVIDResponse>> reader(stub->FetchX509SVID(&context, x509SVIDRequest));
            
            while (reader->Read(&x509SVIDResponse)) {
                updatedCallback(x509SVIDResponse);
                if (stop) {
                    return;
                }
            }

            status = reader->Finish();
        }
    };
} // spiffe namespace
