#ifndef __CSPIFFE_H_INCLUDED__
#define __CSPIFFE_H_INCLUDED__

#include "workload.grpc.pb.h"
#include <grpc++/create_channel.h>

typedef std::function<void(X509SVIDResponse)> SVIDsUpdatedCallback;

namespace spiffe {
    class WorkloadAPIClient {
        public:
            WorkloadAPIClient(const std::string socket_address, SVIDsUpdatedCallback updatedCallback);
            void Start();
            void Stop();
            grpc::Status GetStatus();

        private:
            SVIDsUpdatedCallback updatedCallback;
            std::string socket_address;
            grpc::Status status;
            bool stop;

            void fetchSVIDs();
    };
} // spiffe namespace
#endif // __CSPIFFE_H_INCLUDED__
