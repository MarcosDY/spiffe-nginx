#ifndef __CSPIFFE_H_INCLUDED__
#define __CSPIFFE_H_INCLUDED__

#include "workload.grpc.pb.h"
#include <grpc++/create_channel.h>

/**
 * Callback function to be called when new X509SVIDs have been received.
 */ 
typedef std::function<void(X509SVIDResponse)> X509SVIDsUpdatedCallback;

namespace spiffe {
    /**
     * WorkloadAPIClient class provides a client implementation of the
     * SPIFFE Workload API. The Start() method can be invoked to start fetching
     * SVIDs over a gRPC stream. The mechanism provided to get notifications of
     * new SVIDs as they are available is through a callback function, which is
     * called immediately after a new message in the stream has been received.
     * Start() blocks the current thread until there is a failure or Stop() is
     * called. It's caller's responsability to establish a strategy to retry
     * on failures.
     */
    class WorkloadAPIClient {
        public:
            WorkloadAPIClient(X509SVIDsUpdatedCallback updatedCallback);

            /**
            * Set the SPIFFE Workload Endpoint address
            */
            void SetSocketAddress(std::string socket_address);

            /**
             * Start fetching SVIDs. This will block to read repeatedly
             * messages from the stream of messages until there is a
             * failure or Stop() is called.
             */
            void FetchX509SVIDs();

            /**
             * Stop fetching X509 SVIDs.
             */
            void StopFetchingX509SVIDs();

            /**
             * Get the final status of the stream of X509 SVIDs.
             * The status is updated when the reader finishes reading
             * from the stream of messages coming from the server.
             */
            grpc::Status GetFetchX509SVIDsStatus();

        private:
            X509SVIDsUpdatedCallback updatedCallback;
            std::string socket_address;
            grpc::Status fetchX509SVIDsStatus;
            bool stopFetchingX509SVIDs;
    };
} // spiffe namespace
#endif // __CSPIFFE_H_INCLUDED__
