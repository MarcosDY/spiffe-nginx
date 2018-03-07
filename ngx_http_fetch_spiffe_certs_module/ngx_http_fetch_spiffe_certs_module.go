package main

import (
	"C"
)
import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/spiffe/spire/proto/api/workload"
	"google.golang.org/grpc"
)

type fetchSpiffeCertsModule struct {
	workloadClient        workload.WorkloadClient
	workloadClientContext context.Context
	svidFilePath          string
	svidKeyFilePath       string
	svidBundleFilePath    string
}

// main is required for the file to compile to an object.
func main() {}

//export FetchSvids
func FetchSvids(sockAddr *C.char,
	svidFilePath *C.char,
	svidKeyFilePath *C.char,
	svidBundleFilePath *C.char) *C.char {

	workloadClient, ctx, _, err := createGrpcClient(C.GoString(sockAddr))
	if err != nil {
		log.Printf("error creating GRPC client: %v", err)
		return C.CString(err.Error())
	}

	m := &fetchSpiffeCertsModule{
		workloadClient:        workloadClient,
		workloadClientContext: ctx,
		svidFilePath:          C.GoString(svidFilePath),
		svidKeyFilePath:       C.GoString(svidKeyFilePath),
		svidBundleFilePath:    C.GoString(svidBundleFilePath)}

	_, err = m.dumpBundles()
	if err != nil {
		log.Printf("error dumping bundles: %v", err)
		return C.CString(err.Error())
	}
	go m.fetchLoop()
	return C.CString("")
}

func (m *fetchSpiffeCertsModule) fetchLoop() {
	for {
		// Fetch and dump certificates
		ttl, err := m.dumpBundles()
		if err != nil {
			log.Printf("error dumping bundles: %v", err)
			return
		}

		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			log.Printf("error finding process: %v", err)
			return
		}
		log.Printf("nginx PID is: %v", process.Pid)

		// Create timer for TTL/2
		timer := time.NewTimer(time.Second * time.Duration(ttl/2))

		// Wait for the timer signal
		log.Printf("Will wait for TTL/2 (%d seconds)\n", ttl/2)
		select {
		case <-timer.C:
			log.Print("Time is up! Will renew cert.\n")
			// Continue
		}
		err = process.Signal(syscall.SIGHUP)
		if err != nil {
			log.Printf("error sending signal: %v", err)
			return
		}
	}
}

func createGrpcClient(addr string) (workloadClient workload.WorkloadClient, ctx context.Context, cancel context.CancelFunc, err error) {
	ctx = context.Background()
	ctx, cancel = context.WithCancel(ctx)

	conn, err := grpc.Dial(addr,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		}))

	workloadClient = workload.NewWorkloadClient(conn)

	return workloadClient, ctx, cancel, err
}

func (m *fetchSpiffeCertsModule) dumpBundles() (ttl int32, err error) {
	bundles, err := m.workloadClient.FetchAllBundles(m.workloadClientContext, &workload.Empty{})
	if err != nil {
		return ttl, err
	}

	if len(bundles.Bundles) == 0 {
		return ttl, errors.New("fetched zero bundles")
	}

	ttl = bundles.Ttl
	log.Printf("TTL is: %v seconds\n", ttl)
	log.Printf("Bundles found: %d\n", len(bundles.Bundles))

	if len(bundles.Bundles) > 1 {
		log.Print("Only certificates from the first bundle will be written")
	}

	// There may be more than one bundle, but we are interested in the first one only
	bundle := bundles.Bundles[0]

	svidKeyFile := m.svidKeyFilePath
	svidFile := m.svidFilePath
	svidBundleFile := m.svidBundleFilePath

	svidPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bundle.SvidPrivateKey})

	svid := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle.Svid})

	log.Printf("Writing: %v\n", svidKeyFile)
	err = ioutil.WriteFile(svidKeyFile, append(svidPrivateKey, svid...), os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidKeyFile, err)
	}

	log.Printf("Writing: %v\n", svidFile)
	err = ioutil.WriteFile(svidFile, svid, os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidFile, err)
	}

	svidBundle := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: bundle.SvidBundle,
		})

	log.Printf("Writing: %v\n", svidBundleFile)
	err = ioutil.WriteFile(svidBundleFile, svidBundle, os.ModePerm)
	if err != nil {
		return ttl, fmt.Errorf("error writing file: %v\n%v", svidBundleFile, err)
	}

	return ttl, nil
}
