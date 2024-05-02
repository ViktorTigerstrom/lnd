package rpcwallet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/signcoordinator"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// ErrShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	// TODO: Should this say: lnd is shutting down?
	ErrShuttingDown = errors.New("server is shutting down")

	// ErrRequestType is returned when the request type by the watch-only
	// node has not been implemented by remote signer.
	ErrRequestType = errors.New("unimplemented request by watch-only node")
)

type RemoteSignerClient struct {
	*signcoordinator.SignCoordinator

	walletServer walletrpc.WalletKitServer

	signerServer signrpc.SignerServer

	// WatchOnlyRPCHost is the host:port of the watch-only lnd node.
	watchOnlyRPCHost string

	// MacaroonPath is the path to the macaroon file for the watch-only
	// node.
	macaroonPath string

	// TLSCertPath is the path to the TLS certificate for the watch-only
	// node.
	tlsCertPath string

	shouldRun bool

	stream walletrpc.WalletKit_SignCoordinatorStreamsClient

	connectionTimeout time.Duration

	retryTimeout time.Duration

	stopped int32 // To be used atomically.

	// doneReceiving is closed when either party terminates.
	doneReceiving chan struct{}

	quit chan struct{}

	wg sync.WaitGroup

	// wgMu ensures that we can't spawn a new Run goroutine after we've
	// stopped the remote signer client.
	wgMu sync.Mutex
}

// NewRemoteSignerClient creates a new instance of the remote signer client.
func NewRemoteSignerClient(subServers []lnrpc.SubServer,
	cfg *lncfg.RemoteSigner) (*RemoteSignerClient, error) {

	var (
		walletServer walletrpc.WalletKitServer
		signerServer signrpc.SignerServer
	)

	for _, subServer := range subServers {
		switch subServer.Name() {
		case walletrpc.SubServerName:
			walletServer = subServer.(walletrpc.WalletKitServer)
		case signrpc.SubServerName:
			signerServer = subServer.(signrpc.SignerServer)
		}
	}

	if walletServer == nil {
		return nil, fmt.Errorf("a walletrpc.WalletKitServer is " +
			"required to create a remote signer client")
	}

	if signerServer == nil {
		return nil, fmt.Errorf("a signrpc.SignerServer is required " +
			"to create a remote signer client")
	}

	return &RemoteSignerClient{
		walletServer:      walletServer,
		signerServer:      signerServer,
		watchOnlyRPCHost:  cfg.RPCHost,
		macaroonPath:      cfg.MacaroonPath,
		tlsCertPath:       cfg.TLSCertPath,
		connectionTimeout: cfg.InboundConnectionTimeout,
		shouldRun:         cfg.SignerType == lncfg.SignerClientType,
		doneReceiving:     make(chan struct{}),
		quit:              make(chan struct{}),
		retryTimeout:      time.Second * 1,
	}, nil
}

// Start starts the remote signer client. The function will continuously try to
// setup a connection to the configured watch-only node, and retry to connect if
// the connection fails until we Stop the remote signer client. If the
// cfg.SignerType isn't set to lncfg.SignerClientType, this function is a no-op.
func (r *RemoteSignerClient) Start() error {
	if !r.shouldRun {
		return nil
	}

	// We'll continuously try setup a connection to the watch-only node, and
	// retry to connect if the connection fails until we Stop the remote
	// signer client.
	go func() {
		for {
			err := r.run()
			log.Errorf("Remote signer client error: %v", err)

			select {
			case <-r.quit:
				return
			default:
				log.Debugf("Will retry to connect to "+
					"watch-only node in: %v",
					r.retryTimeout)

				select {
				case <-r.quit:
					return
				case <-time.After(r.retryTimeout):
				}
			}

			log.Infof("Retrying to connect to watch-only node")

			// Increase the retry timeout by 50% for every retry.
			r.retryTimeout =
				time.Duration(float64(r.retryTimeout) * 1.5)
		}
	}()

	return nil
}

// Stop stops the remote signer client.
func (r *RemoteSignerClient) Stop() error {
	if !atomic.CompareAndSwapInt32(&r.stopped, 0, 1) {
		return fmt.Errorf("remote signer client already stopped")
	}

	log.Info("3333333333 Remote signer client shutting down")

	// Ensure that no new Run goroutines can start when we've initiated
	// the stopping of the remote signer client.
	r.wgMu.Lock()
	defer r.wgMu.Unlock()

	close(r.quit)

	r.wg.Wait()

	log.Info("444444444 Remote signer client shut down")

	return nil
}

func (r *RemoteSignerClient) run() error {
	r.wgMu.Lock()

	select {
	case <-r.quit:
		r.wgMu.Unlock()
		return ErrShuttingDown
	default:
	}

	r.wg.Add(1)
	defer r.wg.Done()

	r.wgMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		stream  walletrpc.WalletKit_SignCoordinatorStreamsClient
		cleanup func()
		err     error
	)

	// Try to setup the connection to the watch-only node until it succeeds
	// or the context is canceled or the server is shutting down.
	log.Infof("Attempting to setup connection to watch-only node")

	stream, cleanup, err = r.setupStream(ctx)
	if err != nil {
		return err
	}

	r.stream = stream
	defer cleanup()

	err = r.handshake(ctx)
	if err != nil {
		return err
	}

	log.Infof("Completed setup connection to watch-only node")

	// Reset the retry timeout after a successful connection.
	r.retryTimeout = time.Second * 1

	return r.processSignRequests(ctx)
}

func (r *RemoteSignerClient) setupStream(streamCtx context.Context) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, func(), error) {

	conn, err := r.getClientConn()
	if err != nil {
		return nil, nil, err
	}

	cleanUp := func() {
		conn.Close()
	}

	walletKitClient := walletrpc.NewWalletKitClient(conn)

	stream, err := walletKitClient.SignCoordinatorStreams(streamCtx)
	if err != nil {
		cleanUp()

		return nil, nil, err
	}

	return stream, cleanUp, nil
}

func (r *RemoteSignerClient) getClientConn() (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(), r.connectionTimeout,
	)
	defer cancel()

	// Load the specified macaroon file.
	macBytes, err := os.ReadFile(r.macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("could not read macaroon file: %v", err)
	}

	mac := &macaroon.Macaroon{}

	err = mac.UnmarshalBinary(macBytes)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal macaroon: %v", err)
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create macaroon credential: %v", err)
	}

	tlsCreds, err := credentials.NewClientTLSFromFile(r.tlsCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("could not load TLS cert: %v", err)
	}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(macCred),
	}

	var (
		connDoneChan = make(chan *grpc.ClientConn, 1)
		errChan      = make(chan error, 1)
	)

	go func() {
		conn, err := grpc.DialContext(ctx, r.watchOnlyRPCHost, opts...)
		if err != nil {
			errChan <- fmt.Errorf("could not connect to "+
				"watch-only node: %v", err)
		}

		connDoneChan <- conn
	}()

	select {
	case conn := <-connDoneChan:
		return conn, nil

	case err := <-errChan:
		return nil, err

	case <-r.quit:
		return nil, ErrShuttingDown

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *RemoteSignerClient) handshake(streamCtx context.Context) error {
	var (
		regSentChan = make(chan struct{})
		regDoneChan = make(chan *walletrpc.SignCoordinatorRequest, 1)
		errChan     = make(chan error, 1)
	)

	regType := &walletrpc.SignCoordinatorResponse_SignerRegistration{
		SignerRegistration: true,
	}

	registrationMsg := &walletrpc.SignCoordinatorResponse{
		RequestId:        1, // Request ID is always 1 for registration.
		SignResponseType: regType,
	}

	// Send the registration message to the watch-only node.
	go func() {
		err := r.stream.Send(registrationMsg)
		if err != nil {
			errChan <- err
			return
		}

		close(regSentChan)
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("error sending registration complete "+
			" message to remote signer: %v", err)

	case <-streamCtx.Done():
		return streamCtx.Err()

	case <-r.quit:
		// TODO: Check if this error should be, LND is shutting down,
		// and not server.
		return ErrShuttingDown

	case <-regSentChan:
	}

	// After the registration message has been sent, the signer node will
	// respond with a message indicating that it has accepted the signer
	// registration request if the registration was successful.
	go func() {
		msg, err := r.stream.Recv()
		if err != nil {
			errChan <- err

			return
		}

		regDoneChan <- msg
	}()

	// Wait for the watch-only node to respond that it has accepted the
	// signer has registered.
	var regComplete *walletrpc.SignCoordinatorRequest
	select {
	case regComplete = <-regDoneChan:
		if regComplete.GetRequestId() != 1 {
			return fmt.Errorf("initial response request id must "+
				"be 1, but is: %d", regComplete.GetRequestId())
		}
		complete := regComplete.GetRegistrationComplete()
		if !complete {
			return fmt.Errorf("invalid initial watch-only node " +
				"registration complete message")
		}

	case err := <-errChan:
		return fmt.Errorf("watch-only node handshake error: %v", err)

	case <-r.quit:
		return ErrShuttingDown

	case <-streamCtx.Done():
		return streamCtx.Err()

	case <-time.After(r.connectionTimeout):
		return fmt.Errorf("watch-only node handshake timeout")
	}

	return nil
}

func (r *RemoteSignerClient) processSignRequests(ctx context.Context) error {
	var (
		reqChan = make(chan *walletrpc.SignCoordinatorRequest)
		errChan = make(chan error, 1)
	)

	go func() {
		req, err := r.stream.Recv()
		if err != nil {
			errChan <- fmt.Errorf("error receiving request from "+
				"watch-only node: %v", err)

			return
		}

		select {
		case reqChan <- req:
		case <-r.quit:
			return
		}
	}()

	for {
		select {
		case req := <-reqChan:
			err := r.handleRequest(ctx, req)
			if err != nil {
				return err
			}

		case <-r.quit:
			return ErrShuttingDown

		case <-ctx.Done():
			return ctx.Err()

		case err := <-errChan:
			return err

		}
	}
}

func (r *RemoteSignerClient) handleRequest(ctx context.Context,
	req *walletrpc.SignCoordinatorRequest) error {

	resp, err := r.process(ctx, req)
	if err != nil {
		errStr := "error processing sign request in remote " +
			"signer error: " + err.Error()

		log.Errorf(errStr)

		eType := &walletrpc.SignCoordinatorResponse_SignerError{
			SignerError: &walletrpc.SignerError{
				Error: errStr,
			},
		}

		resp = &walletrpc.SignCoordinatorResponse{
			RequestId:        req.GetRequestId(),
			SignResponseType: eType,
		}
	}

	err = r.sendResponse(ctx, resp)
	if err != nil {
		return fmt.Errorf("error sending response to "+
			"watch-only node: %v", err)
	}

	return nil
}

func (r *RemoteSignerClient) process(ctx context.Context,
	req *walletrpc.SignCoordinatorRequest) (
	*walletrpc.SignCoordinatorResponse, error) {

	requestId := req.GetRequestId()

	switch reqType := req.GetSignRequestType().(type) {
	case *walletrpc.SignCoordinatorRequest_SharedKeyRequest:
		resp, err := r.signerServer.DeriveSharedKey(
			ctx, reqType.SharedKeyRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_SharedKeyResponse{
			SharedKeyResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_SignMessageReq:
		resp, err := r.signerServer.SignMessage(
			ctx, reqType.SignMessageReq,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_SignMessageResp{
			SignMessageResp: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_MuSig2SessionRequest:
		resp, err := r.signerServer.MuSig2CreateSession(
			ctx, reqType.MuSig2SessionRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_MuSig2SessionResponse{
			MuSig2SessionResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_MuSig2RegisterNoncesRequest:
		resp, err := r.signerServer.MuSig2RegisterNonces(
			ctx, reqType.MuSig2RegisterNoncesRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_MuSig2RegisterNoncesResponse{
			MuSig2RegisterNoncesResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_MuSig2SignRequest:
		resp, err := r.signerServer.MuSig2Sign(
			ctx, reqType.MuSig2SignRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_MuSig2SignResponse{
			MuSig2SignResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_MuSig2CombineSigRequest:
		resp, err := r.signerServer.MuSig2CombineSig(
			ctx, reqType.MuSig2CombineSigRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_MuSig2CombineSigResponse{
			MuSig2CombineSigResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_MuSig2CleanupRequest:
		resp, err := r.signerServer.MuSig2Cleanup(
			ctx, reqType.MuSig2CleanupRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_MuSig2CleanupResponse{
			MuSig2CleanupResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	case *walletrpc.SignCoordinatorRequest_SignPsbtRequest:
		resp, err := r.walletServer.SignPsbt(
			ctx, reqType.SignPsbtRequest,
		)
		if err != nil {
			return nil, err
		}

		rType := &walletrpc.SignCoordinatorResponse_SignPsbtResponse{
			SignPsbtResponse: resp,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RequestId:        requestId,
			SignResponseType: rType,
		}

		return signResp, nil
	default:
		return nil, ErrRequestType
	}
}

func (r *RemoteSignerClient) sendResponse(
	ctx context.Context, resp *walletrpc.SignCoordinatorResponse) error {

	// We send the response in a goroutine to ensure we can return an error
	// if the send times out or the context is canceled. This is done to
	// ensure that this function won't block indefinitely.
	var (
		sendDone = make(chan struct{})
		errChan  = make(chan error, 1)
	)

	go func() {
		err := r.stream.Send(resp)
		if err != nil {
			errChan <- err
			return
		}

		close(sendDone)
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("send response to watch-only node error: %v",
			err)

	case <-time.After(r.connectionTimeout):
		return fmt.Errorf("send response to watch-only node timeout")

	case <-r.quit:
		return ErrShuttingDown

	case <-ctx.Done():
		return ctx.Err()

	case <-sendDone:
		return nil
	}
}
