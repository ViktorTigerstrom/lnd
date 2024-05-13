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
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

var (
	// ErrShuttingDown indicates that the server is in the process of
	// gracefully exiting.
	ErrShuttingDown = errors.New("lnd is shutting down")

	// ErrRequestType is returned when the request type by the watch-only
	// node has not been implemented by remote signer.
	ErrRequestType = errors.New("unimplemented request by watch-only node")
)

const (
	// defaultRetryTimeout is the default timeout used when retrying to
	// connect to the watch-only node.
	defaultRetryTimeout = time.Second * 1

	// retryMultiplier is the multiplier used to increase the retry timeout
	// for every retry.
	retryMultiplier = 1.5

	// handshakeRequestID is the request ID that is reversed for the
	// handshake with the watch-only node.
	handshakeRequestID = uint64(1)

	signRpcName = "SignRPC"
)

// SignCoordinatorStreamFeeder is an interface that returns a newly created
// stream to the watch-only node. The stream is used to send and receive
// messages between the remote signer client and the watch-only node.
type SignCoordinatorStreamFeeder interface {
	// GetStream returns a new stream to the watch-only node. The function
	// also returns a cleanup function that should be called when the stream
	// is no longer needed.
	GetStream(streamCtx context.Context) (
		walletrpc.WalletKit_SignCoordinatorStreamsClient, func(), error)

	// Stop stops the stream feeder.
	Stop()
}

// StreamFeeder is an implementation of the SignCoordinatorStreamFeeder
// interface that creates a new stream to the watch-only node, by making an
// outbound GRPC connection to the watch-only node.
//
// Note: The StreamFeeder will only create a new stream if the configuration
// enables an outbound remote signer.
type StreamFeeder struct {
	// cfg is the remote signer configuration.
	cfg *lncfg.RemoteSigner

	// shouldConnect indicates whether the StreamFeeder should connect to
	// the watch-only node or not, i.e. if enabled by the configuration.
	shouldConnect bool

	// connectionTimeout is the timeout used when connecting to the
	// watch-only node.
	connectionTimeout time.Duration

	wg sync.WaitGroup

	quit chan struct{}
}

// NewStreamFeeder creates a new StreamFeeder instance.
func NewStreamFeeder(cfg *lncfg.RemoteSigner) *StreamFeeder {
	shouldConnect := true

	// If we lack the necessary configuration to connect to the watch-only
	// node, we should not connect.
	if cfg == nil || cfg.RPCHost == "" || cfg.MacaroonPath == "" ||
		cfg.TLSCertPath == "" || cfg.Timeout == 0 {

		shouldConnect = false
	}

	// If the signer type is doesn't signal that lnd should act an outbound
	// remote signer, we should not connect.
	if cfg.SignerType != lncfg.SignerClientType {
		shouldConnect = false
	}

	return &StreamFeeder{
		cfg:               cfg,
		shouldConnect:     shouldConnect,
		connectionTimeout: cfg.Timeout,
		quit:              make(chan struct{}),
	}
}

// Stop implements SignCoordinatorStreamFeeder.
//
// NOTE: This is part of the SignCoordinatorStreamFeeder interface.
func (s *StreamFeeder) Stop() {
	close(s.quit)

	s.wg.Wait()
}

// GetStream returns a new stream to the watch-only node, by making an
// outbound GRPC connection to the watch-only node. The function also returns a
// cleanup function that closes the connection, which should be called when the
// stream is no longer needed.
//
// NOTE: This is part of the SignCoordinatorStreamFeeder interface.
func (s *StreamFeeder) GetStream(streamCtx context.Context) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, func(), error) {

	// If the configuration doesn't enable the outbound remote signer, we
	// should not connect.
	if !s.shouldConnect {
		return nil, nil, fmt.Errorf("config not correctly set to be " +
			"able to connect to watch-only node")
	}

	s.wg.Add(1)
	defer s.wg.Done()

	// Create a new outbound GRPC connection to the watch-only node.
	conn, err := s.getClientConn()
	if err != nil {
		return nil, nil, err
	}

	cleanUp := func() {
		conn.Close()
	}

	// Wrap the connection in a WalletKitClient.
	walletKitClient := walletrpc.NewWalletKitClient(conn)

	// Create a new stream to the watch-only node.
	stream, err := walletKitClient.SignCoordinatorStreams(streamCtx)
	if err != nil {
		cleanUp()

		return nil, nil, err
	}

	return stream, cleanUp, nil
}

// getClientConn creates a new outbound GRPC connection to the watch-only node.
func (s *StreamFeeder) getClientConn() (*grpc.ClientConn, error) {
	// If we fail to connect to the watch-only node within the
	// connectionTimeout we should return an error.
	ctx, cancel := context.WithTimeout(
		context.Background(), s.connectionTimeout,
	)
	defer cancel()

	// Load the specified macaroon file for the watch-only node.
	macBytes, err := os.ReadFile(s.cfg.MacaroonPath)
	if err != nil {
		return nil, fmt.Errorf("could not read macaroon file: %w", err)
	}

	mac := &macaroon.Macaroon{}

	err = mac.UnmarshalBinary(macBytes)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal macaroon: %w", err)
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf(
			"could not create macaroon credential: %w", err)
	}

	// Load the specified TLS cert for the watch-only node.
	tlsCreds, err := credentials.NewClientTLSFromFile(s.cfg.TLSCertPath, "")
	if err != nil {
		return nil, fmt.Errorf("could not load TLS cert: %w", err)
	}

	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(macCred),
	}

	var (
		// A channel to signal when has successfully been created.
		connDoneChan = make(chan *grpc.ClientConn, 1)
		errChan      = make(chan error, 1)
	)

	// Now let's try to connect to the watch-only node. We'll do this in a
	// goroutine to ensure we can exit if the quit channel is closed. If the
	// quit channel is closed, the context will also be canceled, hence
	// stopping the goroutine.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		conn, err := grpc.DialContext(ctx, s.cfg.RPCHost, opts...)
		if err != nil {
			errChan <- fmt.Errorf("could not connect to "+
				"watch-only node: %v", err)
		}

		// Only send the connection if we haven't been signaled to
		// stop the goroutine.
		select {
		case <-s.quit:
			return
		case <-ctx.Done():
			return
		default:
			connDoneChan <- conn
		}
	}()

	select {
	case conn := <-connDoneChan:
		return conn, nil

	case err := <-errChan:
		return nil, err

	case <-s.quit:
		return nil, ErrShuttingDown

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// A compile time assertion to ensure StreamFeeder meets the
// SignCoordinatorStreamFeeder interface.
var _ SignCoordinatorStreamFeeder = (*StreamFeeder)(nil)

// RemoteSignerClient is a client which will process and respond to sign
// requests which are sent over a stream between the node and a watch-only node.
//
// Note: The client will only start fully if the passed configuration enables an
// outbound remote signer.
type RemoteSignerClient struct {
	// walletServer is the WalletKitServer that the remote signer client
	// will use to process walletrpc requests.
	walletServer walletrpc.WalletKitServer

	// signerServer is the SignerServer that the remote signer client will
	// use to process signrpc requests.
	signerServer signrpc.SignerServer

	// streamFeeder is the stream feeder that will feed the remote signer
	// client a stream to the watch-only node.
	streamFeeder SignCoordinatorStreamFeeder

	// stream is the stream to the watch-only node.
	stream walletrpc.WalletKit_SignCoordinatorStreamsClient

	// shouldRun indicates whether the remote signer client should start
	// fully or not.
	shouldRun bool

	// requestTimeout is the timeout used when sending responses to the
	// watch-only node.
	requestTimeout time.Duration

	// retryTimeout is the backoff timeout used when retrying to set up a
	// connection to the watch-only node, if the previous connection/attempt
	// failed.
	retryTimeout time.Duration

	stopped int32 // To be used atomically.

	quit chan struct{}

	wg sync.WaitGroup

	// wgMu ensures that we can't spawn a new Run goroutine after we've
	// stopped the remote signer client.
	wgMu sync.Mutex
}

// NewRemoteSignerClient creates a new instance of the remote signer client.
// The passed subServers need to contain a walletrpc.WalletKitServer and a
// signrpc.SignerServer, or an error will be returned.
// Note that the client will only start fully if the passed configuration
// enables an outbound remote signer.
func NewRemoteSignerClient(subServers []lnrpc.SubServer,
	streamFeeder SignCoordinatorStreamFeeder,
	cfg *lncfg.RemoteSigner) (*RemoteSignerClient, error) {

	var (
		walletServer walletrpc.WalletKitServer
		signerServer signrpc.SignerServer
	)

	for _, subServer := range subServers {
		switch subServer.Name() {
		case walletrpc.SubServerName:
			walletServer = subServer.(walletrpc.WalletKitServer)
		case signRpcName:
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

	shouldRun := cfg != nil && cfg.SignerType == lncfg.SignerClientType &&
		cfg.RequestTimeout != 0

	return &RemoteSignerClient{
		walletServer:   walletServer,
		signerServer:   signerServer,
		streamFeeder:   streamFeeder,
		requestTimeout: cfg.RequestTimeout,
		shouldRun:      shouldRun,
		quit:           make(chan struct{}),
		retryTimeout:   defaultRetryTimeout,
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

	r.wg.Add(1)

	// We'll continuously try setup a connection to the watch-only node, and
	// retry to connect if the connection fails until we Stop the remote
	// signer client.
	go func() {
		defer r.wg.Done()

		for {
			err := r.run()
			log.Errorf("Remote signer client error: %v", err)

			select {
			case <-r.quit:
				return
			default:
				log.Infof("Will retry to connect to "+
					"watch-only node in: %v",
					r.retryTimeout)

				// Backoff before retrying to connect to the
				// watch-only node.
				select {
				case <-r.quit:
					return
				case <-time.After(r.retryTimeout):
				}
			}

			log.Infof("Retrying to connect to watch-only node")

			// Increase the retry timeout by 50% for every retry.
			r.retryTimeout = time.Duration(float64(r.retryTimeout) *
				retryMultiplier)
		}
	}()

	return nil
}

// Stop stops the remote signer client.
func (r *RemoteSignerClient) Stop() error {
	if !atomic.CompareAndSwapInt32(&r.stopped, 0, 1) {
		return fmt.Errorf("remote signer client is already shut down")
	}

	log.Info("Remote signer client shutting down")

	// Ensure that no new Run goroutines can start when we've initiated
	// the stopping of the remote signer client.
	r.wgMu.Lock()
	defer r.wgMu.Unlock()

	if r.streamFeeder != nil {
		r.streamFeeder.Stop()
	}

	close(r.quit)

	r.wg.Wait()

	log.Info("Remote signer client shut down")

	return nil
}

// run creates a new stream to the watch-only node, and starts processing and
// responding to the sign requests that are sent over the stream. The function
// will continuously run until the remote signer client is either stopped or
// the stream errors.
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

	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Infof("Attempting to setup connection to watch-only node")

	// Try to get a new stream to the watch-only node.
	stream, streamCleanUp, err := r.streamFeeder.GetStream(streamCtx)
	if err != nil {
		return err
	}

	r.stream = stream
	defer streamCleanUp()

	// Once the stream has been created, we'll need to perform the handshake
	// process with the watch-only node, before it will start sending us
	// requests.
	err = r.handshake(streamCtx)
	if err != nil {
		return err
	}

	log.Infof("Completed setup connection to watch-only node")

	// Reset the retry timeout after a successful connection.
	r.retryTimeout = defaultRetryTimeout

	return r.processSignRequests(streamCtx)
}

// handshake performs the handshake process with the watch-only node. As we are
// the initiator of the stream, we need to send the first message over the
// stream. The watch-only node will only proceed to sending us requests after
// the handshake has been completed.
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
		RefRequestId:     1, // Request ID is always 1 for registration.
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

	case <-time.After(r.requestTimeout):
		return fmt.Errorf("watch-only node handshake timeout")
	}

	return nil
}

// processSignRequests processes and responds to the sign requests that are
// sent over the stream. The function will continuously run until the remote
// signer client is either stopped or the stream errors.
func (r *RemoteSignerClient) processSignRequests(streamCtx context.Context) error {
	var (
		reqChan = make(chan *walletrpc.SignCoordinatorRequest)
		errChan = make(chan error, 1)
	)

	// We run the receive loop in a goroutine to ensure we can stop if the
	// remote signer client is shutting down (i.e. the quit channel is
	// closed). Closing the quit channel will make the processSignRequests
	// function return, which will cancel the stream context, which in turn
	// will stop the receive goroutine.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		for {
			req, err := r.stream.Recv()
			if err != nil {
				errChan <- fmt.Errorf("error receiving "+
					"request from watch-only node: %v", err)

				return
			}

			select {
			case <-r.quit:
				return

			case reqChan <- req:
			}
		}
	}()

	for {
		log.Tracef("Waiting for a request from the watch-only node")

		select {
		case req := <-reqChan:
			// Process the received request.
			err := r.handleRequest(streamCtx, req)
			if err != nil {
				return err
			}

		case <-r.quit:
			return ErrShuttingDown

		case <-streamCtx.Done():
			return streamCtx.Err()

		case err := <-errChan:
			return err
		}
	}
}

// handleRequest processes the received request from the watch-only node, and
// sends the corresponding response back.
func (r *RemoteSignerClient) handleRequest(streamCtx context.Context,
	req *walletrpc.SignCoordinatorRequest) error {

	log.Debugf("Processing a request from watch-only node of type: %T",
		req.GetSignRequestType())

	// Process the request.
	resp, err := r.process(streamCtx, req)
	if err != nil {
		errStr := "error processing the request in the remote " +
			"signer: " + err.Error()

		log.Errorf(errStr)

		// If we fail to process the request, we will send a SignerError
		// back to the watch-only node, indicating the nature of the
		// error.
		eType := &walletrpc.SignCoordinatorResponse_SignerError{
			SignerError: &walletrpc.SignerError{
				Error: errStr,
			},
		}

		resp = &walletrpc.SignCoordinatorResponse{
			RefRequestId:     req.GetRequestId(),
			SignResponseType: eType,
		}
	}

	// Send the response back to the watch-only node.
	err = r.sendResponse(streamCtx, resp)
	if err != nil {
		return fmt.Errorf("error sending response to watch-only "+
			"node: %w", err)
	}

	log.Tracef("Sent the following response to watch-only node: %v", resp)

	return nil
}

// process sends the passed request on to the appropriate server for processing
// it, and returns the response.
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
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
			RefRequestId:     requestId,
			SignResponseType: rType,
		}

		return signResp, nil

	case *walletrpc.SignCoordinatorRequest_Ping:
		// If the received request is a ping, we don't need to pass the
		// request on to a server, but can respond with a ping directly.
		rType := &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		}

		signResp := &walletrpc.SignCoordinatorResponse{
			RefRequestId:     requestId,
			SignResponseType: rType,
		}

		return signResp, nil

	default:
		return nil, ErrRequestType
	}
}

// sendResponse sends the passed response back to the watch-only node over the
// stream.
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
		r.wg.Add(1)
		defer r.wg.Done()

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

	case <-time.After(r.requestTimeout):
		return fmt.Errorf("send response to watch-only node timeout")

	case <-r.quit:
		return ErrShuttingDown

	case <-ctx.Done():
		return ctx.Err()

	case <-sendDone:
		return nil
	}
}
