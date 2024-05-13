package rpcwallet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"google.golang.org/grpc"
)

var (
	// ErrRequestTimeout is the error that's returned if we time out while
	// waiting for a response from the remote signer.
	ErrRequestTimeout = errors.New(
		"remote signer response timeout reached")

	// ErrConnectTimeout is the error that's returned if we time out while
	// waiting the remote signer to connect.
	ErrConnectTimeout = errors.New(
		"timed out when waiting for remote signer to connect ")

	// ErrMultipleConnections is the error that's returned if more than one
	// remote signer attempts to be connected at the same time.
	ErrMultipleConnections = errors.New(
		"only one remote signer can be connected")

	// ErrNotConnected is the error that's returned if the remote signer
	// closes the stream, or we error when receiving over the stream.
	ErrNotConnected = errors.New("the remote signer is no longer connected")

	// ErrUnexpectedResponse is the error that's returned if the response
	// with the expected message id from the remote signer is of an
	// unexpected type.
	ErrUnexpectedResponse = errors.New("unexpected response type")
)

// SignCoordinator is an implementation of the signrpc.SignerClient and the
// walletrpc.WalletKitClient interfaces that passes on all requests to a remote
// signer. It is used by the watch-only wallet to delegate any signing or ECDH
// operations to a remote node over a
// walletrpc.WalletKit_SignCoordinatorStreamsServer stream. The stream is set up
// by the remote signer when it connects to the watch-only wallet, which should
// execute the Run method.
type SignCoordinator struct {
	// stream is a bi-directional stream that is between us and the remote
	// signer.
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer

	// responses is a map of request ids to response channels. This map
	// should be populated with a response channel for each request that has
	// been sent to the remote signer. The response channel should be
	// inserted into the map before the request is sent.
	// Any response received over the stream that does not have an
	// associated response channel in this map is ignored.
	// The response channel should be removed from the map when the response
	// has been received and processed.
	responses map[uint64]chan *walletrpc.SignCoordinatorResponse

	// receiveErrChan is used to signal that the stream with the remote
	// signer has errored, and we can no longer processing responses.
	receiveErrChan chan error

	// doneReceiving is closed when either party terminates, and signals to
	// any pending requests that we'll no longer process the response for
	// that request.
	doneReceiving chan struct{}

	// quit is closed when lnd is shutting down.
	quit chan struct{}

	// clientConnected is sent over when the remote signer connects.
	clientConnected chan struct{}

	// nextRequestID keeps track of the is the next request id that should
	// be used when sending a request to the remote signer.
	nextRequestID uint64

	// requestTimeout is the maximum time we will wait for a response from
	// the remote signer.
	requestTimeout time.Duration

	// connectionTimeout is the maximum time we will wait for the remote
	// signer to connect.
	connectionTimeout time.Duration

	mu sync.Mutex

	wg sync.WaitGroup
}

// A compile time assertion to ensure SignCoordinator meets the
// signrpc.SignerClient interface.
var _ signrpc.SignerClient = (*SignCoordinator)(nil)

// A compile time assertion to ensure SignCoordinator meets the
// walletrpc.WalletKitClient interface.
var _ walletrpc.WalletKitClient = (*SignCoordinator)(nil)

// NewSignCoordinator creates a new instance of the SignCoordinator.
func NewSignCoordinator(requestTimeout time.Duration,
	connectionTimeout time.Duration) *SignCoordinator {

	respsMap := make(map[uint64]chan *walletrpc.SignCoordinatorResponse)

	// requestID 1 is reserved for the initial handshake by the remote
	// signer.
	nextRequestID := handshakeRequestID + 1

	return &SignCoordinator{
		responses:         respsMap,
		receiveErrChan:    make(chan error),
		doneReceiving:     make(chan struct{}),
		clientConnected:   make(chan struct{}),
		quit:              make(chan struct{}),
		nextRequestID:     nextRequestID,
		requestTimeout:    requestTimeout,
		connectionTimeout: connectionTimeout,
	}
}

// Run starts the SignCoordinator and blocks until the remote signer
// disconnects, the SignCoordinator is shut down, or an error occurs.
func (s *SignCoordinator) Run(
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error {

	s.mu.Lock()

	select {
	case <-s.quit:
		s.mu.Unlock()
		return ErrShuttingDown

	case <-s.doneReceiving:
		s.mu.Unlock()
		return ErrNotConnected

	default:
	}

	// If we already have a stream, we error out as we can only have one
	// connection, throughout the lifetime of the SignCoordinator.
	if s.stream != nil {
		s.mu.Unlock()
		return ErrMultipleConnections
	}

	s.stream = stream

	s.mu.Unlock()

	// The handshake must be completed before we can start sending requests
	// to the remote signer.
	err := s.Handshake(stream)
	if err != nil {
		return err
	}

	log.Infof("Remote signer connected")
	close(s.clientConnected)

	// Now lets start the main receiving loop, which will receive all
	// responses to our requests from the remote signer!
	// We start the receiving loop in a goroutine, to ensure that this
	// function exits if the SignCoordinator is shut down (i.e. the s.quit
	// channel is closed). Returning from this function will cause the
	// stream to be closed, which in turn will cause the receiving loop to
	// exit.
	go s.StartReceiving()

	select {
	case err := <-s.receiveErrChan:
		return err

	case <-s.quit:
		return ErrShuttingDown

	case <-s.doneReceiving:
		return ErrNotConnected
	}
}

// Stop shuts down the SignCoordinator and waits until the main receiving loop
// has exited and all pending requests have been terminated.
func (s *SignCoordinator) Stop() {
	log.Infof("Stopping Sign Coordinator")
	defer log.Debugf("Sign coordinator stopped")

	s.mu.Lock()

	close(s.quit)

	s.mu.Unlock()

	s.wg.Wait()
}

// Handshake performs the initial handshake with the remote signer. This must
// be done before any other requests are sent to the remote signer.
func (s *SignCoordinator) Handshake(
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	s.wg.Add(1)
	defer s.wg.Done()

	var (
		registerChan     = make(chan *walletrpc.SignCoordinatorResponse)
		registerDoneChan = make(chan struct{})
		errChan          = make(chan error, 1)
	)

	// Create a context with a timeout and using the context from the stream
	// as the parent context. This ensures that we'll exit if either the
	// stream is closed by the remote signer or if we time out.
	ctxc, cancel := context.WithTimeout(
		stream.Context(), s.requestTimeout,
	)
	defer cancel()

	// Read the first message in a goroutine because the Recv method blocks
	// until the message arrives.
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			errChan <- err

			return
		}

		registerChan <- msg
	}()

	// Wait for the initial message to arrive or time out if it takes too
	// long. The initial message must be a registration message from the
	// remote signer.
	var registrationMsg *walletrpc.SignCoordinatorResponse
	select {
	case registrationMsg = <-registerChan:
		if registrationMsg.GetRefRequestId() != handshakeRequestID {
			return fmt.Errorf("initial request id must be %d, "+
				"but is: %d", handshakeRequestID,
				registrationMsg.GetRefRequestId())
		}
		register := registrationMsg.GetSignerRegistration()
		if !register {
			return fmt.Errorf("invalid initial remote signer " +
				"registration message")
		}

	case err := <-errChan:
		return fmt.Errorf("error receiving initial remote signer "+
			"registration message: %v", err)

	case <-s.quit:
		return ErrShuttingDown

	case <-ctxc.Done():
		return ctxc.Err()
	}

	// Send a message to the client to indicate that the registration has
	// successfully completed.
	req := &walletrpc.SignCoordinatorRequest_RegistrationComplete{
		RegistrationComplete: true,
	}

	regCompleteMsg := &walletrpc.SignCoordinatorRequest{
		RequestId:       handshakeRequestID,
		SignRequestType: req,
	}

	// Send the message in a goroutine because the Send method blocks until
	// the message is read by the client.
	go func() {
		err := stream.Send(regCompleteMsg)
		if err != nil {
			errChan <- err
			return
		}

		close(registerDoneChan)
	}()

	select {
	case err := <-errChan:
		return fmt.Errorf("error sending registration complete "+
			" message to remote signer: %v", err)

	case <-ctxc.Done():
		return ctxc.Err()

	case <-s.quit:
		return ErrShuttingDown

	case <-registerDoneChan:
	}

	return nil
}

// StartReceiving is the receive main loop that receives responses from the
// remote signer. Responses must have a RequestID that corresponds to requests
// which are waiting for a response, otherwise the response is ignored.
func (s *SignCoordinator) StartReceiving() {
	s.wg.Add(1)
	defer s.wg.Done()

	// Signals to any ongoing requests that the remote signer is no longer
	// connected.
	defer close(s.doneReceiving)

	for {
		resp, err := s.stream.Recv()
		if err != nil {
			// We grab the lock here to ensure that the quit channel
			// cannot be closed after we've entered the default case
			// below, but before sending the error over the error
			// channel. If that were to happen, the main Run method
			// would not be able to receive the error sent over the
			// error channel as it'd exit on the closing of the quit
			// channel. That would cause the error sending to hang,
			// and in turn cause the deferred s.wg.Done() to never
			// be called, causing a deadlock.
			s.mu.Lock()
			defer s.mu.Unlock()

			select {
			case <-s.quit:
				// If we've already shut down, the main Run
				// method will not be able to receive any error
				// sent over the error channel. So we just
				// return.
				return
			default:
				// Send the error over the error channel, so
				// that the main Run method can return the error
				s.receiveErrChan <- err
			}

			return
		}

		s.mu.Lock()

		if respChan, ok := s.responses[resp.GetRefRequestId()]; ok {
			respChan <- resp

			close(respChan)
		}
		// If there's no response channel, the thread waiting for the
		// response has most likely timed out. We therefore ignore the
		// response. The other scenario where we don't have a response
		// channel would be if we received a response for a request that
		// we didn't send. This should never happen, but if it does, we
		// ignore the response.

		s.mu.Unlock()

		select {
		case <-s.quit:
			return
		default:
		}
	}
}

// WaitUntilConnected waits until the remote signer has connected. If the remote
// signer does not connect within the configured connection timeout, an error is
// returned.
func (s *SignCoordinator) WaitUntilConnected() error {
	return s.waitUntilConnectedWithTimeout(s.connectionTimeout)
}

// waitUntilConnectedWithTimeout waits until the remote signer has connected. If
// the remote signer does not connect within the given timeout, an error is
// returned.
func (s *SignCoordinator) waitUntilConnectedWithTimeout(
	timeout time.Duration) error {
	select {
	case <-s.clientConnected:
		return nil

	case <-s.quit:
		return ErrShuttingDown

	case <-time.After(timeout):
		return ErrConnectTimeout

	case <-s.doneReceiving:
		return ErrNotConnected
	}
}

// getNextRequestID returns the next request id that should be used when sending
// a request to the remote signer.
func (s *SignCoordinator) getNextRequestID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextRequestID := s.nextRequestID

	s.nextRequestID++

	return nextRequestID
}

// createResponseChannel creates a response channel for the given request id and
// inserts it into the responses map. The function returns a clean up function
// which removes the channel from the responses map, and the caller must ensure
// that this clean up function is executed once the thread that's waiting for
// the response is done.
func (s *SignCoordinator) createResponseChannel(requestID uint64) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	respChan := make(chan *walletrpc.SignCoordinatorResponse, 1)

	// Insert the response channel into the map.
	s.responses[requestID] = respChan

	// Create a cleanup function that will delete the response channel.
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()

		select {
		case <-respChan:
			// If we have timed out, there could be a very unlikely
			// scenario, were we did receive a response before we
			// managed to grab the lock in the cleanup func.
			// In that case we'll just ignore the response.
			// We should still clean up the response channel though.
		default:
		}

		delete(s.responses, requestID)
	}
}

// getResponse waits for a response with the given request id, and returns the
// response if it is received. If the corresponding response from the remote
// signer is a SignerError, the error message is returned. If the response is
// not received within the given timeout, an error is returned.
//
// Note: Before calling this function, the caller must have created a response
// channel for the request id.
func (s *SignCoordinator) getResponse(requestID uint64,
	timeout time.Duration) (*walletrpc.SignCoordinatorResponse, error) {

	s.mu.Lock()

	// Verify that we have a response channel for the request id.
	if _, ok := s.responses[requestID]; !ok {
		// It should be impossible to reach this case, as we create the
		// response channel before sending the request.
		s.mu.Unlock()

		return nil, fmt.Errorf("no response channel found for request "+
			"id %d", requestID)
	}

	// Grab the response channel for the request id.
	respChan := s.responses[requestID]

	s.mu.Unlock()

	// Wait for the response to arrive.
	select {
	case resp := <-respChan:
		// If the response is an error, we return the error message.
		if errorResp, ok := resp.GetSignResponseType().(*walletrpc.SignCoordinatorResponse_SignerError); ok {
			errStr := errorResp.SignerError.GetError()

			log.Debugf("Received an error response from remote "+
				"signer for request ID %d. Error: %v",
				requestID, errStr)

			return nil, errors.New(errStr)
		}

		log.Debugf("Received remote signer response for request ID %d",
			requestID)

		return resp, nil

	case <-s.doneReceiving:
		log.Debugf("Stopped waiting for remote signer response for "+
			"request ID %d as the stream has been closed",
			requestID)

		return nil, ErrNotConnected

	case <-s.quit:
		log.Debugf("Stopped waiting for remote signer response for "+
			"request ID %d as we're shutting down", requestID)

		return nil, ErrShuttingDown

	case <-time.After(timeout):
		log.Debugf("Remote signer response timed out for request ID %d",
			requestID)

		return nil, ErrRequestTimeout
	}
}

// Ping sends a ping request to the remote signer and waits for a pong response.
func (s *SignCoordinator) Ping(timeout time.Duration) (bool, error) {
	s.wg.Add(1)
	defer s.wg.Done()

	startTime := time.Now()

	err := s.waitUntilConnectedWithTimeout(timeout)
	if err != nil {
		return false, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_Ping{
		Ping: true,
	}

	cleanUpChannel := s.createResponseChannel(requestID)
	defer cleanUpChannel()

	log.Debugf("Sending a Ping request to the remote signer with request "+
		"ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return false, err
	}

	newTimeout := timeout - time.Since(startTime)

	if time.Since(startTime) > timeout {
		return false, ErrRequestTimeout
	}

	resp, err := s.getResponse(requestID, newTimeout)
	if err != nil {
		return false, err
	}

	signResp := resp.GetPong()
	if !signResp {
		return false, ErrUnexpectedResponse
	}

	return signResp, nil
}

// DeriveSharedKey sends a SharedKeyRequest request to the remote signer and
// waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) DeriveSharedKey(_ context.Context,
	in *signrpc.SharedKeyRequest,
	_ ...grpc.CallOption) (*signrpc.SharedKeyResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SharedKeyRequest{
		SharedKeyRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.SharedKeyRequest request to the remote "+
		"signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetSharedKeyResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a MuSig2CleanupRequest request to the remote signer and
// waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2Cleanup(_ context.Context,
	in *signrpc.MuSig2CleanupRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CleanupResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2CleanupRequest{
		MuSig2CleanupRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.MuSig2CleanupRequest request to the "+
		"remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetMuSig2CleanupResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a MuSig2CombineSigRequest request to the remote signer
// and waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2CombineSig(_ context.Context,
	in *signrpc.MuSig2CombineSigRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CombineSigResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2CombineSigRequest{
		MuSig2CombineSigRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.MuSig2CombineSigRequest request to the "+
		"remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetMuSig2CombineSigResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a MuSig2SessionRequest request to the remote signer and
// waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2CreateSession(_ context.Context,
	in *signrpc.MuSig2SessionRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SessionResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2SessionRequest{
		MuSig2SessionRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.MuSig2SessionRequest request to the "+
		"remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetMuSig2SessionResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a MuSig2RegisterNoncesRequest request to the remote
// signer and waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2RegisterNonces(_ context.Context,
	in *signrpc.MuSig2RegisterNoncesRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2RegisterNoncesResponse,
	error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2RegisterNoncesRequest{
		MuSig2RegisterNoncesRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.MuSig2RegisterNoncesRequest request to "+
		"the remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetMuSig2RegisterNoncesResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a MuSig2SignRequest request to the remote signer and
// waits for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2Sign(_ context.Context,
	in *signrpc.MuSig2SignRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SignResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2SignRequest{
		MuSig2SignRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.MuSig2SignRequest request to the "+
		"remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	rpcResp := resp.GetMuSig2SignResponse()
	if rpcResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return rpcResp, nil
}

// DeriveSharedKey sends a SignMessageReq request to the remote signer and waits
// for the corresponding response.
//
// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) SignMessage(_ context.Context,
	in *signrpc.SignMessageReq,
	_ ...grpc.CallOption) (*signrpc.SignMessageResp, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SignMessageReq{
		SignMessageReq: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a signrpc.SignMessageReq request to the remote "+
		"signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	signResp := resp.GetSignMessageResp()
	if signResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return signResp, nil
}

// DeriveSharedKey sends a SignPsbtRequest request to the remote signer and
// waits for the corresponding response.
//
// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) SignPsbt(_ context.Context,
	in *walletrpc.SignPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.SignPsbtResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SignPsbtRequest{
		SignPsbtRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

	log.Debugf("Sending a walletrpc.SignPsbtRequest request to the "+
		"remote signer with request ID %d", requestID)

	err = s.stream.Send(&walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: req,
	})
	if err != nil {
		return nil, err
	}

	resp, err := s.getResponse(requestID, s.requestTimeout)
	if err != nil {
		return nil, err
	}

	signResp := resp.GetSignPsbtResponse()
	if signResp == nil {
		return nil, ErrUnexpectedResponse
	}

	return signResp, nil
}

// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) ComputeInputScript(_ context.Context,
	_ *signrpc.SignReq,
	_ ...grpc.CallOption) (*signrpc.InputScriptResp, error) {

	panic("unimplemented")
}

// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) MuSig2CombineKeys(_ context.Context,
	_ *signrpc.MuSig2CombineKeysRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CombineKeysResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) SignOutputRaw(_ context.Context,
	_ *signrpc.SignReq,
	_ ...grpc.CallOption) (*signrpc.SignResp, error) {

	panic("unimplemented")
}

// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) VerifyMessage(_ context.Context,
	_ *signrpc.VerifyMessageReq,
	_ ...grpc.CallOption) (*signrpc.VerifyMessageResp, error) {

	panic("unimplemented")
}

// NOTE: This is part of the signrpc.SignerClient interface.
func (s *SignCoordinator) DeriveKey(_ context.Context,
	_ *signrpc.KeyLocator,
	_ ...grpc.CallOption) (*signrpc.KeyDescriptor, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ListUnspent(_ context.Context,
	_ *walletrpc.ListUnspentRequest,
	_ ...grpc.CallOption) (*walletrpc.ListUnspentResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) LeaseOutput(_ context.Context,
	_ *walletrpc.LeaseOutputRequest,
	_ ...grpc.CallOption) (*walletrpc.LeaseOutputResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ReleaseOutput(_ context.Context,
	_ *walletrpc.ReleaseOutputRequest,
	_ ...grpc.CallOption) (*walletrpc.ReleaseOutputResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ListLeases(_ context.Context,
	_ *walletrpc.ListLeasesRequest,
	_ ...grpc.CallOption) (*walletrpc.ListLeasesResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) DeriveNextKey(_ context.Context,
	_ *walletrpc.KeyReq,
	_ ...grpc.CallOption) (*signrpc.KeyDescriptor, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) NextAddr(_ context.Context,
	_ *walletrpc.AddrRequest,
	_ ...grpc.CallOption) (*walletrpc.AddrResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) GetTransaction(_ context.Context,
	_ *walletrpc.GetTransactionRequest,
	_ ...grpc.CallOption) (*lnrpc.Transaction, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ListAccounts(_ context.Context,
	_ *walletrpc.ListAccountsRequest,
	_ ...grpc.CallOption) (*walletrpc.ListAccountsResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) RequiredReserve(_ context.Context,
	_ *walletrpc.RequiredReserveRequest,
	_ ...grpc.CallOption) (*walletrpc.RequiredReserveResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ListAddresses(_ context.Context,
	_ *walletrpc.ListAddressesRequest,
	_ ...grpc.CallOption) (*walletrpc.ListAddressesResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) SignMessageWithAddr(_ context.Context,
	_ *walletrpc.SignMessageWithAddrRequest,
	_ ...grpc.CallOption) (*walletrpc.SignMessageWithAddrResponse,
	error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) VerifyMessageWithAddr(_ context.Context,
	_ *walletrpc.VerifyMessageWithAddrRequest,
	_ ...grpc.CallOption) (*walletrpc.VerifyMessageWithAddrResponse,
	error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ImportAccount(_ context.Context,
	_ *walletrpc.ImportAccountRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportAccountResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ImportPublicKey(_ context.Context,
	_ *walletrpc.ImportPublicKeyRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportPublicKeyResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ImportTapscript(_ context.Context,
	_ *walletrpc.ImportTapscriptRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportTapscriptResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) PublishTransaction(_ context.Context,
	_ *walletrpc.Transaction,
	_ ...grpc.CallOption) (*walletrpc.PublishResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) RemoveTransaction(_ context.Context,
	_ *walletrpc.GetTransactionRequest,
	_ ...grpc.CallOption) (*walletrpc.RemoveTransactionResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) SendOutputs(_ context.Context,
	_ *walletrpc.SendOutputsRequest,
	_ ...grpc.CallOption) (*walletrpc.SendOutputsResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) EstimateFee(_ context.Context,
	_ *walletrpc.EstimateFeeRequest,
	_ ...grpc.CallOption) (*walletrpc.EstimateFeeResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) PendingSweeps(_ context.Context,
	_ *walletrpc.PendingSweepsRequest,
	_ ...grpc.CallOption) (*walletrpc.PendingSweepsResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) BumpFee(_ context.Context,
	_ *walletrpc.BumpFeeRequest,
	_ ...grpc.CallOption) (*walletrpc.BumpFeeResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) ListSweeps(_ context.Context,
	_ *walletrpc.ListSweepsRequest,
	_ ...grpc.CallOption) (*walletrpc.ListSweepsResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) LabelTransaction(_ context.Context,
	_ *walletrpc.LabelTransactionRequest,
	_ ...grpc.CallOption) (*walletrpc.LabelTransactionResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) FundPsbt(_ context.Context,
	_ *walletrpc.FundPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.FundPsbtResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (s *SignCoordinator) FinalizePsbt(_ context.Context,
	_ *walletrpc.FinalizePsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.FinalizePsbtResponse, error) {

	panic("unimplemented")
}

// NOTE: This is part of the walletrpc.WalletKitClient interface.
func (*SignCoordinator) SignCoordinatorStreams(_ context.Context,
	_ ...grpc.CallOption) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, error) {

	panic("unimplemented")
}
