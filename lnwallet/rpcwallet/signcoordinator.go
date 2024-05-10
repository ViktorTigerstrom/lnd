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
	"github.com/lightningnetwork/lnd/lnwallet"
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

type ResponsePair struct {
	ID       uint64
	Response *walletrpc.SignCoordinatorResponse
}

// RPCKeyRing is an implementation of the SecretKeyRing interface that uses a
// local watch-only wallet for keeping track of addresses and transactions but
// delegates any signing or ECDH operations to a remote node through RPC.
type SignCoordinator struct {
	// WalletController is the embedded wallet controller of the watch-only
	// base wallet. We need to overwrite/shadow certain of the implemented
	// methods to make sure we can mirror them to the remote wallet.
	lnwallet.WalletController

	stream walletrpc.WalletKit_SignCoordinatorStreamsServer

	responses map[uint64]chan *walletrpc.SignCoordinatorResponse

	receiveErrChan chan error

	// doneReceiving is closed when either party terminates.
	doneReceiving chan struct{}

	// quit is closed when lnd is shutting down.
	quit chan struct{}

	// clientConnected is sent over when the client connects.
	clientConnected chan struct{}

	nextRequestID uint64

	requestTimeout time.Duration

	connectionTimeout time.Duration

	mu sync.Mutex

	wg sync.WaitGroup
}

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

	if s.stream != nil {
		s.mu.Unlock()
		return ErrMultipleConnections
	}

	s.stream = stream

	s.mu.Unlock()

	err := s.Handshake(stream)
	if err != nil {
		return err
	}

	close(s.clientConnected)

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

func (s *SignCoordinator) Stop() {
	log.Infof("Stopping Sign Coordinator")
	defer log.Debugf("Sign coordinator stopped")

	s.mu.Lock()

	close(s.quit)

	s.mu.Unlock()

	s.wg.Wait()
}

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
	// long.
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
	regCompleteMsg := &walletrpc.SignCoordinatorRequest{
		RequestId: handshakeRequestID,
		SignRequestType: &walletrpc.SignCoordinatorRequest_RegistrationComplete{
			RegistrationComplete: true,
		},
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

	log.Infof("Remote signer connected")

	return nil
}

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

func (s *SignCoordinator) WaitUntilConnected() error {
	return s.waitUntilConnectedWithTimeout(s.connectionTimeout)
}

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

func (s *SignCoordinator) getNextRequestID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	nextRequestID := s.nextRequestID

	s.nextRequestID++

	return nextRequestID
}

func (s *SignCoordinator) createResponseChannel(requestID uint64) func() {
	s.mu.Lock()
	defer s.mu.Unlock()

	respChan := make(chan *walletrpc.SignCoordinatorResponse, 1)

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
// response if it is received. If the response is an error, the error message is
// returned. If the response is not received within the given timeout, an error
// is returned.
// Before calling this function, the caller must have created a response channel
// for the request id.
func (s *SignCoordinator) getResponse(requestID uint64,
	timeout time.Duration) (*walletrpc.SignCoordinatorResponse, error) {

	s.mu.Lock()

	if _, ok := s.responses[requestID]; !ok {
		// Should be impossible to reach this case, as we create the
		// response channel before sending the request.
		s.mu.Unlock()

		return nil, fmt.Errorf("no response channel found for request "+
			"id %d", requestID)
	}

	respChan := s.responses[requestID]

	s.mu.Unlock()

	select {
	case resp := <-respChan:
		// If the response is an error, we return the error
		// message.
		if errorResp, ok := resp.GetSignResponseType().(*walletrpc.SignCoordinatorResponse_SignerError); ok {
			errStr := errorResp.SignerError.Error

			return nil, errors.New(errStr)
		}

		log.Infof("Received response for request id %d",
			requestID)

		return resp, nil

	case <-s.doneReceiving:
		return nil, ErrNotConnected

	case <-s.quit:
		return nil, ErrShuttingDown

	case <-time.After(timeout):
		return nil, ErrRequestTimeout
	}
}

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

// DeriveSharedKey implements signrpc.SignerClient.
func (s *SignCoordinator) DeriveSharedKey(_ context.Context,
	in *signrpc.SharedKeyRequest,
	_ ...grpc.CallOption) (*signrpc.SharedKeyResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 DeriveSharedKey request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SharedKeyRequest{
		SharedKeyRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// MuSig2Cleanup implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2Cleanup(_ context.Context,
	in *signrpc.MuSig2CleanupRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CleanupResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 MuSig2Cleanup request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2CleanupRequest{
		MuSig2CleanupRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// MuSig2CombineSig implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2CombineSig(_ context.Context,
	in *signrpc.MuSig2CombineSigRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CombineSigResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 MuSig2CombineSig request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2CombineSigRequest{
		MuSig2CombineSigRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// MuSig2CreateSession implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2CreateSession(_ context.Context,
	in *signrpc.MuSig2SessionRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SessionResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 MuSig2CreateSession request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2SessionRequest{
		MuSig2SessionRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// MuSig2RegisterNonces implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2RegisterNonces(_ context.Context,
	in *signrpc.MuSig2RegisterNoncesRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2RegisterNoncesResponse,
	error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 MuSig2RegisterNonces request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2RegisterNoncesRequest{
		MuSig2RegisterNoncesRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// MuSig2Sign implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2Sign(_ context.Context,
	in *signrpc.MuSig2SignRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2SignResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 MuSig2Sign request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_MuSig2SignRequest{
		MuSig2SignRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// SignMessage implements signrpc.SignerClient.
func (s *SignCoordinator) SignMessage(_ context.Context,
	in *signrpc.SignMessageReq,
	_ ...grpc.CallOption) (*signrpc.SignMessageResp, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 SignMessage request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SignMessageReq{
		SignMessageReq: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

func (s *SignCoordinator) SignPsbt(_ context.Context,
	in *walletrpc.SignPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.SignPsbtResponse, error) {

	s.wg.Add(1)
	defer s.wg.Done()

	log.Infof("111111111 SignPsbt request in SignCoordinator")

	err := s.WaitUntilConnected()
	if err != nil {
		return nil, err
	}

	log.Infof("22222222 Done waiting for connection in SignCoordinator")

	requestID := s.getNextRequestID()

	req := &walletrpc.SignCoordinatorRequest_SignPsbtRequest{
		SignPsbtRequest: in,
	}

	cleanUp := s.createResponseChannel(requestID)
	defer cleanUp()

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

// ComputeInputScript implements signrpc.SignerClient.
func (s *SignCoordinator) ComputeInputScript(_ context.Context,
	_ *signrpc.SignReq,
	_ ...grpc.CallOption) (*signrpc.InputScriptResp, error) {

	panic("unimplemented")
}

// MuSig2CombineKeys implements signrpc.SignerClient.
func (s *SignCoordinator) MuSig2CombineKeys(_ context.Context,
	_ *signrpc.MuSig2CombineKeysRequest,
	_ ...grpc.CallOption) (*signrpc.MuSig2CombineKeysResponse, error) {

	panic("unimplemented")
}

// SignOutputRaw implements signrpc.SignerClient.
func (s *SignCoordinator) SignOutputRaw(_ context.Context,
	_ *signrpc.SignReq,
	_ ...grpc.CallOption) (*signrpc.SignResp, error) {

	panic("unimplemented")
}

// VerifyMessage implements signrpc.SignerClient.
func (s *SignCoordinator) VerifyMessage(_ context.Context,
	_ *signrpc.VerifyMessageReq,
	_ ...grpc.CallOption) (*signrpc.VerifyMessageResp, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ListUnspent(_ context.Context,
	_ *walletrpc.ListUnspentRequest,
	_ ...grpc.CallOption) (*walletrpc.ListUnspentResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) LeaseOutput(_ context.Context,
	_ *walletrpc.LeaseOutputRequest,
	_ ...grpc.CallOption) (*walletrpc.LeaseOutputResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ReleaseOutput(_ context.Context,
	_ *walletrpc.ReleaseOutputRequest,
	_ ...grpc.CallOption) (*walletrpc.ReleaseOutputResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ListLeases(_ context.Context,
	_ *walletrpc.ListLeasesRequest,
	_ ...grpc.CallOption) (*walletrpc.ListLeasesResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) DeriveNextKey(_ context.Context,
	_ *walletrpc.KeyReq,
	_ ...grpc.CallOption) (*signrpc.KeyDescriptor, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) DeriveKey(_ context.Context,
	_ *signrpc.KeyLocator,
	_ ...grpc.CallOption) (*signrpc.KeyDescriptor, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) NextAddr(_ context.Context,
	_ *walletrpc.AddrRequest,
	_ ...grpc.CallOption) (*walletrpc.AddrResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) GetTransaction(_ context.Context,
	_ *walletrpc.GetTransactionRequest,
	_ ...grpc.CallOption) (*lnrpc.Transaction, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ListAccounts(_ context.Context,
	_ *walletrpc.ListAccountsRequest,
	_ ...grpc.CallOption) (*walletrpc.ListAccountsResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) RequiredReserve(_ context.Context,
	_ *walletrpc.RequiredReserveRequest,
	_ ...grpc.CallOption) (*walletrpc.RequiredReserveResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ListAddresses(_ context.Context,
	_ *walletrpc.ListAddressesRequest,
	_ ...grpc.CallOption) (*walletrpc.ListAddressesResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) SignMessageWithAddr(_ context.Context,
	_ *walletrpc.SignMessageWithAddrRequest,
	_ ...grpc.CallOption) (*walletrpc.SignMessageWithAddrResponse,
	error) {

	panic("unimplemented")
}

func (s *SignCoordinator) VerifyMessageWithAddr(_ context.Context,
	_ *walletrpc.VerifyMessageWithAddrRequest,
	_ ...grpc.CallOption) (*walletrpc.VerifyMessageWithAddrResponse,
	error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ImportAccount(_ context.Context,
	_ *walletrpc.ImportAccountRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportAccountResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ImportPublicKey(_ context.Context,
	_ *walletrpc.ImportPublicKeyRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportPublicKeyResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ImportTapscript(_ context.Context,
	_ *walletrpc.ImportTapscriptRequest,
	_ ...grpc.CallOption) (*walletrpc.ImportTapscriptResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) PublishTransaction(_ context.Context,
	_ *walletrpc.Transaction,
	_ ...grpc.CallOption) (*walletrpc.PublishResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) RemoveTransaction(_ context.Context,
	_ *walletrpc.GetTransactionRequest,
	_ ...grpc.CallOption) (*walletrpc.RemoveTransactionResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) SendOutputs(_ context.Context,
	_ *walletrpc.SendOutputsRequest,
	_ ...grpc.CallOption) (*walletrpc.SendOutputsResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) EstimateFee(_ context.Context,
	_ *walletrpc.EstimateFeeRequest,
	_ ...grpc.CallOption) (*walletrpc.EstimateFeeResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) PendingSweeps(_ context.Context,
	_ *walletrpc.PendingSweepsRequest,
	_ ...grpc.CallOption) (*walletrpc.PendingSweepsResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) BumpFee(_ context.Context,
	_ *walletrpc.BumpFeeRequest,
	_ ...grpc.CallOption) (*walletrpc.BumpFeeResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) ListSweeps(_ context.Context,
	_ *walletrpc.ListSweepsRequest,
	_ ...grpc.CallOption) (*walletrpc.ListSweepsResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) LabelTransaction(_ context.Context,
	_ *walletrpc.LabelTransactionRequest,
	_ ...grpc.CallOption) (*walletrpc.LabelTransactionResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) FundPsbt(_ context.Context,
	_ *walletrpc.FundPsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.FundPsbtResponse, error) {

	panic("unimplemented")
}

func (s *SignCoordinator) FinalizePsbt(_ context.Context,
	_ *walletrpc.FinalizePsbtRequest,
	_ ...grpc.CallOption) (*walletrpc.FinalizePsbtResponse, error) {

	panic("unimplemented")
}

// SignCoordinatorStreams implements walletrpc.WalletKitClient.
func (*SignCoordinator) SignCoordinatorStreams(_ context.Context,
	_ ...grpc.CallOption) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, error) {

	panic("unimplemented")
}

var _ signrpc.SignerClient = (*SignCoordinator)(nil)

var _ walletrpc.WalletKitClient = (*SignCoordinator)(nil)
