package rpcwallet

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

var (
	// ErrRequestTimeout is the error that's returned if we time out while
	// waiting for a request.
	ErrRequestTimeout = errors.New(
		"signcoordinator request timeout reached")

	ErrStreamCanceled = errors.New("stream canceled")

	ErrMockResponseErr = errors.New("mock response error")

	ErrStreamError = errors.New("stream creation error")
)

const (
	handshakeRequestID = uint64(1)
)

// Mock implementation of SignCoordinatorStreamFeeder
type mockStreamFeeder struct {
	stream           *mockStream
	streamShouldFail bool

	streamCreated chan error
	quit          chan struct{}

	mu sync.Mutex
}

func newMockStreamFeeder(getStreamShouldFail bool) *mockStreamFeeder {
	return &mockStreamFeeder{
		streamCreated:    make(chan error),
		quit:             make(chan struct{}),
		streamShouldFail: getStreamShouldFail,
	}
}

func (msf *mockStreamFeeder) GetStream(ctxc context.Context) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, func(), error) {

	msf.mu.Lock()

	select {
	case <-msf.quit:
		msf.mu.Unlock()
		return nil, nil, ErrShuttingDown
	default:
	}

	if msf.streamShouldFail {
		msf.mu.Unlock()

		select {
		case msf.streamCreated <- ErrStreamError:
		case <-ctxc.Done():
		case <-msf.quit:
		}

		return nil, nil, ErrStreamError
	}

	stream := newMockStream(ctxc)

	msf.stream = stream

	msf.mu.Unlock()

	select {
	case msf.streamCreated <- nil:
	case <-ctxc.Done():
	case <-msf.quit:
	}

	return msf.stream, func() {}, nil
}

func (msf *mockStreamFeeder) SetStreamFailure(shouldFail bool) {
	msf.mu.Lock()
	defer msf.mu.Unlock()

	msf.streamShouldFail = shouldFail
}

func (msf *mockStreamFeeder) GetStreamShouldFailure() bool {
	msf.mu.Lock()
	defer msf.mu.Unlock()

	return msf.streamShouldFail
}

func (msf *mockStreamFeeder) Stop() {
	close(msf.quit)
}

func (msf *mockStreamFeeder) handleHandshake(t *testing.T) {
	err := <-msf.streamCreated
	require.NoError(t, err)

	msf.stream.handleHandshake(t)
}

// Mock implementation of a stream.
type mockStream struct {
	sendChan    chan *walletrpc.SignCoordinatorResponse
	recvChan    chan *walletrpc.SignCoordinatorRequest
	recvErrChan chan error

	ctx context.Context
}

func (ms *mockStream) Send(resp *walletrpc.SignCoordinatorResponse) error {
	ms.sendChan <- resp

	return nil
}

func (ms *mockStream) Recv() (*walletrpc.SignCoordinatorRequest, error) {
	select {
	case resp := <-ms.recvChan:
		return resp, nil
	case err := <-ms.recvErrChan:
		return nil, err
	case <-ms.ctx.Done():
		// If the context is canceled, we return an error to indicate
		// that the stream has been canceled.
		return nil, ErrStreamCanceled
	}
}

// Helper function to simulate requests sent over the mock stream.
func (ms *mockStream) recvRequest(req *walletrpc.SignCoordinatorRequest) {
	ms.recvChan <- req
}

// Helper function to simulate that the stream errors.
func (ms *mockStream) recvErr(err error) {
	ms.recvErrChan <- err
}

func (ms *mockStream) handleHandshake(t *testing.T) {
	resp := <-ms.sendChan

	require.Equal(t, handshakeRequestID, resp.GetRequestId())
	require.True(t, resp.GetSignerRegistration())

	// Send a message to the client to indicate that the registration has
	// successfully completed.
	regCompleteMsg := &walletrpc.SignCoordinatorRequest{
		RequestId: handshakeRequestID,
		SignRequestType: &walletrpc.SignCoordinatorRequest_RegistrationComplete{
			RegistrationComplete: true,
		},
	}

	ms.recvRequest(regCompleteMsg)
}

func newMockStream(ctxc context.Context) *mockStream {
	return &mockStream{
		sendChan:    make(chan *walletrpc.SignCoordinatorResponse, 10),
		recvChan:    make(chan *walletrpc.SignCoordinatorRequest, 10),
		recvErrChan: make(chan error),
		ctx:         ctxc,
	}
}

func (ms *mockStream) Header() (metadata.MD, error) { return nil, nil }
func (ms *mockStream) SendMsg(m any) error          { return nil }
func (ms *mockStream) Trailer() metadata.MD         { return nil }
func (ms *mockStream) CloseSend() error             { return nil }
func (ms *mockStream) RecvMsg(m any) error          { return nil }
func (ms *mockStream) Context() context.Context     { return ms.ctx }

func newTestRemoteSignerClient(t *testing.T,
	streamFeeder *mockStreamFeeder,
	start bool) *RemoteSignerClient {

	client, err := NewRemoteSignerClient(
		[]lnrpc.SubServer{&mockWalletKitServer{}, &mockSignerServer{}},
		streamFeeder,
		&lncfg.RemoteSigner{
			InboundConnectionTimeout: 1 * time.Second,
			SignerType:               lncfg.SignerClientType,
		},
	)
	require.NoError(t, err)

	if start {
		require.NoError(t, client.Start())

		if !streamFeeder.GetStreamShouldFailure() {
			streamFeeder.handleHandshake(t)
		}
	}

	return client
}

// Test cases
func TestRemoteSignerClient_PingResponse(t *testing.T) {
	t.Parallel()

	mockFeeder := newMockStreamFeeder(false)

	client := newTestRemoteSignerClient(t, mockFeeder, true)
	defer func() {
		require.NoError(t, client.Stop())
	}()

	pingReq := &walletrpc.SignCoordinatorRequest_Ping{
		Ping: true,
	}

	requestID := uint64(2)

	req := &walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: pingReq,
	}

	mockFeeder.stream.recvRequest(req)

	resp := <-mockFeeder.stream.sendChan

	require.Equal(t, requestID, resp.GetRequestId())
	require.True(t, resp.GetPong())
}

func TestRemoteSignerClient_MultiplePingResponses(t *testing.T) {
	t.Parallel()

	mockFeeder := newMockStreamFeeder(false)

	client := newTestRemoteSignerClient(t, mockFeeder, true)
	defer func() {
		require.NoError(t, client.Stop())
	}()

	pingReq := &walletrpc.SignCoordinatorRequest_Ping{
		Ping: true,
	}

	requestID1 := uint64(2)

	req1 := &walletrpc.SignCoordinatorRequest{
		RequestId:       requestID1,
		SignRequestType: pingReq,
	}

	mockFeeder.stream.recvRequest(req1)

	resp1 := <-mockFeeder.stream.sendChan

	require.Equal(t, requestID1, resp1.GetRequestId())
	require.True(t, resp1.GetPong())

	requestID2 := uint64(3)

	req2 := &walletrpc.SignCoordinatorRequest{
		RequestId:       requestID2,
		SignRequestType: pingReq,
	}

	mockFeeder.stream.recvRequest(req2)

	resp2 := <-mockFeeder.stream.sendChan

	require.Equal(t, requestID2, resp2.GetRequestId())
	require.True(t, resp2.GetPong())
}

func TestRemoteSignerClient_StreamRecvErrorHandling(t *testing.T) {
	t.Parallel()

	msf := newMockStreamFeeder(false)

	client := newTestRemoteSignerClient(t, msf, true)
	defer func() {
		require.NoError(t, client.Stop())
	}()

	msf.stream.recvErr(ErrStreamCanceled)

	err := <-msf.streamCreated
	require.NoError(t, err)
}

func TestRemoteSignerClient_ResponseError(t *testing.T) {
	t.Parallel()

	msf := newMockStreamFeeder(false)

	client := newTestRemoteSignerClient(t, msf, true)
	defer func() {
		require.NoError(t, client.Stop())
	}()

	pingReq := &walletrpc.SignCoordinatorRequest_SignMessageReq{
		SignMessageReq: &signrpc.SignMessageReq{},
	}

	requestID := uint64(2)

	req := &walletrpc.SignCoordinatorRequest{
		RequestId:       requestID,
		SignRequestType: pingReq,
	}

	msf.stream.recvRequest(req)

	resp := <-msf.stream.sendChan

	require.Equal(t, requestID, resp.GetRequestId())

	signErr := resp.GetSignerError()
	require.NotNil(t, signErr)

	expErrStr := "error processing sign request in remote signer error: " +
		ErrMockResponseErr.Error()

	require.Equal(t, expErrStr, signErr.GetError())
}

// Test that the client will retry to create a stream if the stream creation
// fails, and that the backoff duration before retrying to setup the stream
// again is increased with each retry.
func TestRemoteSignerClient_StreamCreationBackoffTest(t *testing.T) {
	t.Parallel()

	msf := newMockStreamFeeder(true)

	client := newTestRemoteSignerClient(t, msf, true)
	defer func() {
		require.NoError(t, client.Stop())
	}()

	err := <-msf.streamCreated
	require.Equal(t, ErrStreamError, err)

	lastStreamCreationAttempt := time.Now()

	// The first time the client fails to setup a stream, we expect that the
	// client will retry to create the stream after the default retry
	// timeout, without any multiplied backoff. Once that happens, the
	// streamCreated channel should be sent over, with the ErrStreamError.
	err = <-msf.streamCreated
	require.Equal(t, ErrStreamError, err)

	// Now let's verify that the client waited the default retry timeout
	// before retrying to recreate the stream.
	retryBackoff := time.Since(lastStreamCreationAttempt)
	expectedBackoff := time.Duration(float64(defaultRetryTimeout) *
		math.Pow(float64(retryMultiplier), 0)) // 0 for no multiplier

	// Verify that the retry backoff is within the expected range. We allow
	// a small margin of error (100ms)to account for the time it takes to
	// execute the test code.
	require.GreaterOrEqual(t, retryBackoff, expectedBackoff)
	require.LessOrEqual(
		t, retryBackoff, expectedBackoff+100*time.Millisecond,
	)

	// Reset the last attempt time, so we can check the next retry.
	lastStreamCreationAttempt = time.Now()

	// Now let's wait till the client retries to create the stream again.
	// This time we expect that a multiplier of the retryMultiplier^1 has
	// been applied to the backoff duration.
	err = <-msf.streamCreated
	require.Equal(t, ErrStreamError, err)

	// Verify that the retry backoff is within the expected range, with the
	// multiplier applied.
	retryBackoff = time.Since(lastStreamCreationAttempt)
	// The second backoff should have the multiplier applied once, therefore
	// the multiplier raised to the power of 1.
	expectedBackoff = time.Duration(float64(defaultRetryTimeout) *
		math.Pow(float64(retryMultiplier), 1))

	// Verify that the retry backoff is within the expected range.
	require.GreaterOrEqual(t, retryBackoff, expectedBackoff)
	require.LessOrEqual(
		t, retryBackoff, expectedBackoff+100*time.Millisecond,
	)

	// Reset the last attempt time, so we can check the next retry.
	lastStreamCreationAttempt = time.Now()

	// For the next retry, we want the stream creation to succeed. This will
	// reset the retry backoff to the default value, once the stream is
	// successfully created.
	msf.SetStreamFailure(false)

	// Now let's wait till the client retries to create the stream again.
	// Even though the creation will succeed, it'll still take the expected
	// backoff before the client attempts to make the successful stream
	// creation attempt. The backoff time is therefore expected to be the
	// defaultRetryTimeout*retryMultiplier^2.
	err = <-msf.streamCreated
	// We expect the stream creation to succeed this time.
	require.NoError(t, err)

	// Verify that the retry backoff is within the expected range, with the
	// multiplier applied.
	retryBackoff = time.Since(lastStreamCreationAttempt)

	// The second backoff should have the multiplier applied once, therefore
	// the multiplier raised to the power of 2.
	expectedBackoff = time.Duration(float64(defaultRetryTimeout) *
		math.Pow(float64(retryMultiplier), 2))

	// Verify that the retry backoff is within the expected range.
	require.GreaterOrEqual(t, retryBackoff, expectedBackoff)
	require.LessOrEqual(
		t, retryBackoff, expectedBackoff+100*time.Millisecond,
	)

	// As the steam creation was successful, the client will proceed with
	// the handshake procedure before the stream creation is considered
	// successful. We therefore need to simulate the handshake procedure.
	msf.handleHandshake(t)

	// Now let's cause the stream to fail again, to verify that the client
	// reset the backoff to the default value.
	msf.stream.recvErr(ErrStreamCanceled)

	// Reset the last attempt time, so we can check the next retry.
	lastStreamCreationAttempt = time.Now()

	// Now let's wait till the client retries to create the stream again.
	err = <-msf.streamCreated
	// We expect the stream creation to also succeed this time.
	require.NoError(t, err)

	// As the backoff is reset to the default value, we expect that no
	// multiplier has been applied to the backoff duration.
	retryBackoff = time.Since(lastStreamCreationAttempt)
	expectedBackoff = time.Duration(float64(defaultRetryTimeout) *
		math.Pow(float64(retryMultiplier), 0))

	// Verify that the retry backoff is within the expected range.
	require.GreaterOrEqual(t, retryBackoff, expectedBackoff)
	require.LessOrEqual(
		t, retryBackoff, expectedBackoff+100*time.Millisecond,
	)
}

// Mock WalletKitServer and SignerServer that panic for all methods.
type mockWalletKitServer struct {
	walletrpc.UnimplementedWalletKitServer
}

// Name returns a unique string representation of the sub-server. This
// can be used to identify the sub-server and also de-duplicate them.
func (m *mockWalletKitServer) Name() string { return walletrpc.SubServerName }

var _ walletrpc.WalletKitServer = (*mockWalletKitServer)(nil)

// Start starts the sub-server and all goroutines it needs to operate.
func (m *mockWalletKitServer) Start() error { return nil }

// Stop signals that the sub-server should wrap up any lingering
// requests, and being a graceful shutdown.
func (m *mockWalletKitServer) Stop() error { return nil }

// InjectDependencies populates the sub-server's dependencies using the
// passed SubServerConfigDispatcher.
func (m *mockWalletKitServer) InjectDependencies(
	subCfgs lnrpc.SubServerConfigDispatcher) error {

	return nil
}

type mockSignerServer struct {
	signrpc.UnimplementedSignerServer
}

var _ signrpc.SignerServer = (*mockSignerServer)(nil)

func (m *mockSignerServer) SignMessage(_ context.Context,
	_ *signrpc.SignMessageReq) (*signrpc.SignMessageResp, error) {

	return nil, ErrMockResponseErr
}

// Name returns a unique string representation of the sub-server. This
// can be used to identify the sub-server and also de-duplicate them.
func (m *mockSignerServer) Name() string { return "SignRPC" }

// Start starts the sub-server and all goroutines it needs to operate.
func (m *mockSignerServer) Start() error { return nil }

// Stop signals that the sub-server should wrap up any lingering
// requests, and being a graceful shutdown.
func (m *mockSignerServer) Stop() error { return nil }

// InjectDependencies populates the sub-server's dependencies using the
// passed SubServerConfigDispatcher.
func (m *mockSignerServer) InjectDependencies(
	subCfgs lnrpc.SubServerConfigDispatcher) error {

	return nil
}
