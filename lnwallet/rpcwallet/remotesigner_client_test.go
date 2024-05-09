package rpcwallet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

var (
	// ErrRequestTimeout is the error that's returned if we time out while
	// waiting for a request.
	ErrRequestTimeout = errors.New(
		"signcoordinator request timeout reached")

	ErrStreamCanceled = errors.New("stream canceled")

	ErrStreamError = errors.New("stream creation error")
)

const (
	handshakeRequestID = uint64(1)
)

// Mock implementation of SignCoordinatorStreamFeeder
type mockStreamFeeder struct {
	stream           *mockStream
	retries          int
	creationFailures int

	streamCreated       chan struct{}
	streamCreateErrChan chan error
	quit                chan struct{}
}

func newMockStreamFeeder(creationFailures int) *mockStreamFeeder {
	return &mockStreamFeeder{
		streamCreated:       make(chan struct{}),
		streamCreateErrChan: make(chan error),
		quit:                make(chan struct{}),
		creationFailures:    creationFailures,
	}
}

func (msf *mockStreamFeeder) GetStream(ctxc context.Context) (
	walletrpc.WalletKit_SignCoordinatorStreamsClient, func(), error) {

	select {
	case <-msf.quit:
		return nil, nil, ErrShuttingDown
	default:
	}

	if msf.retries < msf.creationFailures {
		defer func() {
			select {
			case msf.streamCreateErrChan <- ErrStreamError:
			case <-ctxc.Done():
			case <-msf.quit:
			}
		}()

		msf.retries++

		return nil, nil, ErrStreamError
	}

	stream := newMockStream(ctxc)

	msf.stream = stream

	defer func() {
		select {
		case msf.streamCreated <- struct{}{}:
		case <-ctxc.Done():
		case <-msf.quit:
		}
	}()

	return msf.stream, func() {}, nil
}

func (msf *mockStreamFeeder) Stop() {
	close(msf.quit)
}

func (msf *mockStreamFeeder) handleHandshake(t *testing.T) {
	<-msf.streamCreated

	msf.stream.handleHandshake(t)
}

// Mock implementation of a stream.
type mockStream struct {
	sendChan   chan *walletrpc.SignCoordinatorResponse
	recvChan   chan *walletrpc.SignCoordinatorRequest
	cancelChan chan struct{}
	//sendErr error
	//recvMsg *walletrpc.SignCoordinatorRequest
	recvErr error

	ctx    context.Context
	cancel func()
}

func (ms *mockStream) Send(resp *walletrpc.SignCoordinatorResponse) error {
	ms.sendChan <- resp

	return nil
}

func (ms *mockStream) Recv() (*walletrpc.SignCoordinatorRequest, error) {
	select {
	case resp := <-ms.recvChan:
		return resp, nil
	case <-ms.ctx.Done():
		// To simulate a canceled stream, we return an error when the
		// cancelChan is closed.
		return nil, ErrStreamCanceled
	}
}

// Helper function to simulate requests sent over the mock stream.
func (ms *mockStream) recvRequest(req *walletrpc.SignCoordinatorRequest) {
	ms.recvChan <- req
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
		sendChan:   make(chan *walletrpc.SignCoordinatorResponse, 10),
		recvChan:   make(chan *walletrpc.SignCoordinatorRequest, 10),
		cancelChan: make(chan struct{}),
		ctx:        ctxc,
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

		if streamFeeder.creationFailures == 0 {
			streamFeeder.handleHandshake(t)
		}
	}

	return client
}

// Test cases
func TestRemoteSignerClient_PingResponse(t *testing.T) {

	mockFeeder := newMockStreamFeeder(0)

	client := newTestRemoteSignerClient(t, mockFeeder, true)
	defer client.Stop()

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

func TestRemoteSignerClient_StreamFeederErrorHandling(t *testing.T) {

	msf := newMockStreamFeeder(1)

	client := newTestRemoteSignerClient(t, msf, true)
	defer client.Stop()

	err := <-msf.streamCreateErrChan
	require.Equal(t, ErrStreamError, err)

	wait.Predicate(func() bool {
		return msf.retries == 1 &&
			client.retryTimeout > defaultRetryTimeout
	}, 1*time.Second)
}

/*func TestRemoteSignerClient_StopFunctionality(t *testing.T) {
	tests := []struct {
		name    string
		feeder  *mockStreamFeeder
		wantErr bool
	}{
		{
			name:    "GetStream errors",
			feeder:  newMockStreamFeeder(1),
			wantErr: false,
		},
		{
			name:    "GetStream successful",
			feeder:  &mockStreamFeeder{stream: &mockStream{}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestRemoteSignerClient(t, tt.feeder)
			if err := client.Start(); err != nil {
				t.Fatalf("error starting RemoteSignerClient: %v", err)
			}
			err := client.Stop()
			if (err != nil) != tt.wantErr {
				t.Errorf("Stop() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}*/

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
