package signcoordinator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
)

type mockStream struct {
	sendChan   chan *walletrpc.SignCoordinatorRequest
	recvChan   chan *walletrpc.SignCoordinatorResponse
	cancelChan chan struct{}

	ctx    context.Context
	cancel func()
}

func newMockStream() *mockStream {
	ctxc, cancel := context.WithCancel(context.Background())

	return &mockStream{
		sendChan:   make(chan *walletrpc.SignCoordinatorRequest, 10),
		recvChan:   make(chan *walletrpc.SignCoordinatorResponse, 10),
		cancelChan: make(chan struct{}),
		ctx:        ctxc,
		cancel:     cancel,
	}
}

func (ms *mockStream) Send(req *walletrpc.SignCoordinatorRequest) error {
	ms.sendChan <- req
	return nil
}

func (ms *mockStream) Recv() (*walletrpc.SignCoordinatorResponse, error) {
	select {
	case resp := <-ms.recvChan:
		return resp, nil
	case <-ms.cancelChan:
		// To simulate a canceled stream, we return an error when the
		// cancelChan is closed.
		return nil, ErrStreamCanceled
	}
}

func (ms *mockStream) RecvMsg(msg any) error {
	return nil
}

func (ms *mockStream) SendHeader(metadata.MD) error {
	return nil
}

func (ms *mockStream) SendMsg(m any) error {
	return nil
}
func (ms *mockStream) SetHeader(metadata.MD) error {
	return nil
}

func (ms *mockStream) SetTrailer(metadata.MD) {}

func (ms *mockStream) Context() context.Context {
	return ms.ctx
}

// Cancel closes the cancelChan to simulate a canceled stream.
func (ms *mockStream) Cancel() {
	close(ms.cancelChan)
	ms.cancel()
}

// Helper function to simulate responses sent over the mock stream.
func (ms *mockStream) sendResponse(resp *walletrpc.SignCoordinatorResponse) {
	ms.recvChan <- resp
}

func setupSignCoordinator(t *testing.T) (*SignCoordinator, *mockStream,
	chan error) {

	stream := newMockStream()
	coordinator := NewSignCoordinator(2*time.Second, 3*time.Second)

	errChan := make(chan error)
	go func() {
		err := coordinator.Run(stream)
		if err != nil {
			errChan <- err
		}
	}()

	regType := &walletrpc.SignCoordinatorResponse_SignerRegistration{
		SignerRegistration: true,
	}

	registrationMsg := &walletrpc.SignCoordinatorResponse{
		RequestId:        1, // Request ID is always 1 for registration.
		SignResponseType: regType,
	}

	stream.sendResponse(registrationMsg)

	select {
	case req := <-stream.sendChan:
		require.Equal(t, req.GetRequestId(), uint64(1))
		require.True(t, req.GetRegistrationComplete())
	case <-time.After(time.Second):
		require.Fail(
			t, "registration complete message not received",
		)
	}

	return coordinator, stream, errChan
}

func getRequest(s *mockStream) (*walletrpc.SignCoordinatorRequest, error) {
	select {
	case req := <-s.sendChan:
		return req, nil
	case <-time.After(time.Second):
		return nil, ErrRequestTimeout
	}
}

func TestSignCoordinator_PingResponse(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	wg.Wait()

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_ConcurrentPingResponses(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	// Send concurrent Ping requests
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req1, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req1.GetRequestId(), uint64(2))
	require.True(t, req1.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req2, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req2.GetRequestId(), uint64(3))
	require.True(t, req2.GetPing())

	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	// Send responses for both Ping requests
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 3,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	wg.Wait()

	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req3, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req3.GetRequestId(), uint64(4))
	require.True(t, req3.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok = coordinator.responses[uint64(4)]
	require.True(t, ok)

	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req4, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req4.GetRequestId(), uint64(5))
	require.True(t, req4.GetPing())

	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(5)]
	require.True(t, ok)

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 5,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 4,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	wg.Wait()

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_PingTimeout(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	// Simulate a Ping request that times out
	_, err := coordinator.Ping(1 * time.Second)
	require.Equal(t, ErrResponseTimeout, err)

	// Verify that the responses map is empty after the timeout
	require.Empty(t, coordinator.responses)

	// Now lets simulate that the response is sent back after the request
	// has timed out.
	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Verify that the responses map still remains empty, as responses for
	// timed out requests are ignored.
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_PingTimeoutByOneRequest(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	// Send concurrent Ping requests
	var wg sync.WaitGroup
	wg.Add(1)

	timeoutChan := make(chan struct{}, 1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(1 * time.Second)
		require.Equal(t, ErrResponseTimeout, err)
		require.False(t, success)

		close(timeoutChan)
	}()

	req1, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req1.GetRequestId(), uint64(2))
	require.True(t, req1.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req2, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req2.GetRequestId(), uint64(3))
	require.True(t, req2.GetPing())

	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	<-timeoutChan

	require.Len(t, coordinator.responses, 1)
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	// Send responses for both Ping requests
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 3,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	wg.Wait()

	wg.Add(1)

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_IncorrectResponseRequestId(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(1 * time.Second)
		require.Equal(t, ErrResponseTimeout, err)
		require.False(t, success)
	}()

	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 3, // Incorrect request ID
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	wg.Wait()

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_SignerError(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(1 * time.Second)
		require.Equal(t, "mock error", err.Error())
		require.False(t, success)
	}()

	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_SignerError{
			SignerError: &walletrpc.SignerError{
				Error: "mock error",
			},
		},
	})

	wg.Wait()

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_StopCoordinator(t *testing.T) {
	t.Parallel()

	coordinator, stream, runErrChan := setupSignCoordinator(t)

	pingTimeout := 3 * time.Second
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(pingTimeout)
		require.Equal(t, ErrShuttingDown, err)
		require.False(t, success)
	}()

	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Stop the coordinator
	wg.Add(1)
	go func() {
		defer wg.Done()
		coordinator.Stop()
	}()

	err = <-runErrChan
	require.Equal(t, ErrShuttingDown, err)

	// As the coordinator Run function returned the ErrShuttingDown error,
	// the lnd would normally cancel the stream. We simulate this by
	// calling the Cancel method on the mock stream.
	stream.Cancel()

	wg.Wait()

	require.Less(t, time.Since(startTime), pingTimeout)

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

func TestSignCoordinator_RemoteSignerDisconnects(t *testing.T) {
	t.Parallel()

	coordinator, stream, runErrChan := setupSignCoordinator(t)

	pingTimeout := 3 * time.Second
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(pingTimeout)
		require.Equal(t, ErrNotConnected, err)
		require.False(t, success)
	}()

	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, req.GetRequestId(), uint64(2))
	require.True(t, req.GetPing())

	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// We simulate that the remote signer disconnects by canceling the
	// stream.
	stream.Cancel()

	// This should cause the Run function to return the error that the
	// stream was canceled with.
	err = <-runErrChan
	require.Equal(t, ErrStreamCanceled, err)

	wg.Wait()

	// Verify that the coordinator signals that it's done receiving
	// responses after the stream is canceled, i.e. the StartReceiving
	// function is no longer running.
	<-coordinator.doneReceiving

	require.Less(t, time.Since(startTime), pingTimeout)

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}
