package rpcwallet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lntest/wait"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// mockSCStream is a mock implementation of the
// walletrpc.WalletKit_SignCoordinatorStreamsServer stream interface.
type mockSCStream struct {
	// sendChan is used to simulate requests sent over the stream from the
	// sign coordinator to the remote signer.
	sendChan chan *walletrpc.SignCoordinatorRequest

	// recvChan is used to simulate responses sent over the stream from the
	// remote signer to the sign coordinator.
	recvChan chan *walletrpc.SignCoordinatorResponse

	// cancelChan is used to simulate a canceled stream.
	cancelChan chan struct{}

	ctx context.Context
}

// newMockSCStream creates a new mock stream.
func newMockSCStream() *mockSCStream {
	return &mockSCStream{
		sendChan:   make(chan *walletrpc.SignCoordinatorRequest, 10),
		recvChan:   make(chan *walletrpc.SignCoordinatorResponse, 10),
		cancelChan: make(chan struct{}),
		ctx:        context.Background(),
	}
}

// Send simulates a sent request from the sign coordinator to the remote signer
// over the mock stream.
func (ms *mockSCStream) Send(req *walletrpc.SignCoordinatorRequest) error {
	ms.sendChan <- req
	return nil
}

// Recv simulates a received response from the remote signer to the sign
// coordinator over the mock stream.
func (ms *mockSCStream) Recv() (*walletrpc.SignCoordinatorResponse, error) {
	select {
	case resp := <-ms.recvChan:
		return resp, nil
	case <-ms.cancelChan:
		// To simulate a canceled stream, we return an error when the
		// cancelChan is closed.
		return nil, ErrStreamCanceled
	}
}

// Mock implementations of various WalletKit_SignCoordinatorStreamsServer
// methods.
func (ms *mockSCStream) RecvMsg(msg any) error        { return nil }
func (ms *mockSCStream) SendHeader(metadata.MD) error { return nil }
func (ms *mockSCStream) SendMsg(m any) error          { return nil }
func (ms *mockSCStream) SetHeader(metadata.MD) error  { return nil }
func (ms *mockSCStream) SetTrailer(metadata.MD)       {}

// Context returns the context of the mock stream.
func (ms *mockSCStream) Context() context.Context {
	return ms.ctx
}

// Cancel closes the cancelChan to simulate a canceled stream.
func (ms *mockSCStream) Cancel() {
	close(ms.cancelChan)
}

// Helper function to simulate responses sent over the mock stream.
func (ms *mockSCStream) sendResponse(resp *walletrpc.SignCoordinatorResponse) {
	ms.recvChan <- resp
}

// setupSignCoordinator sets up a new SignCoordinator instance with a mock
// stream to simulate communication with a remote signer. It also simulates the
// handshake between the sign coordinator and the remote signer.
func setupSignCoordinator(t *testing.T) (*SignCoordinator, *mockSCStream,
	chan error) {

	stream := newMockSCStream()
	coordinator := NewSignCoordinator(2*time.Second, 3*time.Second)

	errChan := make(chan error)
	go func() {
		err := coordinator.Run(stream)
		if err != nil {
			errChan <- err
		}
	}()

	// Simulate a handshake registration message sent from the remote signer
	// to the sign coordinator.
	regType := &walletrpc.SignCoordinatorResponse_SignerRegistration{
		SignerRegistration: true,
	}

	registrationMsg := &walletrpc.SignCoordinatorResponse{
		RefRequestId:     1, // Request ID is always 1 for registration.
		SignResponseType: regType,
	}

	stream.sendResponse(registrationMsg)

	// Ensure that the sign coordinator responds with a registration
	// complete message.
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

// getRequest is a helper function to get a request sent that has been sent from
// the sign coordinator over the mock stream.
func getRequest(s *mockSCStream) (*walletrpc.SignCoordinatorRequest, error) {
	select {
	case req := <-s.sendChan:
		return req, nil
	case <-time.After(time.Second):
		return nil, ErrRequestTimeout
	}
}

// TestSignCoordinator_PingResponse tests that the sign coordinator correctly
// sends a Ping request to the remote signer and handles the received a Pong
// response correctly.
func TestSignCoordinator_PingResponse(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request in a goroutine so that we can pickup the request
	// sent over the mock stream, and respond accordingly.
	go func() {
		defer wg.Done()

		// The Ping method will return true if the response is a Pong
		// response.
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	// Get the request sent over the mock stream.
	req, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now we simulate the response from the remote signer by sending a Pong
	// response over the mock stream.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Wait for the goroutines to finish, which should only happen after the
	// requests have had their expected responses processed.
	wg.Wait()

	// Verify the responses map is empty after all responses are received
	// to ensure that no memory leaks occur.
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_ConcurrentPingResponses tests that the sign coordinator
// correctly handles concurrent Ping requests and responses, and that the order
// which responses are sent back over the stream doesn't matter.
func TestSignCoordinator_ConcurrentPingResponses(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup

	// Let's first start by sending two concurrent Ping requests, and send
	// the respective responses back in order.
	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)

		require.NoError(t, err)
		require.True(t, success)
	}()

	// Get the first request sent over the mock stream.
	req1, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req1.GetRequestId())
	require.True(t, req1.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now we send the second Ping request.
	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)

		require.NoError(t, err)
		require.True(t, success)
	}()

	// Get the second request sent over the mock stream.
	req2, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(3), req2.GetRequestId())
	require.True(t, req2.GetPing())

	// Verify that the coordinator now has correctly set up a two response
	// channels for the Ping requests with their specific request IDs.
	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	// Send responses for both Ping requests in order.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 3,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Wait for the goroutines to finish, which should only happen after the
	// requests have had their expected responses processed.
	wg.Wait()

	// Now let's verify that the sign coordinator can correctly process
	// responses that are sent back in a different order than the requests
	// were sent.

	// Send a new set of concurrent Ping requests.
	wg.Add(1)

	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	req3, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, uint64(4), req3.GetRequestId())
	require.True(t, req3.GetPing())

	// Verify that the coordinator has removed the response channels for the
	// previous Ping requests, and set up a new one for the new request.
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

	require.Equal(t, uint64(5), req4.GetRequestId())
	require.True(t, req4.GetPing())

	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(5)]
	require.True(t, ok)

	// Send the responses back in reverse order.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 5,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 4,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Wait for the goroutines to finish, which should only happen after the
	// requests have had their expected responses processed.
	wg.Wait()

	// Verify the responses map is empty after all responses are received
	// to ensure that no memory leaks occur.
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_PingTimeout tests that the sign coordinator correctly
// handles a Ping request that times out.
func TestSignCoordinator_PingTimeout(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	// Simulate a Ping request that times out
	_, err := coordinator.Ping(1 * time.Second)
	require.Equal(t, ErrRequestTimeout, err)

	// Verify that the responses map is empty after the timeout
	require.Empty(t, coordinator.responses)

	// Now lets simulate that the response is sent back after the request
	// has timed out.
	req, err := getRequest(stream)
	require.NoError(t, err)

	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Verify that the responses map still remains empty, as responses for
	// timed out requests are ignored.
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_PingTimeoutByOneRequest tests that the sign coordinator
// correctly handles a Ping request that times out, while another Ping request
// is still pending which then receives a response.
func TestSignCoordinator_PingTimeoutByOneRequest(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	timeoutChan := make(chan struct{}, 1)

	// Send a Ping request that is expected to time out.
	go func() {
		defer wg.Done()

		// Note that the timeout is set to 1 seconds.
		success, err := coordinator.Ping(1 * time.Second)
		require.Equal(t, ErrRequestTimeout, err)
		require.False(t, success)

		// Signal that the request has timed out.
		close(timeoutChan)
	}()

	// Get the request sent over the mock stream.
	req1, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req1.GetRequestId())
	require.True(t, req1.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now let's send another Ping request that will receive a response.
	wg.Add(1)

	go func() {
		defer wg.Done()

		// Note that the timeout is set to 2 seconds, and will therefore
		// time out later than the first request.
		success, err := coordinator.Ping(2 * time.Second)
		require.NoError(t, err)
		require.True(t, success)
	}()

	// Get the second request sent over the mock stream.
	req2, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(3), req2.GetRequestId)
	require.True(t, req2.GetPing())

	// Verify that the coordinator has correctly set up a two response
	// channels for the Ping requests with their specific request IDs.
	require.Len(t, coordinator.responses, 2)
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	// Now let's wait for the first request to time out.
	<-timeoutChan

	// Ensure that this leads to the sign coordinator removing the response
	// channel for the timed out request.
	require.Len(t, coordinator.responses, 1)

	// The second request should still be pending, so the responses map
	// should contain the response channel for the second request.
	_, ok = coordinator.responses[uint64(3)]
	require.True(t, ok)

	// Send responses for the second Ping request.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 3,
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Wait for the goroutines to finish, which should only happen after the
	// second request has had its expected response processed.
	wg.Wait()

	// Verify the responses map is empty after all responses have been
	// handled, to ensure that no memory leaks occur.
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_IncorrectResponseRequestId tests that the sign
// coordinator correctly ignores responses with an unknown request ID.
func TestSignCoordinator_IncorrectResponseRequestId(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup

	// Save the start time of the test.
	startTime := time.Now()
	pingTimeout := 2 * time.Second

	wg.Add(1)

	// Send a Ping request that times out in 2 second.
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(pingTimeout)
		require.Equal(t, ErrRequestTimeout, err)
		require.False(t, success)
	}()

	// Get the request sent over the mock stream.
	req, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now lets send a response with an another request ID than the Ping
	// request.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 3, // Incorrect request ID
		SignResponseType: &walletrpc.SignCoordinatorResponse_Pong{
			Pong: true,
		},
	})

	// Ensure that the response is ignored, and that the responses map still
	// contains the response channel for the Ping request until it times
	// out. We allow a small margin of error to account for the time it
	// takes to execute the Invariant function.
	err = wait.Invariant(func() bool {
		correctLen := len(coordinator.responses) == 1
		_, ok = coordinator.responses[uint64(2)]

		return correctLen && ok
	}, pingTimeout-time.Since(startTime)-100*time.Millisecond)
	require.NoError(t, err)

	// Wait for the goroutines to finish, which should only happen after the
	// request has timed out and verified the error.
	wg.Wait()

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_SignerError tests that the sign coordinator correctly
// handles a SignerError response from the remote signer.
func TestSignCoordinator_SignerError(t *testing.T) {
	t.Parallel()

	coordinator, stream, _ := setupSignCoordinator(t)

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request that will receive a SignerError response.
	go func() {
		defer wg.Done()

		success, err := coordinator.Ping(1 * time.Second)
		// Ensure that the result from the Ping method is an error,
		// which is the expected result when a SignerError response is
		// received.
		require.Equal(t, "mock error", err.Error())
		require.False(t, success)
	}()

	// Get the request sent over the mock stream.
	req, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now lets send a SignerError response instead of a Pong back over the
	// mock stream.
	stream.sendResponse(&walletrpc.SignCoordinatorResponse{
		RefRequestId: 2,
		SignResponseType: &walletrpc.SignCoordinatorResponse_SignerError{
			SignerError: &walletrpc.SignerError{
				Error: "mock error",
			},
		},
	})

	// Wait for the goroutines to finish, which should only happen after the
	// request has had its expected response processed.
	wg.Wait()

	// Verify the responses map is empty after all responses have been
	// processed, to ensure that no memory leaks occur.
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_SignerErrorWithNoRequest tests that the sign coordinator
// correctly stops processing responses any pending requests when the sign
// coordinator is stopped.
func TestSignCoordinator_StopCoordinator(t *testing.T) {
	t.Parallel()

	coordinator, stream, runErrChan := setupSignCoordinator(t)

	pingTimeout := 3 * time.Second
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request with a long timeout to ensure that the request
	// will not time out before the coordinator is stopped.
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(pingTimeout)
		require.Equal(t, ErrShuttingDown, err)
		require.False(t, success)
	}()

	// Get the request sent over the mock stream.
	req, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
	require.Len(t, coordinator.responses, 1)
	_, ok := coordinator.responses[uint64(2)]
	require.True(t, ok)

	// Now lets stop the sign coordinator.
	wg.Add(1)
	go func() {
		defer wg.Done()

		coordinator.Stop()
	}()

	// When the coordinator is stopped, the Run function will return an
	// error that gets sent over the runErrChan.
	err = <-runErrChan

	// Ensure that the Run function returned the expected error that lnd is
	// shutting down.
	require.Equal(t, ErrShuttingDown, err)

	// As the coordinator Run function returned the ErrShuttingDown error,
	// the lnd would normally cancel the stream. We simulate this by
	// calling the Cancel method on the mock stream.
	stream.Cancel()

	// Ensure that both the Ping request goroutine and the sign coordinator
	// Stop goroutine have finished.
	wg.Wait()

	// Ensure that the Ping request goroutine returned before the timeout
	// was reached, which indicates that the request was canceled because
	// the sign coordinator was stopped.
	require.Less(t, time.Since(startTime), pingTimeout)

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}

// TestSignCoordinator_RemoteSignerDisconnects tests that the sign coordinator
// correctly handles that the remote signer disconnects, which closes the
// stream.
func TestSignCoordinator_RemoteSignerDisconnects(t *testing.T) {
	t.Parallel()

	coordinator, stream, runErrChan := setupSignCoordinator(t)

	pingTimeout := 3 * time.Second
	startTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(1)

	// Send a Ping request with a long timeout to ensure that the request
	// will not time out before the remote signer disconnects.
	go func() {
		defer wg.Done()
		success, err := coordinator.Ping(pingTimeout)
		require.Equal(t, ErrNotConnected, err)
		require.False(t, success)
	}()

	// Get the request sent over the mock stream.
	req, err := getRequest(stream)
	require.NoError(t, err)

	// Verify that the request has the expected request ID and that it's a
	// Ping request.
	require.Equal(t, uint64(2), req.GetRequestId())
	require.True(t, req.GetPing())

	// Verify that the coordinator has correctly set up a single response
	// channel for the Ping request with the specific request ID.
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

	// Ensure that the Ping request goroutine has finished.
	wg.Wait()

	// Verify that the coordinator signals that it's done receiving
	// responses after the stream is canceled, i.e. the StartReceiving
	// function is no longer running.
	<-coordinator.doneReceiving

	// Ensure that the Ping request goroutine returned before the timeout
	// was reached, which indicates that the request was canceled because
	// the remote signer disconnected.
	require.Less(t, time.Since(startTime), pingTimeout)

	// Verify the responses map is empty after all responses are received
	require.Empty(t, coordinator.responses)
}
