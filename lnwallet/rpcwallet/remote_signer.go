package rpcwallet

import (
	"time"

	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

// RemoteSigner is an interface that abstracts the communication with a remote
// signer. It extends the signrpc.SignerClient and walletrpc.WalletKitClient
// interfaces, and adds some additional methods to manage the connection and
// verify the health of the remote signer.
type RemoteSigner interface {
	// RemoteSigner extends the signrpc.SignerClient
	signrpc.SignerClient

	// RemoteSigner extends the walletrpc.WalletKitClient
	walletrpc.WalletKitClient

	// Timeout returns the set connection timeout for the remote signer.
	Timeout() time.Duration

	// Ready blocks and returns nil when the remote signer is ready to
	// accept requests.
	Ready() error

	// Ping verifies that the remote signer is still responsive.
	Ping(timeout time.Duration) error

	// Run feeds lnd with the incoming stream that an outbound remote signer
	// has set up, and then blocks until the stream is closed. Lnd can then
	// proceed to send any requests to the remote signer through the stream.
	Run(stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error
}
