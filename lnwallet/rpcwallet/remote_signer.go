package rpcwallet

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
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

// InboundRemoteSigner references a remote signer that allows a watch-only node
// to connect to it via a single inbound GRPC connection.
type InboundRemoteSigner struct {
	// Embedded signrpc.SignerClient and walletrpc.WalletKitClient to
	// implement the RemoteSigner interface.
	signrpc.SignerClient

	walletrpc.WalletKitClient

	// The host:port of the remote signer node.
	rpcHost string

	// The path to the TLS certificate of the remote signer node.
	tlsCertPath string

	// The path to the macaroon of the remote signer node.
	macaroonPath string

	// The timeout for the connection to the remote signer node.
	timeout time.Duration
}

// NewInboundRemoteSigner creates a new InboundRemoteSigner instance.
func NewInboundRemoteSigner(rpcHost string, tlsCertPath string,
	macaroonPath string,
	timeout time.Duration) (*InboundRemoteSigner, func(), error) {

	rpcConn, err := connect(rpcHost, tlsCertPath, macaroonPath, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to the remote "+
			"signing node through RPC: %v", err)
	}

	cleanUp := func() {
		rpcConn.Close()
	}

	remoteSigner := &InboundRemoteSigner{
		SignerClient:    signrpc.NewSignerClient(rpcConn),
		WalletKitClient: walletrpc.NewWalletKitClient(rpcConn),
		timeout:         timeout,
	}

	return remoteSigner, cleanUp, nil
}

// Run feeds lnd with the incoming stream that an inbound remote signer has set
// up, and blocks until the stream is closed. Lnd can then proceed to send any
// requests to the remote signer through the stream.
//
// NOTE: This is part of the RemoteSigner interface.
func (*InboundRemoteSigner) Run(
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error {

	// If lnd has been configured to use an inbound remote signer, it should
	// not allow an outbound remote signer to connect.
	return errors.New("incorrect remote signer type used")
}

// Ready blocks and returns nil when the remote signer is ready to accept
// requests.
//
// NOTE: This is part of the RemoteSigner interface.
func (r *InboundRemoteSigner) Ready() error {
	// The inbound remote signer is ready as soon we have connected to the
	// remote signer node in the constructor. Therefore, we always return
	// nil here to signal that we are ready.
	return nil
}

// Ping verifies that the remote signer is still responsive.
//
// NOTE: This is part of the RemoteSigner interface.
func (r *InboundRemoteSigner) Ping(timeout time.Duration) error {
	conn, err := connect(
		r.rpcHost, r.tlsCertPath, r.macaroonPath,
		timeout,
	)
	if err != nil {
		return fmt.Errorf("error connecting to the remote "+
			"signing node through RPC: %v", err)
	}

	defer func() {
		err = conn.Close()
		if err != nil {
			log.Warnf("Failed to close health check "+
				"connection to remote signing node: %v",
				err)
		}
	}()

	return nil
}

// Timeout returns the set connection timeout for the remote signer.
//
// NOTE: This is part of the RemoteSigner interface.
func (r *InboundRemoteSigner) Timeout() time.Duration {
	return r.timeout
}

// A compile time assertion to ensure InboundRemoteSigner meets the
// RemoteSigner interface.
var _ RemoteSigner = (*InboundRemoteSigner)(nil)

// connect tries to establish an RPC connection to the given host:port with the
// supplied certificate and macaroon.
func connect(hostPort, tlsCertPath, macaroonPath string,
	timeout time.Duration) (*grpc.ClientConn, error) {

	certBytes, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, fmt.Errorf("error reading TLS cert file %v: %w",
			tlsCertPath, err)
	}

	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(certBytes) {
		return nil, fmt.Errorf("credentials: failed to append " +
			"certificate")
	}

	macBytes, err := os.ReadFile(macaroonPath)
	if err != nil {
		return nil, fmt.Errorf("error reading macaroon file %v: %w",
			macaroonPath, err)
	}
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, fmt.Errorf("error decoding macaroon: %w", err)
	}

	macCred, err := macaroons.NewMacaroonCredential(mac)
	if err != nil {
		return nil, fmt.Errorf("error creating creds: %w", err)
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(
			cp, "",
		)),
		grpc.WithPerRPCCredentials(macCred),
		grpc.WithBlock(),
	}
	ctxt, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := grpc.DialContext(ctxt, hostPort, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to RPC server: %w",
			err)
	}

	return conn, nil
}
