package rpcwallet

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/signcoordinator"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/macaroon.v2"
)

type RemoteSigner interface {
	// RemoteSigner extends the signrpc.SignerClient
	signrpc.SignerClient

	// RemoteSigner extends the walletrpc.WalletKitClient
	walletrpc.WalletKitClient

	// Timeout returns the set timeout used for the remote signer.
	Timeout() time.Duration

	Ready() error

	Ping(timeout time.Duration) error

	Run(stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error
}

type StandardRemoteSigner struct {
	signrpc.SignerClient

	walletrpc.WalletKitClient

	rpcHost string

	tlsCertPath string

	macaroonPath string

	timeout time.Duration
}

// Run implements RemoteSigner.
func (*StandardRemoteSigner) Run(
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error {

	return nil
}

// Ready implements RemoteSigner.
func (r *StandardRemoteSigner) Ready() error {
	// The remote signer is ready as soon we have connected to to the remote
	// signer node in the constructor. Therefore, we always return nil here
	// to signal that we are ready.
	return nil
}

// Ping implements RemoteSigner.
func (r *StandardRemoteSigner) Ping(timeout time.Duration) error {
	conn, err := connectRPC(
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

func NewStandardRemoteSigner(rpcHost string, tlsCertPath string,
	macaroonPath string,
	timeout time.Duration) (*StandardRemoteSigner, func(), error) {

	rpcConn, err := connectRPC(rpcHost, tlsCertPath, macaroonPath, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to the remote "+
			"signing node through RPC: %v", err)
	}

	cleanUp := func() {
		rpcConn.Close()
	}

	remoteSigner := &StandardRemoteSigner{
		SignerClient:    signrpc.NewSignerClient(rpcConn),
		WalletKitClient: walletrpc.NewWalletKitClient(rpcConn),
		timeout:         timeout,
	}

	return remoteSigner, cleanUp, nil
}

// Timeout implements RemoteSigner.
func (r *StandardRemoteSigner) Timeout() time.Duration {
	return r.timeout
}

var _ RemoteSigner = (*StandardRemoteSigner)(nil)

// connectRPC tries to establish an RPC connection to the given host:port with
// the supplied certificate and macaroon.
func connectRPC(hostPort, tlsCertPath, macaroonPath string,
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

type ReverseRemoteSigner struct {
	*signcoordinator.SignCoordinator

	rpcTimeout time.Duration
}

func NewReverseRemoteSigner(rpcTimeout time.Duration,
	connectionTimeout time.Duration) (*ReverseRemoteSigner, func()) {

	remoteSigner := &ReverseRemoteSigner{
		rpcTimeout: rpcTimeout,
	}

	remoteSigner.SignCoordinator = signcoordinator.NewSignCoordinator(
		rpcTimeout, connectionTimeout,
	)

	return remoteSigner, remoteSigner.Stop
}

// Timeout implements RemoteSigner.
func (r *ReverseRemoteSigner) Timeout() time.Duration {
	return r.rpcTimeout
}

// Ready implements RemoteSigner.
func (r *ReverseRemoteSigner) Ready() error {
	log.Infof("Waiting for the remote signer to connect")

	return r.SignCoordinator.WaitUntilConnected()
}

func (r *ReverseRemoteSigner) Ping(timeout time.Duration) error {
	pong, err := r.SignCoordinator.Ping(timeout)
	if err != nil {
		return fmt.Errorf("health check ping to remote signer "+
			"errored: %w", err)
	}

	if !pong {
		return fmt.Errorf("incorrect pong response from " +
			"remote signer for ping request in health check")
	}

	return nil
}

// Run implements RemoteSigner.
func (r *ReverseRemoteSigner) Run(
	stream walletrpc.WalletKit_SignCoordinatorStreamsServer) error {

	return r.SignCoordinator.Run(stream)
}

var _ RemoteSigner = (*ReverseRemoteSigner)(nil)
