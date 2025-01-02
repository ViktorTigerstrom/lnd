//go:build remotesignerrpc
// +build remotesignerrpc

package remotesignerrpc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/macaroons"
	"google.golang.org/grpc"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	// subServerName is the name of the sub rpc server. We'll use this name
	// to register ourselves, and we also require that the main
	// SubServerConfigDispatcher instance recognize it as the name of our
	// RPC service.
	subServerName = "RemoteSignerRPC"
)

var (
	// ErrServerShuttingDown is returned when the server is shutting down.
	ErrServerShuttingDown = errors.New("server shutting down")

	// macaroonOps are the set of capabilities that our minted macaroon (if
	// it doesn't already exist) will have.
	// TODO: Add real perms
	macaroonOps = []bakery.Op{
		{
			Entity: "invoices",
			Action: "write",
		},
		{
			Entity: "invoices",
			Action: "read",
		},
	}

	// macPermissions maps RPC calls to the permissions they require.
	// TODO: Add real perms
	macPermissions = map[string][]bakery.Op{
		"/remotesignerrpc.RemoteSigner/WhitelistAddress": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/remotesignerrpc.RemoteSigner/WhitelistedAddresses": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/remotesignerrpc.RemoteSigner/RemoveWhitelistedAddress": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/remotesignerrpc.RemoteSigner/WhitelistPaymentHash": {{
			Entity: "invoices",
			Action: "write",
		}},
		"/remotesignerrpc.RemoteSigner/WhitelistedPaymentHashes": {{
			Entity: "invoices",
			Action: "read",
		}},
		"/remotesignerrpc.RemoteSigner/RemoveWhitelistedPaymentHash": {{
			Entity: "invoices",
			Action: "write",
		}},
	}

	// DefaultInvoicesMacFilename is the default name of the invoices
	// macaroon that we expect to find via a file handle within the main
	// configuration file in this package.
	// TODO: Add real macfile
	DefaultInvoicesMacFilename = "invoices.macaroon"
)

// ServerShell is a shell struct holding a reference to the actual sub-server.
// It is used to register the gRPC sub-server with the root server before we
// have the necessary dependencies to populate the actual sub-server.
type ServerShell struct {
	RemoteSignerServer
}

// Server is a sub-server of the main RPC server: the invoices RPC. This sub
// RPC server allows external callers to access the status of the invoices
// currently active within lnd, as well as configuring it at runtime.
type Server struct {
	injected int32 // To be used atomically.

	// Required by the grpc-gateway/v2 library for forward compatibility.
	UnimplementedRemoteSignerServer

	quit chan struct{}

	cfg *Config
}

// A compile time check to ensure that Server fully implements the
// InvoicesServer gRPC service.
var _ RemoteSignerServer = (*Server)(nil)

// New returns a new instance of the invoicesrpc Invoices sub-server. We also
// return the set of permissions for the macaroons that we may create within
// this method. If the macaroons we need aren't found in the filepath, then
// we'll create them on start up. If we're unable to locate, or create the
// macaroons we need, then we'll return with an error.
func New() (*Server, lnrpc.MacaroonPerms, error) {
	server := &Server{
		cfg:  &Config{},
		quit: make(chan struct{}, 1),
	}

	return server, macPermissions, nil
}

// Stop signals any active goroutines for a graceful closure.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Stop() error {
	close(s.quit)

	return nil
}

// InjectDependencies populates the sub-server's dependencies. If the
// finalizeDependencies boolean is true, then the sub-server will finalize its
// dependencies and return an error if any required dependencies are missing.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) InjectDependencies(
	configRegistry lnrpc.SubServerConfigDispatcher,
	finalizeDependencies bool) error {

	if finalizeDependencies && atomic.AddInt32(&s.injected, 1) != 1 {
		return lnrpc.ErrDependenciesFinalized
	}

	cfg, err := getConfig(configRegistry, finalizeDependencies)
	if err != nil {
		return err
	}

	if finalizeDependencies {
		s.cfg = cfg

		return nil
	}

	// If the path of the invoices macaroon wasn't specified, then we'll
	// assume that it's found at the default network directory.
	macFilePath := filepath.Join(
		cfg.NetworkDir, DefaultInvoicesMacFilename,
	)

	// Now that we know the full path of the invoices macaroon, we can
	// check to see if we need to create it or not. If stateless_init is set
	// then we don't write the macaroons.
	if cfg.MacService != nil && !cfg.MacService.StatelessInit &&
		!lnrpc.FileExists(macFilePath) {

		log.Infof("Baking macaroons for invoices RPC Server at: %v",
			macFilePath)

		// At this point, we know that the invoices macaroon doesn't
		// yet, exist, so we need to create it with the help of the
		// main macaroon service.
		invoicesMac, err := cfg.MacService.NewMacaroon(
			context.Background(), macaroons.DefaultRootKeyID,
			macaroonOps...,
		)
		if err != nil {
			return err
		}
		invoicesMacBytes, err := invoicesMac.M().MarshalBinary()
		if err != nil {
			return err
		}
		err = os.WriteFile(macFilePath, invoicesMacBytes, 0644)
		if err != nil {
			_ = os.Remove(macFilePath)
			return err
		}
	}

	s.cfg = cfg

	return nil
}

// Name returns a unique string representation of the sub-server. This can be
// used to identify the sub-server and also de-duplicate them.
//
// NOTE: This is part of the lnrpc.SubServer interface.
func (s *Server) Name() string {
	return subServerName
}

// RegisterWithRootServer will be called by the root gRPC server to direct a sub
// RPC server to register itself with the main gRPC root server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRootServer(grpcServer *grpc.Server) error {
	// We make sure that we register it with the main gRPC server to ensure
	// all our methods are routed properly.
	RegisterRemoteSignerServer(grpcServer, r)

	log.Debugf("Invoices RPC server successfully registered with root " +
		"gRPC server")

	return nil
}

// RegisterWithRestServer will be called by the root REST mux to direct a sub
// RPC server to register itself with the main REST mux server. Until this is
// called, each sub-server won't be able to have requests routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) RegisterWithRestServer(ctx context.Context,
	mux *runtime.ServeMux, dest string, opts []grpc.DialOption) error {

	// We make sure that we register it with the main REST server to ensure
	// all our methods are routed properly.
	err := RegisterRemoteSignerHandlerFromEndpoint(ctx, mux, dest, opts)
	if err != nil {
		log.Errorf("Could not register Invoices REST server "+
			"with root REST server: %v", err)
		return err
	}

	log.Debugf("Invoices REST server successfully registered with " +
		"root REST server")
	return nil
}

// CreateSubServer creates an instance of the sub-server, and returns the
// macaroon permissions that the sub-server wishes to pass on to the root server
// for all methods routed towards it.
//
// NOTE: This is part of the lnrpc.GrpcHandler interface.
func (r *ServerShell) CreateSubServer() (
	lnrpc.SubServer, lnrpc.MacaroonPerms, error) {

	subServer, macPermissions, err := New()
	if err != nil {
		return nil, nil, err
	}

	r.RemoteSignerServer = subServer
	return subServer, macPermissions, nil
}

// WhitelistAddress adds an address to the whitelist. If the address is already
// whitelisted, this call will fail.
func (s *Server) WhitelistAddress(ctx context.Context,
	arg *WhitelistAddressRequest) (*WhitelistAddressResp, error) {

	err := s.cfg.RemoteSignerDB.InsertWhitelistedAddress(
		ctx, arg.Address, arg.Amount,
	)
	if err != nil {
		return nil, err
	}

	return &WhitelistAddressResp{}, nil
}

// WhitelistedAddresses lists the currently whitelisted addresses.
func (s *Server) WhitelistedAddresses(ctx context.Context,
	_ *WhitelistedAddressesRequest) (*WhitelistedAddressesResp, error) {

	addresses, err := s.cfg.RemoteSignerDB.ListWhitelistedAddresses(ctx)
	if err != nil {
		return nil, err
	}

	return &WhitelistedAddressesResp{Addresses: addresses}, nil
}

// RemoveWhitelistedAddress removes an address from the whitelist.
func (s *Server) RemoveWhitelistedAddress(ctx context.Context,
	arg *RemoveWhitelistAddressRequest) (
	*RemoveWhitelistAddressResp, error) {

	removed, err := s.cfg.RemoteSignerDB.DeleteWhitelistedAddress(
		ctx, arg.Address,
	)
	if err != nil {
		return nil, err
	}

	return &RemoveWhitelistAddressResp{Removed: removed}, nil
}

// WhitelistPaymentHash adds an payment hash to the whitelist. If the payment
// hash is already whitelisted, this call will fail.
func (s *Server) WhitelistPaymentHash(ctx context.Context,
	arg *WhitelistPaymentHashRequest) (
	*WhitelistPaymentHashResp, error) {

	err := s.cfg.RemoteSignerDB.InsertWhitelistedPaymentHash(
		ctx, arg.PaymentHash, arg.Amount,
	)
	if err != nil {
		return nil, err
	}

	return &WhitelistPaymentHashResp{}, nil
}

// WhitelistedPaymentHashes lists the currently whitelisted payment hashes.
func (s *Server) WhitelistedPaymentHashes(ctx context.Context,
	arg *WhitelistedPaymentHashesRequest) (
	*WhitelistedPaymentHashesResp, error) {

	paymentHashes, err := s.cfg.RemoteSignerDB.ListWhitelistedPaymentHashes(
		ctx,
	)
	if err != nil {
		return nil, err
	}

	return &WhitelistedPaymentHashesResp{PaymentHashes: paymentHashes}, nil
}

// RemoveWhitelistedPaymentHash removes a payment hash from the whitelist.
func (s *Server) RemoveWhitelistedPaymentHash(ctx context.Context,
	arg *RemoveWhitelistPaymentHashRequest) (
	*RemoveWhitelistPaymentHashResp, error) {

	removed, err := s.cfg.RemoteSignerDB.DeleteWhitelistedPaymentHash(
		ctx, arg.PaymentHash,
	)
	if err != nil {
		return nil, err
	}

	return &RemoveWhitelistPaymentHashResp{Removed: removed}, nil
}
