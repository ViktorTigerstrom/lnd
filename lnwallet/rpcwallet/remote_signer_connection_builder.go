package rpcwallet

import (
	"context"
	"errors"

	"github.com/lightningnetwork/lnd/lncfg"
)

// RemoteSignerBuilder creates instances of the RemoteSignerConnection
// interface, based on the provided configuration.
type RemoteSignerBuilder struct {
	cfg *lncfg.RemoteSigner
}

// NewRemoteSignerBuilder creates a new instance of the RemoteSignerBuilder.
func NewRemoteSignerBuilder(cfg *lncfg.RemoteSigner) *RemoteSignerBuilder {
	return &RemoteSignerBuilder{cfg}
}

// Build creates a new RemoteSigner instance. If the configuration specifies
// that an inbound remote signer should be used, a new OutboundConnection is
// created. If the configuration specifies that an outbound remote signer should
// be used, a new InboundConnection is created.
// The function returns the created RemoteSigner instance, and a cleanup
// function that should be called when the RemoteSigner is no longer needed.
func (b *RemoteSignerBuilder) Build(
	ctx context.Context) (RemoteSignerConnection, error) {

	// Validate that the configuration has valid values set.
	err := b.cfg.Validate()
	if err != nil {
		return nil, err
	}

	if !b.cfg.Enable {
		// This should be unreachable, but this is an extra sanity check
		return nil, errors.New("remote signer not enabled in " +
			"config")
	}

	// Create the remote signer based on the configuration.
	if !b.cfg.AllowInboundConnection {
		return NewOutboundConnection(
			ctx, b.cfg.ConnectionCfg,
		)
	}
	/*else {
		return nil, errors.New("allowing inbound connections to " +
			"the watch-only node not yet supported")
	} */

	inboundConnection := NewInboundConnection(
		b.cfg.RequestTimeout, b.cfg.Timeout,
	)

	return inboundConnection, nil
}
