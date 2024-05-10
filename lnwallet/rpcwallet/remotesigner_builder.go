package rpcwallet

import (
	"errors"

	"github.com/lightningnetwork/lnd/lncfg"
)

type RemoteSignerBuilder struct {
	cfg *lncfg.RemoteSigner
}

// NewRemoteSignerBuilder creates a new instance of the RemoteSignerBuilder.
func NewRemoteSignerBuilder(cfg *lncfg.RemoteSigner) *RemoteSignerBuilder {
	return &RemoteSignerBuilder{cfg}
}

// Build creates a new instance of the RemoteSigner.
func (b *RemoteSignerBuilder) Build() (RemoteSigner, func(), error) {
	if b.cfg == nil {
		return nil, nil, errors.New("remote signer config is nil")
	}

	err := b.cfg.Validate()
	if err != nil {
		return nil, nil, err
	}

	switch b.cfg.SignerType {
	case lncfg.DefaultInboundRemoteSignerType:
		return b.createStandardRemoteSigner()
	case lncfg.OutboundRemoteSignerType:
		return b.createReverseRemoteSigner()
	default:
		return nil, nil, errors.New("unknown remote signer type")
	}
}

func (b *RemoteSignerBuilder) createStandardRemoteSigner() (
	*StandardRemoteSigner, func(), error) {

	return NewStandardRemoteSigner(
		b.cfg.RPCHost, b.cfg.TLSCertPath, b.cfg.MacaroonPath,
		b.cfg.Timeout,
	)
}

func (b *RemoteSignerBuilder) createReverseRemoteSigner() (
	*ReverseRemoteSigner, func(), error) {

	reverseRemoteSigner, cleanUp := NewReverseRemoteSigner(
		b.cfg.RequestTimeout, b.cfg.Timeout,
	)

	return reverseRemoteSigner, cleanUp, nil
}
