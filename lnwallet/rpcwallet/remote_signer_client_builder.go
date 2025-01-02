package rpcwallet

import (
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/validator"
)

type RscBuilder = RemoteSignerClientBuilder

// RemoteSignerClientBuilder creates instances of the RemoteSignerClient
// interface, based on the provided configuration.
type RemoteSignerClientBuilder struct {
	watchOnlyCfg  *lncfg.WatchOnlyNode
	validationCfg *lncfg.Validation
}

// NewRemoteSignerClientBuilder creates a new instance of the
// RemoteSignerClientBuilder.
func NewRemoteSignerClientBuilder(woCfg *lncfg.WatchOnlyNode,
	vCfg *lncfg.Validation) *RscBuilder {

	return &RscBuilder{woCfg, vCfg}
}

// Build creates a new RemoteSignerClient instance. If the configuration enables
// an outbound remote signer, a new OutboundRemoteSignerClient will be returned.
// Else, a NoOpClient will be returned.
func (b *RscBuilder) Build(subServers []lnrpc.SubServer,
	remoteSignerDB validator.RemoteSignerDB,
	network *chaincfg.Params) (RemoteSignerClient, error) {

	var (
		walletServer walletrpc.WalletKitServer
		signerServer signrpc.SignerServer
	)

	for _, subServer := range subServers {
		if server, ok := subServer.(walletrpc.WalletKitServer); ok {
			walletServer = server
		}

		if server, ok := subServer.(signrpc.SignerServer); ok {
			signerServer = server
		}
	}

	// Check if we have all servers and if the configuration enables an
	// outbound remote signer. If not, return a NoOpClient.
	if walletServer == nil || signerServer == nil {
		log.Debugf("Using a No Op remote signer client due to " +
			"current sub-server support")

		return &NoOpClient{}, nil
	}

	if !b.watchOnlyCfg.Enable {
		log.Debugf("Using a No Op remote signer client due to the " +
			"current watchonly config")

		return &NoOpClient{}, nil
	}

	rsValidator, err := b.buildValidator(remoteSignerDB, network)
	if err != nil {
		return &NoOpClient{}, err
	}

	// An outbound remote signer client is enabled, therefore we create one.
	log.Debugf("Using an outbound remote signer client")

	streamFeeder := NewStreamFeeder(b.watchOnlyCfg.ConnectionCfg)

	rsClient, err := NewOutboundClient(
		walletServer, signerServer, streamFeeder, rsValidator,
		b.watchOnlyCfg.RequestTimeout,
	)
	if err != nil {
		return &NoOpClient{}, err
	}

	return rsClient, err
}

func (b *RscBuilder) buildValidator(remoteSignerDB validator.RemoteSignerDB,
	network *chaincfg.Params) (validator.Validation, error) {

	switch b.validationCfg.Mode {
	case lncfg.HalfValidationMode:
		return validator.NewHalfValidator(
			remoteSignerDB, network, b.validationCfg.AllowFunding,
		), nil
	case lncfg.BlindValidationMode:
		return validator.NewBlindValidator(remoteSignerDB, network), nil
	default:
		return nil, fmt.Errorf("unsupported validation mode: %s",
			b.validationCfg.Mode)
	}
}
