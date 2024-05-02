package lncfg

import (
	"fmt"
	"time"
)

const (
	// DefaultRemoteSignerRPCTimeout is the default timeout that is used
	// when forwarding a request to the remote signer through RPC.
	DefaultRemoteSignerRPCTimeout = 5 * time.Second

	DefaultStandardRemoteSignerType = "standard"
	ReverseRemoteSignerType         = "reverse"
	SignerClientType                = "signer"
)

// RemoteSigner holds the configuration options for a remote RPC signer.
//
//nolint:lll
type RemoteSigner struct {
	Enable bool `long:"enable" description:"Use a remote signer for signing any on-chain related transactions or messages. Only recommended if local wallet is initialized as watch-only. Remote signer must use the same seed/root key as the local watch-only wallet but must have private keys."`
	//SignerType               string        `long:"signertype" description:"The type of remote signer to use, either 'standard' (default) or 'reverse'. 'standard' means that the remote signer node allows inbound connections, and the rpchost and tlscertpath arguments therefore need to also be set. 'reverse' means that the remote signer node only makes outbound connections." choice:"standard" choice:"reverse"`
	SignerType string `long:"signertype" description:"The type of remote signer to use, either 'standard' (default), 'reverse' or 'signer'. 'standard' means that the remote signer node allows inbound connections, and the rpchost and tlscertpath arguments therefore need to also be set. 'reverse' means that the remote signer node only makes outbound connections. 'signer' means that the lnd instance will act as the remote signer making the outbound connection to another lnd instance is running which has the 'reverse' signer_type set." choice:"standard" choice:"reverse" choice:"signer"`
	//RPCHost                  string        `long:"rpchost" description:"The remote signer's RPC host:port. This param will should only be set if signertype is set to 'standard'"`
	//MacaroonPath             string        `long:"macaroonpath" description:"The macaroon to use for authenticating with the remote signer. This param will should only be set if signertype is set to 'standard'"`
	//TLSCertPath              string        `long:"tlscertpath" description:"The TLS certificate to use for establishing the remote signer's identity. This param will should only be set if signertype is set to 'standard'"`
	RPCHost                  string        `long:"rpchost" description:"The remote signer's or watch-only node's RPC host:port. This param will should not be set signertype is set to 'reverse'"`
	MacaroonPath             string        `long:"macaroonpath" description:"The macaroon to use for authenticating with the remote signer or the watch-only node. This param will should not be set signertype is set to 'reverse'"`
	TLSCertPath              string        `long:"tlscertpath" description:"The TLS certificate to use for establishing the remote signer's or watch-only node's identity. This param will should not be set signertype is set to 'reverse'"`
	Timeout                  time.Duration `long:"timeout" description:"The timeout for connecting to and signing requests with the remote signer. Valid time units are {s, m, h}."`
	InboundConnectionTimeout time.Duration `long:"inboundconnectiontimeout" description:"The time we will wait for the reverse remote signer to connect to us after starting lnd. This param will should only be set if signertype is set to 'reverse'. Valid time units are {s, m, h}"`
	MigrateWatchOnly         bool          `long:"migrate-wallet-to-watch-only" description:"If a wallet with private key material already exists, migrate it into a watch-only wallet on first startup. WARNING: This cannot be undone! Make sure you have backed up your seed before you use this flag! All private keys will be purged from the wallet after first unlock with this flag!"`
}

// Validate checks the values configured for our remote RPC signer.
func (r *RemoteSigner) Validate() error {
	if !r.Enable {
		return nil
	}

	if r.SignerType == SignerClientType && r.Enable {
		return fmt.Errorf("remote signer: do not set " +
			"remotesigner.enable when signertype is set to " +
			"'signer'")
	}

	if r.Timeout < time.Millisecond {
		return fmt.Errorf("remote signer: timeout of %v is invalid, "+
			"cannot be smaller than %v", r.Timeout,
			time.Millisecond)
	}

	if r.MigrateWatchOnly && !r.Enable {
		return fmt.Errorf("remote signer: cannot turn on wallet " +
			"migration to watch-only if remote signing is not " +
			"enabled")
	}

	if r.SignerType == ReverseRemoteSignerType && r.RPCHost != "" {
		return fmt.Errorf("remote signer: the rpchost for the remote " +
			"signer should only be set if the signertype is set " +
			"to standard")
	}

	if r.SignerType == ReverseRemoteSignerType && r.MacaroonPath != "" {
		return fmt.Errorf("remote signer: the macaroonpath for the " +
			"remote signer should only be set if the signertype " +
			"is set to standard")
	}

	if r.SignerType == ReverseRemoteSignerType && r.TLSCertPath != "" {
		return fmt.Errorf("remote signer: the tlscertpath for the " +
			"remote signer should only be set if the signertype " +
			"is set to standard")
	}

	return nil
}
