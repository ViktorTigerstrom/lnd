package lncfg

import (
	"fmt"
	"time"
)

const (
	// DefaultRemoteSignerRPCTimeout is the default connection timeout
	// that is used when connecting to the remote signer or watch-only node
	// through RPC.
	DefaultRemoteSignerRPCTimeout = 5 * time.Second

	// DefaultRequestTimeout is the default timeout used for requests to and
	// from the remote signer.
	DefaultRequestTimeout = 5 * time.Second

	// DefaultStartupTimeout is the default startup timeout used when the
	// watch-only node with signerrole 'watchonly-outbound' waits for the
	// remote signer to connect.
	DefaultStartupTimeout = 5 * time.Minute
)

// RemoteSigner holds the configuration options for how to connect to a remote
// signer. Only a watch-only node specifies this config.
//
//nolint:ll
type RemoteSigner struct {
	// Enable signals if this node is a watch-only node in a remote signer
	// setup.
	Enable bool `long:"enable" description:"Use a remote signer for signing any on-chain related transactions or messages. Only recommended if local wallet is initialized as watch-only. Remote signer must use the same seed/root key as the local watch-only wallet but must have private keys."`

	// AllowInboundConnection is true if the signer node will connect to this node.
	AllowInboundConnection bool `long:"allowinboundconnection" description:"Signals that we allow an inbound connection from a remote signer to this node."`

	// Options that apply regardless of mode.
	MigrateWatchOnly bool `long:"migrate-wallet-to-watch-only" description:"If a wallet with private key material already exists, migrate it into a watch-only wallet on first startup. WARNING: This cannot be undone! Make sure you have backed up your seed before you use this flag! All private keys will be purged from the wallet after first unlock with this flag!"`

	// Outbound mode options. When this node makes the connection to the
	// signer
	ConnectionCfg

	// Inbound options mode. When the signer is expected to connect to this
	// node.
	inboundWatchOnlyCfg
}

// DefaultRemoteSignerCfg returns the default RemoteSigner config.
func DefaultRemoteSignerCfg() *RemoteSigner {
	return &RemoteSigner{
		Enable:                 false,
		AllowInboundConnection: false,
		inboundWatchOnlyCfg: inboundWatchOnlyCfg{
			StartupTimeout: DefaultStartupTimeout,
		},
		ConnectionCfg: defaultConnectionCfg("remotesigner"),
	}
}

// Validate checks the values configured for our remote RPC signer.
func (r *RemoteSigner) Validate() error {
	if !r.Enable {
		return nil
	}

	if r.MigrateWatchOnly {
		return fmt.Errorf("remote signer: cannot turn on wallet " +
			"migration to watch-only if remote signing is not " +
			"enabled")
	}

	if r.AllowInboundConnection {
		if r.StartupTimeout < time.Second {
			return fmt.Errorf("remotesigner.startuptimeout of "+
				"%v is invalid, cannot be smaller than %v",
				r.Timeout, time.Second)
		}

		return nil
	}

	// Else, we are in outbound mode, so we verify the connection config.
	return r.ConnectionCfg.Validate()
}

// inboundWatchOnlyCfg holds the configuration options specific for watch-only
// nodes with the allowinboundconnection` option set.
//
//nolint:ll
type inboundWatchOnlyCfg struct {
	StartupTimeout time.Duration `long:"startuptimeout" description:"The time the watch-only node will wait for the remote signer to connect during startup. If the timeout expires before the remote signer connects, the watch-only node will shut down. Valid time units are {s, m, h}."`
}

// WatchOnlyNode holds the configuration options for how to connect to a watch
// only node. Only a signer node specifies this config.
//
//nolint:ll
type WatchOnlyNode struct {
	// Enable signals if this node a signer node and is expected to connect
	// to a watch-only node.
	Enable bool `long:"enable" description:"Signals that this node a signer node and is expected to connect to a watch-only node."`

	// How to connect to the watch only node.
	ConnectionCfg
}

// DefaultWatchOnlyNodeCfg returns the default WatchOnlyNode config.
func DefaultWatchOnlyNodeCfg() *WatchOnlyNode {
	return &WatchOnlyNode{
		Enable:        false,
		ConnectionCfg: defaultConnectionCfg("watchonlynode"),
	}
}

// Validate checks the values set in the WatchOnlyNode config are valid.
func (w *WatchOnlyNode) Validate() error {
	if !w.Enable {
		return nil
	}

	return w.ConnectionCfg.Validate()
}

// ConnectionCfg holds the configuration options required when setting up a
// connection to either a remote signer or watch-only node, depending on which
// side makes the outbound connection.
//
//nolint:ll
type ConnectionCfg struct {
	parentConfig   string
	RPCHost        string        `long:"rpchost" description:"The RPC host:port of the remote signer or watch-only node. For watch-only nodes with 'remotesigner.inbound' set to false (the default value if not specifically set), this should be set to the remote signer's RPC host:port. For remote signer nodes connecting to a watch-only node with 'remotesigner.inbound' set to true, this should be set to the watch-only node's RPC host:port."`
	MacaroonPath   string        `long:"macaroonpath" description:"The macaroon to use for authenticating with the remote signer or the watch-only node. For watch-only nodes with 'remotesigner.inbound' set to false (the default value if not specifically set), this should be set to the remote signer's macaroon. For remote signer nodes connecting to a watch-only node with 'remotesigner.inbound' set to true, this should be set to the watch-only node's macaroon."`
	TLSCertPath    string        `long:"tlscertpath" description:"The TLS certificate to use for establishing the remote signer's or watch-only node's identity. For watch-only nodes with 'remotesigner.inbound' set to false (the default value if not specifically set), this should be set to the remote signer's TLS certificate. For remote signer nodes connecting to a watch-only node with 'remotesigner.inbound' set to true, this should be set to the watch-only node's TLS certificate."`
	Timeout        time.Duration `long:"timeout" description:"The timeout for making the connection to the remote signer or watch-only node, depending on whether the node acts as a watch-only node or a signer. Valid time units are {s, m, h}."`
	RequestTimeout time.Duration `long:"requesttimeout" description:"The time we will wait when making requests to the remote signer or watch-only node, depending on whether the node acts as a watch-only node or a signer. Valid time units are {s, m, h}."`
}

// defaultConnectionCfg returns the default ConnectionCfg config.
func defaultConnectionCfg(parentConfig string) ConnectionCfg {
	return ConnectionCfg{
		parentConfig:   parentConfig,
		Timeout:        DefaultRemoteSignerRPCTimeout,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// Validate checks the values set in the ConnectionCfg config are valid.
func (c *ConnectionCfg) Validate() error {
	if c.Timeout < time.Millisecond {
		return fmt.Errorf("%s.timeout of %v is invalid, cannot be "+
			"smaller than %v", c.parentConfig, c.Timeout,
			time.Millisecond)
	}

	if c.RequestTimeout < time.Second {
		return fmt.Errorf("%s.requesttimeout of %v is invalid, cannot "+
			"be smaller than %v", c.parentConfig, c.Timeout,
			time.Second)
	}

	if c.RPCHost == "" {
		return fmt.Errorf("%s.rpchost must be set", c.parentConfig)
	}

	if c.MacaroonPath == "" {
		return fmt.Errorf("%s.macaroonpath must be set", c.parentConfig)
	}

	if c.TLSCertPath == "" {
		return fmt.Errorf("%s.tlscertpath must be set", c.parentConfig)
	}

	return nil
}
