//go:build signrpc
// +build signrpc

package signrpc

import (
	"fmt"

	"github.com/lightningnetwork/lnd/lnrpc"
)

// createNewSubServer is a helper method that will create the new signer sub
// server given the main config dispatcher method. If we're unable to find the
// config that is meant for us in the config dispatcher, then we'll exit with
// an error.
func createNewSubServer(configRegistry lnrpc.SubServerConfigDispatcher) (
	*Server, lnrpc.MacaroonPerms, error) {

	config, err := getConfig(configRegistry, false)
	if err != nil {
		return nil, nil, err
	}

	return New(config)
}

func getConfig(configRegistry lnrpc.SubServerConfigDispatcher,
	enforceDependencies bool) (*Config, error) {
	// We'll attempt to look up the config that we expect, according to our
	// SubServerName name. If we can't find this, then we'll exit with an
	// error, as we're unable to properly initialize ourselves without this
	// config.
	subServerConf, ok := configRegistry.FetchConfig(SubServerName)
	if !ok {
		return nil, fmt.Errorf("unable to find config for subserver "+
			"type %s", SubServerName)
	}

	// Now that we've found an object mapping to our service name, we'll
	// ensure that it's the type we need.
	config, ok := subServerConf.(*Config)
	if !ok {
		return nil, fmt.Errorf("wrong type of config for subserver "+
			"%s, expected %T got %T", SubServerName, &Config{},
			subServerConf)
	}

	if enforceDependencies {
		if err := verifyDependencies(config); err != nil {
			return nil, err
		}
	}

	return config, nil
}

func verifyDependencies(config *Config) error {
	// Before we try to make the new signer service instance, we'll perform
	// some sanity checks on the arguments to ensure that they're usable.

	switch {
	// If the macaroon service is set (we should use macaroons), then
	// ensure that we know where to look for them, or create them if not
	// found.
	case config.MacService != nil && config.NetworkDir == "":
		return fmt.Errorf("NetworkDir must be set to create Signrpc")
	case config.Signer == nil:
		return fmt.Errorf("Signer must be set to create Signrpc")
	}

	return nil
}

func init() {
	subServer := &lnrpc.SubServerDriver{
		SubServerName: SubServerName,
		NewGrpcHandler: func() lnrpc.GrpcHandler {
			return &ServerShell{}
		},
	}

	// If the build tag is active, then we'll register ourselves as a
	// sub-RPC server within the global lnrpc package namespace.
	if err := lnrpc.RegisterSubServer(subServer); err != nil {
		panic(fmt.Sprintf("failed to register sub server driver '%s': %v",
			SubServerName, err))
	}
}
