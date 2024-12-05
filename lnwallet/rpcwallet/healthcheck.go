package rpcwallet

import (
	"context"
	"time"
)

// HealthCheck returns a health check function for the given remote signing
// configuration.
func HealthCheck(rs RemoteSignerConnection, timeout time.Duration,
	ctx context.Context) func() error {

	return func() error {
		ctxt, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		err := rs.Ping(timeout, ctxt)
		if err != nil {
			log.Errorf("Remote signer health check failed: %v", err)

			return err
		}

		return nil
	}
}
