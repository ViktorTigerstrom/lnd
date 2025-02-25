package validator

import (
	"context"

	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

type RemoteSignerDB interface {
	InsertWhitelistedAddress(ctx context.Context, address string,
		amount int64) error

	GetWhitelistedAddress(ctx context.Context,
		address string) (string, error)

	ListWhitelistedAddresses(ctx context.Context) ([]string, error)

	DeleteWhitelistedAddress(ctx context.Context,
		address string) (bool, error)

	InsertWhitelistedPaymentHash(ctx context.Context, paymentHash []byte,
		amount int64) error

	GetWhitelistedPaymentHash(ctx context.Context,
		paymentHash []byte) ([]byte, error)

	ListWhitelistedPaymentHashes(ctx context.Context) ([][]byte, error)

	DeleteWhitelistedPaymentHash(ctx context.Context,
		paymentHash []byte) (bool, error)
}

// Validation is an interface that abstracts the logic for implementing
// remote signing validation.
type Validation interface {
	// ValidatePSBT determines whether the provided SignPsbtRequest
	// should be signed or rejected, based on the validation rules
	// implemented by the Validator.
	ValidatePSBT(ctx context.Context,
		req *walletrpc.SignPsbtRequest) (*ValidationResult, error)

	// GetFeatures returns the features supported by the Validator
	// implementation. This information helps the watch-only node
	// decide which types of metadata to send to the remote signer.
	GetFeatures() string

	// AddMetadata allows metadata to be passed to the Validator.
	// This metadata may be used during a future ValidatePSBT call.
	AddMetadata(metadata []byte) error
}
