package validator

import (
	"context"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

// BlindValidator is a no-op validator that which allows blind signing of all
// requests.
type BlindValidator struct{}

// NewBlindValidator creates a new BlindValidator instance.
func NewBlindValidator(_ RemoteSignerDB,
	_ *chaincfg.Params) *BlindValidator {

	return &BlindValidator{}
}

// ValidatePSBT always determines that the provided SignPsbtRequest should be
// signed.
func (r *BlindValidator) ValidatePSBT(_ context.Context,
	_ *walletrpc.SignPsbtRequest) (*ValidationResult, error) {

	return ValidationSuccessResult(), nil
}

// ValidateMuSig2Sign always determines that the provided ValidateMuSig2Sign
// should be signed.
func (r *BlindValidator) ValidateMuSig2Sign(_ context.Context,
	_ *signrpc.MuSig2SignRequest) (*ValidationResult, error) {

	return ValidationSuccessResult(), nil
}

// GetFeatures returns the features supported by the BlindValidator
// implementation. This information helps the watch-only node
// decide which types of metadata to send to the remote signer.
func (r *BlindValidator) GetFeatures() string {
	return ""
}

// AddMetadata allows metadata to be passed to the BlindValidator.
// This metadata may be used during a future ValidatePSBT call.
func (r *BlindValidator) AddMetadata(ctx context.Context,
	metadata *walletrpc.MetadataRequest) error {

	return nil
}

// A compile time assertion to ensure BlindValidator meets the Validation
// interface.
var _ Validation = (*BlindValidator)(nil)
