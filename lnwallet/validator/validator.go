//go:build dev
// +build dev

package validator

import (
	"context"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

// Validator is currently a no-op validator that runs in the production env.
type Validator struct{}

func ValidateCompatibleConfig(dbCfg *lncfg.DB) error {
	return nil
}

// NewValidator creates a new Validator instance.
func NewValidator(remoteSignerDB RemoteSignerDB,
	network *chaincfg.Params) *Validator {

	return &Validator{}
}

// ValidatePSBT always determines that the provided SignPsbtRequest should be
// signed.
func (r *Validator) ValidatePSBT(_ context.Context,
	_ *walletrpc.SignPsbtRequest) (*ValidationResult, error) {

	return ValidationSuccessResult(), nil
}

// ValidateMuSig2Sign always determines that the provided ValidateMuSig2Sign
// should be signed.
func (r *Validator) ValidateMuSig2Sign(ctx context.Context,
	req *signrpc.MuSig2SignRequest) (*ValidationResult, error) {

	return ValidationSuccessResult(), nil
}

// GetFeatures returns the features supported by the Validator
// implementation. This information helps the watch-only node
// decide which types of metadata to send to the remote signer.
func (r *Validator) GetFeatures() string {
	return ""
}

// AddMetadata allows metadata to be passed to the Validator.
// This metadata may be used during a future ValidatePSBT call.
func (r *Validator) AddMetadata(ctx context.Context,
	metadata *walletrpc.MetadataRequest) error {

	return nil
}

// A compile time assertion to ensure Validator meets the Validation interface.
var _ Validation = (*Validator)(nil)
