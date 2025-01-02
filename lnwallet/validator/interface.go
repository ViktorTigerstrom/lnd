package validator

import (
	"context"
	"github.com/lightningnetwork/lnd/lnrpc"
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
		paymentHash [32]byte) ([]byte, error)

	ListWhitelistedPaymentHashes(ctx context.Context) ([][]byte, error)

	DeleteWhitelistedPaymentHash(ctx context.Context,
		paymentHash []byte) (bool, error)

	InsertLocalCommitment(ctx context.Context, commitmentTxPackage []byte,
		fundingTxid []byte, fundingOutputIndex uint32,
		commitmentHeight uint64) error

	GetLatestLocalCommitment(ctx context.Context, fundingTxid []byte,
		fundingOutputIndex uint32) (LocalCommitmentInfo, error)

	DeleteLocalCommitment(ctx context.Context,
		fundingTxid []byte, fundingOutputIndex uint32,
		commitmentHeight uint64) (bool, error)

	// AddFundingInfo inserts the FundingInfo (along with its associated
	// key descriptors and channel configurations) into the database in a
	// single transaction.
	AddFundingInfo(ctx context.Context,
		fi *walletrpc.FundingInfo) (uint64, error)

	// GetFundingInfo retrieves a FundingInfo object from the database given
	// a channel's ChannelPoint.
	GetFundingInfo(ctx context.Context,
		chanPoint *lnrpc.ChannelPoint) (*walletrpc.FundingInfo, error)
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
	AddMetadata(ctx context.Context,
		metadata *walletrpc.MetadataRequest) error
}

// LocalCommitmentInfo holds information about a local commitment transaction.
type LocalCommitmentInfo struct {
	// CommitmentTxPackage is the serialized psbt request package.
	CommitmentTxPackage []byte

	// FundingTxid is the transaction id of the funding transaction.
	FundingTxid []byte

	// FundingOutputIndex is the output index of the channel that the
	// commitment transaction belongs to in the funding transaction.
	FundingOutputIndex uint32

	// CommitmentHeight is the height of the commitment transaction.
	CommitmentHeight uint64
}
