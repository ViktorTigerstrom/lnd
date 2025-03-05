package validator

type TransactionType uint32

const (
	// RemoteCommitment signals that the transaction is the remote party's
	// commitment transaction.
	RemoteCommitment TransactionType = iota

	// LocalCommitment signals that the transaction is the local
	// commitment transaction.
	LocalCommitment

	// CooperativeClose signals that the transaction is a Cooperative
	// closure transaction.
	CooperativeClose

	// FundingTransaction signals that the transaction is a funding
	// transaction.
	FundingTransaction

	// LocalSecondLevelHTLCTransaction signals that the transaction is a
	// local second level HTLC transaction.
	LocalSecondLevelHTLCTransaction

	// RemoteLevelHTLCTransaction signals that the transaction is a second
	// level HTLC transaction.
	RemoteSecondLevelHTLCTransaction

	// Unknown signals that the transaction type in unknown
	Unknown
)

// String returns a human-readable name for a build type.
func (t TransactionType) String() string {
	switch t {
	case RemoteCommitment:
		return "remote_commitment"
	case LocalCommitment:
		return "local_commitment"
	case CooperativeClose:
		return "cooperative_close"
	case FundingTransaction:
		return "funding_transaction"
	case LocalSecondLevelHTLCTransaction:
		return "second_level_htlc_transaction"
	default:
		return "unknown"
	}
}

// IsRemoteCommitmentTransaction returns true if the transaction type is
// RemoteCommitment.
func (t TransactionType) IsRemoteCommitmentTransaction() bool {
	return t == RemoteCommitment
}

// IsLocalCommitmentTransaction returns true if the transaction type is
// LocalCommitment.
func (t TransactionType) IsLocalCommitmentTransaction() bool {
	return t == LocalCommitment
}
