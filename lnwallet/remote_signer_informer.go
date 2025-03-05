package lnwallet

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
)

// RemoteSignerInformer forwards information to the remote signer regarding the
// current channel state for informational purposes only.
type RemoteSignerInformer interface {
	// ForwardLocalCommitment sends the current local commitment transaction
	// to the remote signer strictly for informational purposes.
	ForwardLocalCommitment(commitTx *wire.MsgTx,
		signDesc *input.SignDescriptor) error
}
