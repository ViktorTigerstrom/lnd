package lnwallet

import (
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/input"
)

// RemoteSignerInformer forwards information to the remote signer regarding the
// current channel state for informational purposes only.
type RemoteSignerInformer interface {
	// ForwardLocalCommitment sends the current local commitment transaction
	// to the remote signer strictly for informational purposes.
	ForwardLocalCommitment(commitTx *wire.MsgTx,
		signDesc *input.SignDescriptor) error

	// ForwardMuSig2Info sends the transaction packet for the referenced
	// MuSig2Session to the remote signer.
	ForwardMuSig2Info(muSig2SessionId []byte, commitTx *wire.MsgTx,
		signDesc *input.SignDescriptor) error

	// ForwardFundingInfo sends the information regarding the channel when
	// channel has been funded and has a valid funding outpoint.
	ForwardFundingInfo(fundingPoint *wire.OutPoint,
		localChanCfg *channeldb.ChannelConfig,
		remoteChanCfg *channeldb.ChannelConfig,
		chanType channeldb.ChannelType,
		isLocalInitiator bool) error
}
