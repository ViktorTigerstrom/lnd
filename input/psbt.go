package input

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/lntypes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightningnetwork/lnd/keychain"
)

const (
	// baseLen is a 4-byte root key fingerprint and 5 4-byte derivation
	// path elements, or 24 bytes.
	baseDescLen = 4 + 5*4

	// descLenWithPubKey is baseLen, plus a 33-byte compressed pubkey, or
	// 57 bytes.
	descLenWithPubKey = baseDescLen + btcec.PubKeyBytesLenCompressed
)

var (
	PsbtKeyTypeOutputChanType                  = []byte{0x60}
	PsbtKeyTypeOutputInitiator                 = []byte{0x61}
	PsbtKeyTypeOutputCsvDelay                  = []byte{0x62}
	PsbtKeyTypeOutputCltvExpiry                = []byte{0x63}
	PsbtKeyTypeOutputLeaseExpiry               = []byte{0x64}
	PsbtKeyTypeOutputCommitPoint               = []byte{0x65}
	PsbtKeyTypeOutputRHash                     = []byte{0x66}
	PsbtKeyTypeOutputLocalMultiSigKey          = []byte{0x67}
	PsbtKeyTypeOutputLocalRevocationBasePoint  = []byte{0x68}
	PsbtKeyTypeOutputLocalPaymentBasePoint     = []byte{0x69}
	PsbtKeyTypeOutputLocalDelayBasePoint       = []byte{0x6a}
	PsbtKeyTypeOutputLocalHtlcBasePoint        = []byte{0x6b}
	PsbtKeyTypeOutputRemoteMultiSigKey         = []byte{0x6c}
	PsbtKeyTypeOutputRemoteRevocationBasePoint = []byte{0x6d}
	PsbtKeyTypeOutputRemotePaymentBasePoint    = []byte{0x6e}
	PsbtKeyTypeOutputRemoteDelayBasePoint      = []byte{0x6f}
	PsbtKeyTypeOutputFundingPoint              = []byte{0x50}
	PsbtKeyTypeOutputRemoteHtlcBasePoint       = []byte{0x70}
	PsbtKeyRemoteCommitmentTransaction         = []byte{0x71}
	PsbtKeyLocalCommitmentTransaction          = []byte{0x72}
	PsbtKeyCooperativeCloseTransaction         = []byte{0x73}
	PsbtKeyFundingTransaction                  = []byte{0x74}
	PsbtKeyLocalSecondLevelHTLCTransaction     = []byte{0x75}
	PsbtKeyRemoteSecondLevelHTLCTransaction    = []byte{0x76}
	PsbtKeyDefaultTransaction                  = []byte{0x77}
	PsbtKeyOutputTypeIncomingHTLC              = []byte{0x78}
	PsbtKeyOutputTypeOfferedHTLC               = []byte{0x79}
	PsbtKeyOutputTypeToRemote                  = []byte{0x80}
	PsbtKeyOutputTypeToLocal                   = []byte{0x81}
	PsbtKeyOutputTypeRemoteAnchor              = []byte{0x82}
	PsbtKeyOutputTypeLocalAnchor               = []byte{0x83}
	PsbtKeyOutputTypeSecondLevelHTLC           = []byte{0x84}

	byteOrder = binary.LittleEndian
)

// UnknownOption returns a *psbt.Unknown for enriching a PSBT signing request.
type UnknownOption func() *psbt.Unknown

// UnknownOptions returns a slice of *psbt.Unknown for populating the Unknowns
// field of a psbt.Packet, psbt.PInput, or psbt.POutput struct.
func UnknownOptions(opts ...UnknownOption) []*psbt.Unknown {
	unknowns := make([]*psbt.Unknown, len(opts))

	for i := range opts {
		unknowns[i] = opts[i]()
	}

	return unknowns
}

// wrapUnknownOption wraps a key and value in a function matching the signature
// of UnknownOption.
func wrapUnknownOption(key []byte, value []byte) UnknownOption {
	return func() *psbt.Unknown {
		return &psbt.Unknown{
			Key:   key,
			Value: value,
		}
	}
}

// uint64Bytes returns a byte slice for the little endian representation of the
// argument.
func uint64Bytes(num uint64) []byte {
	var msgBytes [8]byte

	byteOrder.PutUint64(msgBytes[:], num)

	return msgBytes[:]
}

// uint64Bytes returns a byte slice for the little endian representation of the
// argument.
func uint32Bytes(num uint32) []byte {
	var msgBytes [4]byte

	byteOrder.PutUint32(msgBytes[:], num)

	return msgBytes[:]
}

// boolBytes returns a single-byte slice with a 0 for false and 1 for true.
func boolBytes(val bool) []byte {
	if val {
		return []byte{1}
	}

	return []byte{0}
}

// descBytes returns a byte slice representing the descriptor (family/index
// and possibly pubkey). It requires the wallet's root key fingerprint and
// coin type to encode the derivation path correctly.
func descBytes(fingerprint, coin uint32, desc *keychain.KeyDescriptor) []byte {
	// Serialize the derivation path first.
	msgBytes := psbt.SerializeBIP32Derivation(fingerprint, []uint32{
		hdkeychain.HardenedKeyStart + keychain.BIP0043Purpose,
		hdkeychain.HardenedKeyStart + coin,
		hdkeychain.HardenedKeyStart + uint32(desc.Family),
		0,
		desc.Index,
	})

	// Add the derived pubkey if it's provided. This way, the signer can
	// check if it's correct.
	if desc.PubKey != nil {
		msgBytes = append(msgBytes,
			desc.PubKey.SerializeCompressed()...)
	}

	return msgBytes
}

// ChannelType returns an UnknownOption for the channel type.
func ChannelType(chanType uint64) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputChanType,
		uint64Bytes(chanType),
	)
}

// Initiator returns an UnknownOption for whether we initiated the channel.
func Initiator(initiator bool) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputInitiator,
		boolBytes(initiator),
	)
}

// CsvDelay returns an UnknownOption for the CSV delay.
func CsvDelay(delay uint32) UnknownOption {
	return wrapUnknownOption(PsbtKeyTypeOutputCsvDelay, uint32Bytes(delay))
}

// CltvExpiry returns an UnknownOption for the CLTV expiry.
func CltvExpiry(expiry uint32) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputCltvExpiry,
		uint32Bytes(expiry),
	)
}

// LeaseExpiry returns an UnknownOption for the lease expiry.
func LeaseExpiry(expiry uint32) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputLeaseExpiry,
		uint32Bytes(expiry),
	)
}

// CommitPoint returns an UnknownOption for the commit point.
func CommitPoint(point *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputCommitPoint,
		point.SerializeCompressed(),
	)
}

// FundingOutpoint returns an UnknownOption for the funding outpoint.
func FundingOutpoint(fundingOutpoint wire.OutPoint) (UnknownOption, error) {
	fundingOutpointBytes, err := fundingOutpointToBytes(fundingOutpoint)
	if err != nil {
		return nil, err
	}

	return wrapUnknownOption(
		PsbtKeyTypeOutputFundingPoint,
		fundingOutpointBytes,
	), nil
}

// Convert FundingOutpoint to []byte
func fundingOutpointToBytes(outpoint wire.OutPoint) ([]byte, error) {
	// Decode the txid (hex string) to bytes
	txidBytes, err := hex.DecodeString(outpoint.Hash.String())
	if err != nil {
		return nil, err
	}

	// Reverse the txid bytes (Bitcoin stores txids little-endian internally)
	for i := 0; i < len(txidBytes)/2; i++ {
		txidBytes[i], txidBytes[len(txidBytes)-1-i] = txidBytes[len(txidBytes)-1-i], txidBytes[i]
	}

	// Convert the output index (uint32) to little-endian byte slice
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, outpoint.Index)

	// Concatenate txidBytes (32 bytes) + indexBytes (4 bytes)
	finalBytes := append(txidBytes, indexBytes...)

	return finalBytes, nil
}

// RHash returns an UnknownOption for the rHash.
func RHash(rHash []byte) UnknownOption {
	return wrapUnknownOption(PsbtKeyTypeOutputRHash, rHash)
}

// LocalMultiSigKey returns an UnknownOption for the local multisig key. It
// requires the wallet's root key fingerprint and coin type to construct the
// derivation path correctly.
func LocalMultiSigKey(fingerprint, coin uint32,
	desc *keychain.KeyDescriptor) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputLocalMultiSigKey,
		descBytes(fingerprint, coin, desc),
	)
}

// LocalRevocationBasePoint returns an UnknownOption for the local revocation
// base point. It requires the wallet's root key fingerprint and coin type to
// construct the derivation path correctly.
func LocalRevocationBasePoint(fingerprint, coin uint32,
	desc *keychain.KeyDescriptor) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputLocalRevocationBasePoint,
		descBytes(fingerprint, coin, desc),
	)
}

// LocalPaymentBasePoint returns an UnknownOption for the local payment base
// point. It requires the wallet's root key fingerprint and coin type to
// construct the derivation path correctly.
func LocalPaymentBasePoint(fingerprint, coin uint32,
	desc *keychain.KeyDescriptor) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputLocalPaymentBasePoint,
		descBytes(fingerprint, coin, desc),
	)
}

// LocalDelayBasePoint returns an UnknownOption for the local delay base point.
// It requires the wallet's root key fingerprint and coin type to construct the
// derivation path correctly.
func LocalDelayBasePoint(fingerprint, coin uint32,
	desc *keychain.KeyDescriptor) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputLocalDelayBasePoint,
		descBytes(fingerprint, coin, desc),
	)
}

// LocalHtlcBasePoint returns an UnknownOption for the local HTLC base point.
// It requires the wallet's root key fingerprint and coin type to construct the
// derivation path correctly.
func LocalHtlcBasePoint(fingerprint, coin uint32,
	desc *keychain.KeyDescriptor) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputLocalHtlcBasePoint,
		descBytes(fingerprint, coin, desc),
	)
}

// RemoteMultiSigKey returns an UnknownOption for the remote multisig key.
func RemoteMultiSigKey(key *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputRemoteMultiSigKey,
		key.SerializeCompressed(),
	)
}

// RemoteRevocationBasePoint returns an UnknownOption for the remote revocation
// base point.
func RemoteRevocationBasePoint(key *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputRemoteRevocationBasePoint,
		key.SerializeCompressed(),
	)
}

// RemotePaymentBasePoint returns an UnknownOption for the remote payment base
// point.
func RemotePaymentBasePoint(key *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputRemotePaymentBasePoint,
		key.SerializeCompressed(),
	)
}

// RemoteDelayBasePoint returns an UnknownOption for the remote delay base
// point.
func RemoteDelayBasePoint(key *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputRemoteDelayBasePoint,
		key.SerializeCompressed(),
	)
}

// RemoteHtlcBasePoint returns an UnknownOption for the remote HTLC base point.
func RemoteHtlcBasePoint(key *btcec.PublicKey) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputRemoteHtlcBasePoint,
		key.SerializeCompressed(),
	)
}

// RemoteCommitmentTransaction returns an UnknownOption for remote commitment
// transaction type.
func RemoteCommitmentTransaction() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyRemoteCommitmentTransaction, []byte{},
	)
}

// LocalCommitmentTransaction returns an UnknownOption for local commitment
// transaction type.
func LocalCommitmentTransaction() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyLocalCommitmentTransaction, []byte{},
	)
}

// CooperativeCloseTransaction returns an UnknownOption for cooperative close
// transaction type.
func CooperativeCloseTransaction() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyCooperativeCloseTransaction, []byte{},
	)
}

// FundingTransaction returns an UnknownOption for funding transaction type.
func FundingTransaction() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyFundingTransaction, []byte{},
	)
}

// SecondLevelHTLCTransaction returns an UnknownOption for second level HTLC
// transaction type.
func SecondLevelHTLCTransaction(
	whoseCommit lntypes.ChannelParty) UnknownOption {

	if whoseCommit.IsLocal() {
		return wrapUnknownOption(
			PsbtKeyLocalSecondLevelHTLCTransaction, []byte{},
		)
	} else {
		return wrapUnknownOption(
			PsbtKeyRemoteSecondLevelHTLCTransaction, []byte{},
		)
	}
}

// DefaultTransaction returns an UnknownOption for the default transaction type.
func DefaultTransaction() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyDefaultTransaction, []byte{},
	)
}

// IncomingHTLCOutput returns an UnknownOption for an incoming HTLC output type.
func IncomingHTLCOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeIncomingHTLC, []byte{},
	)
}

// OfferedHTLCOutput returns an UnknownOption for an offered HTLC output type.
func OfferedHTLCOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeOfferedHTLC, []byte{},
	)
}

// ToRemoteOutput returns an UnknownOption for the to_remote output type. Note
// that this is from the perspective of the transaction itself, and the local
// node is therefore not always the to_local output. I.e. the output for the
// node itself is the to_remote output if this UnknownOption is set for an
// output on the remote commitment transaction, but not for the local commitment
// transaction.
func ToRemoteOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeToRemote, []byte{},
	)
}

// ToLocalOutput returns an UnknownOption for the to_local output type. Note
// that this is from the perspective of the transaction itself, and the local
// node is therefore not always the to_local output. I.e. the output for the
// node itself is the to_local output if this UnknownOption is set for an
// output on the local commitment transaction, but not for the remote commitment
// transaction.
func ToLocalOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeToLocal, []byte{},
	)
}

// RemoteAnchorOutput returns an UnknownOption for the remote anchor output
// type. Note that this is from the perspective of the transaction itself, and
// the local node is therefore not always the local anchor output. I.e. the
// anchor output for the node itself is the remote anchor output if this
// UnknownOption is set for an output on the remote commitment transaction,
// but not for the local commitment transaction.
func RemoteAnchorOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeRemoteAnchor, []byte{},
	)
}

// LocalAnchorOutput returns an UnknownOption for the local anchor output
// type. Note that this is from the perspective of the transaction itself, and
// the local node is therefore not always the local anchor output. I.e. the
// anchor output for the node itself is the local anchor output if this
// UnknownOption is set for an output on the local commitment transaction,
// but not for the remote commitment transaction.
func LocalAnchorOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeLocalAnchor, []byte{},
	)
}

// SecondLeveLHTLCOutput returns an UnknownOption for the second level HTLC
// output type.
func SecondLeveLHTLCOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeSecondLevelHTLC, []byte{},
	)
}

// KeyDescriptorFromUnknownValue decodes a value encoded by LocalDesc. It
// returns, in order:
// * Root key fingerprint of the wallet
// * Coin type
// * A *keychain.KeyDescriptor
// * A non-nil error on failure or nil error on success
//
// The branch is always expected to be 0 and the purpose 1017'.
func KeyDescriptorFromUnknownValue(value []byte) (
	uint32, uint32, keychain.KeyDescriptor, error) {

	// Check if we have a bare derivation or a descriptor with a pubkey.
	if len(value) != baseDescLen && len(value) != descLenWithPubKey {
		return 0, 0, keychain.KeyDescriptor{}, psbt.ErrInvalidPsbtFormat
	}

	fingerprint, derivation, err := psbt.ReadBip32Derivation(
		value[:baseDescLen],
	)
	if err != nil {
		return 0, 0, keychain.KeyDescriptor{}, err
	}

	// Ensure we're getting the right purpose.
	if derivation[0] != hdkeychain.HardenedKeyStart+
		keychain.BIP0043Purpose {

		return 0, 0, keychain.KeyDescriptor{}, psbt.ErrInvalidPsbtFormat
	}

	// Ensure we're getting a 0 branch.
	if derivation[3] != 0 {
		return 0, 0, keychain.KeyDescriptor{}, psbt.ErrInvalidPsbtFormat
	}

	// Ensure the family and coin type are hardened.
	if derivation[1] < hdkeychain.HardenedKeyStart ||
		derivation[2] < hdkeychain.HardenedKeyStart {

		return 0, 0, keychain.KeyDescriptor{}, psbt.ErrInvalidPsbtFormat
	}

	coinType := derivation[1] - hdkeychain.HardenedKeyStart

	localDesc := keychain.KeyDescriptor{
		KeyLocator: keychain.KeyLocator{
			Family: keychain.KeyFamily(
				derivation[2] - hdkeychain.HardenedKeyStart,
			),
			Index: derivation[4],
		},
	}

	// Check if we have a public key and decode if necessary.
	if len(value) == descLenWithPubKey {
		var err error

		localDesc.PubKey, err = btcec.ParsePubKey(value[baseDescLen:])
		if err != nil {
			return 0, 0, keychain.KeyDescriptor{}, err
		}
	}

	return fingerprint, coinType, localDesc, nil
}
