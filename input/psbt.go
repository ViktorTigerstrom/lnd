package input

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lntypes"
	"io"
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
	PsbtKeyTypeOutputAuxLeaf                   = []byte{0x51}
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
	PsbtKeyOutputTypeDefault                   = []byte{0x85}

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

func BytesToUint64(b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, fmt.Errorf("invalid byte slice length: expected 8, "+
			"got %d", len(b))
	}
	return binary.LittleEndian.Uint64(b), nil
}

// uint64Bytes returns a byte slice for the little endian representation of the
// argument.
func uint32Bytes(num uint32) []byte {
	var msgBytes [4]byte

	byteOrder.PutUint32(msgBytes[:], num)

	return msgBytes[:]
}

func BytesToUint32(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, fmt.Errorf("invalid byte slice length: expected 4, "+
			"got %d", len(b))
	}
	return binary.LittleEndian.Uint32(b), nil
}

// boolBytes returns a single-byte slice with a 0 for false and 1 for true.
func boolBytes(val bool) []byte {
	if val {
		return []byte{1}
	}

	return []byte{0}
}

func BytesToBool(b []byte) (bool, error) {
	if len(b) != 1 {
		return false, fmt.Errorf("invalid byte slice length: "+
			"expected 1, got %d", len(b))
	}

	switch b[0] {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		return false, fmt.Errorf("invalid byte value: "+
			"expected 0 or 1, got %d", b[0])
	}
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

// BytesToAuxLeaf coverts bytes to an AuxTapLeaf. If the passed []byte is empty,
// an fn.None result will be returned.
func BytesToAuxLeaf(auxLeafBytes []byte) (AuxTapLeaf, error) {
	if len(auxLeafBytes) == 0 {
		return fn.None[txscript.TapLeaf](), nil
	}

	// An AuxLeaf must contain at least one byte for the version, followed
	// by the bytes for the script.
	if len(auxLeafBytes) == 1 {
		return fn.None[txscript.TapLeaf](), fmt.Errorf("the passed " +
			"auxLeafBytes is not a correctly formated AuxLeaf")
	}

	versionByte := auxLeafBytes[0]
	scriptBytes := auxLeafBytes[1:]
	version := txscript.TapscriptLeafVersion(versionByte)

	if version != txscript.BaseLeafVersion {
		return fn.None[txscript.TapLeaf](), fmt.Errorf("the passed " +
			"version of the auxLeafBytes isn't supprtoed")
	}

	tapLeaf := txscript.NewTapLeaf(version, scriptBytes)

	return fn.Some[txscript.TapLeaf](tapLeaf), nil
}

// auxLeafToBytes coverts an AuxTapLeaf to bytes. If the passed AuxTapLeaf is an
// fn.None option, an empty []byte will be returned.
func auxLeafToBytes(auxLeaf AuxTapLeaf) []byte {
	if auxLeaf.IsNone() {
		return make([]byte, 0)
	}

	tapLeaf := auxLeaf.UnsafeFromSome()

	auxLeafBytes := make([]byte, 1)

	auxLeafBytes[0] = uint8(tapLeaf.LeafVersion)
	auxLeafBytes = append(auxLeafBytes, tapLeaf.Script...)

	return auxLeafBytes
}

// ChannelType returns an UnknownOption for the channel type.
func ChannelType(chanType uint64) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputChanType,
		uint64Bytes(chanType),
	)
}

// AuxLeafOption returns an UnknownOption for an AuxTapLeaf.
func AuxLeafOption(auxLeaf AuxTapLeaf) UnknownOption {
	return wrapUnknownOption(
		PsbtKeyTypeOutputAuxLeaf,
		auxLeafToBytes(auxLeaf),
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
func FundingOutpoint(fundingOutpoint wire.OutPoint) UnknownOption {

	return wrapUnknownOption(
		PsbtKeyTypeOutputFundingPoint, []byte(fundingOutpoint.String()),
	)
}

// RHash returns an UnknownOption for the rHash.
func RHash(rHash []byte) UnknownOption {
	return wrapUnknownOption(PsbtKeyTypeOutputRHash, rHash)
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

// DefaultOutput returns an UnknownOption for any output that's not a channel
// related output type.
func DefaultOutput() UnknownOption {
	return wrapUnknownOption(
		PsbtKeyOutputTypeDefault, []byte{},
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

// SerializeSignInfos serializes a slice of SignInfo into a byte slice.
// The format is as follows:
//
//	[totalLen:uint32] [numSignInfos:uint32]
//	For each SignInfo:
//	    [numUnknowns:uint32]
//	    For each unknown:
//	        [keyLen:uint32] [key bytes]
//	        [valLen:uint32] [value bytes]
func SerializeSignInfos(infos []SignInfo) ([]byte, error) {
	// Use a temporary buffer for the payload.
	payload := new(bytes.Buffer)

	// Write the number of SignInfo entries.
	if err := binary.Write(payload, byteOrder, uint32(len(infos))); err != nil {
		return nil, fmt.Errorf("failed to write number of SignInfos: %v", err)
	}

	// For each SignInfo entry.
	for _, info := range infos {
		// Write the number of unknown entries in this SignInfo.
		if err := binary.Write(payload, byteOrder, uint32(len(info))); err != nil {
			return nil, fmt.Errorf("failed to write number of unknowns: %v", err)
		}

		// Write each unknown entry.
		for _, unk := range info {
			// Write key length and key bytes.
			if err := binary.Write(payload, byteOrder, uint32(len(unk.Key))); err != nil {
				return nil, fmt.Errorf("failed to write key length: %v", err)
			}
			if _, err := payload.Write(unk.Key); err != nil {
				return nil, fmt.Errorf("failed to write key: %v", err)
			}

			// Write value length and value bytes.
			if err := binary.Write(payload, byteOrder, uint32(len(unk.Value))); err != nil {
				return nil, fmt.Errorf("failed to write value length: %v", err)
			}
			if _, err := payload.Write(unk.Value); err != nil {
				return nil, fmt.Errorf("failed to write value: %v", err)
			}
		}
	}

	// Prepend the payload with its total length as a 4-byte little-endian uint32.
	finalBuf := new(bytes.Buffer)
	totalLen := uint32(payload.Len())
	if err := binary.Write(finalBuf, byteOrder, totalLen); err != nil {
		return nil, fmt.Errorf("failed to write total length: %v", err)
	}
	if _, err := finalBuf.Write(payload.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write payload: %v", err)
	}

	return finalBuf.Bytes(), nil
}

// ParseSignInfos parses a byte slice (serialized using SerializeSignInfos)
// into a slice of SignInfo. It assumes that the first 4 bytes indicate the
// total payload length.
func ParseSignInfos(data []byte) ([]SignInfo, error) {
	buf := bytes.NewReader(data)

	// Read the total length prefix.
	var totalLen uint32
	if err := binary.Read(buf, byteOrder, &totalLen); err != nil {
		return nil, fmt.Errorf("failed to read total length: %v", err)
	}

	// Optionally verify that the remaining bytes match totalLen.
	if totalLen != uint32(buf.Len()) {
		return nil, fmt.Errorf("mismatched length: expected %d bytes, got %d bytes", totalLen, buf.Len())
	}

	// Read the number of SignInfo entries.
	var numInfos uint32
	if err := binary.Read(buf, byteOrder, &numInfos); err != nil {
		return nil, fmt.Errorf("failed to read number of SignInfos: %v", err)
	}

	infos := make([]SignInfo, 0, numInfos)
	for i := uint32(0); i < numInfos; i++ {
		// Read the number of unknown entries in this SignInfo.
		var numUnknowns uint32
		if err := binary.Read(buf, byteOrder, &numUnknowns); err != nil {
			return nil, fmt.Errorf("failed to read number of unknowns: %v", err)
		}

		var info SignInfo
		for j := uint32(0); j < numUnknowns; j++ {
			// Read key length.
			var keyLen uint32
			if err := binary.Read(buf, byteOrder, &keyLen); err != nil {
				return nil, fmt.Errorf("failed to read key length: %v", err)
			}

			// Read key.
			key := make([]byte, keyLen)
			if _, err := io.ReadFull(buf, key); err != nil {
				return nil, fmt.Errorf("failed to read key: %v", err)
			}

			// Read value length.
			var valueLen uint32
			if err := binary.Read(buf, byteOrder, &valueLen); err != nil {
				return nil, fmt.Errorf("failed to read value length: %v", err)
			}

			// Read value.
			value := make([]byte, valueLen)
			if _, err := io.ReadFull(buf, value); err != nil {
				return nil, fmt.Errorf("failed to read value: %v", err)
			}

			// Append the unknown to the current SignInfo.
			info = append(info, &psbt.Unknown{
				Key:   key,
				Value: value,
			})
		}

		infos = append(infos, info)
	}

	return infos, nil
}

// SerializedSignInfosLength takes a byte slice (which might have extra bytes appended)
// and returns the total number of bytes that were produced by SerializeSignInfos,
// including the 4-byte length prefix.
func SerializedSignInfosLength(data []byte) (int, error) {
	// Check that there's at least 4 bytes for the total length prefix.
	if len(data) < 4 {
		return 0, fmt.Errorf("insufficient data: expected at least 4 bytes, got %d", len(data))
	}

	// Read the total length of the payload.
	totalLen := binary.LittleEndian.Uint32(data[:4])
	serializedLength := int(4 + totalLen)

	if len(data) < serializedLength {
		return 0, fmt.Errorf("insufficient data: expected %d bytes, got %d", serializedLength, len(data))
	}

	return serializedLength, nil
}
