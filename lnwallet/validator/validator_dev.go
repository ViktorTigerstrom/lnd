//go:build !dev
// +build !dev

package validator

import (
	"bytes"
	"context"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

// Validator is currently a no-op validator that runs in the production env.
type Validator struct{}

// NewValidator creates a new Validator instance.
func NewValidator() *Validator {
	return &Validator{}
}

// ValidatePSBT always determines that the provided SignPsbtRequest should be
// signed.
func (r *Validator) ValidatePSBT(_ context.Context,
	req *walletrpc.SignPsbtRequest) (*ValidationResult, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		return nil, err
	}

	transactionType, err := r.getTransactionType(packet)
	if err != nil {
		return nil, err
	}

	log.Infof("packet is: %v", packet)
	log.Infof("transaction type for request is: %s",
		transactionType.String())

	switch transactionType {
	case RemoteCommitment:
		return r.validateRemoteCommitment(packet)

	case LocalCommitment:
		return r.validateLocalCommitment(packet)

	case CooperativeClose:
		return r.validateCooperativeClose(packet)

	case FundingTransaction:
		return r.validateFundingTransaction(packet)

	case SecondLevelHTLCTransaction:
		// TODO: MUST DO IT FOR REMOTE secondLevelHTLCTx as well
		return r.validateLocalSecondLevelHTLCTx(packet)

	case Unknown:
		return r.validateDefaultTransaction(packet)

	default:
		log.Errorf("Unexpected transaction type.")

		err := fmt.Errorf("unexpected transaction type: %v",
			transactionType)

		return nil, fmt.Errorf("unexpected transaction type: %v", err)
	}
	/*

		switch GetTransactionType(packet) {

		case txType.IsRemoteCommitmentTransaction:
			for _, output := range packet.Outputs {
				switch GetCommitmentOutputType(output) {

				case outputType.ToLocal:
					if !KeyDerivedFromRemoteDelayedBasepoint(output) {
						res := ValidationFailureResult("Incorrect " +
							"public key for to_local " +
							"output in remote commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.ToRemote:
					if !KeyDerivedFromLocalPaymentBasepoint(output) {
						res := ValidationFailureResult("Incorrect " +
							"public key for to_remote " +
							"output in remote commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.OfferedHTLC:
					correctKeys := KeysDerivedFromHTLCsBasepoints(
						v.GetLocalHTLCBasePoint(packet),
						v.GetRemoteHTLCBasePoint(packet),
						output,
					)
					if !correctKeys {
						res := ValidationFailureResult(
							"Public keys in HTLC not derived from " +
							"channel HTLC basepoints in " +
							"remote commitment "+
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.ReceivedHTLC:
					if !PaymentHashIsWhiteListed(output){
						res := ValidationFailureResult(
							"Unauthorized payment_hash " +
							"detected in remote commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

					correctKeys := KeysDerivedFromHTLCsBasepoints(
						v.GetLocalHTLCBasePoint(packet),
						v.GetRemoteHTLCBasePoint(packet),
						output,
					)
					if !correctKeys {
						res := ValidationFailureResult(
							"Public keys in HTLC not derived from " +
							"channel HTLC basepoints in " +
							"remote commitment "+
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.LocalAnchor:
					if !KeyIsRemoteFundingPubkey(output) {
						res := ValidationFailureResult("Public " +
							"key for to_local_anchor isn't" +
							"remote's funding pubkey in " +
							"remote commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.RemoteAnchor:
					if !KeyIsLocalFundingPubkey(output) {
						res := ValidationFailureResult("Public " +
							"key for to_remote_anchor isn't" +
							"local funding pubkey in " +
							"remote commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				default:
					res := ValidationFailureResult("Unexpected " +
						"output in remote commitment " +
						"transaction: %v", output)
					return res, nil
				}

				if !ScriptHashMatch(output) {
					res := ValidationFailureResult("Locking " +
						"script does not match script "+
						"hash for output %v in remote " +
						"commitment transaction", output)
					return res, nil
				}
			}

			return ValidationSuccessResult(), nil

		case txType.IsLocalCommitmentTransaction: // Force closure
			// Checks that the commitment height of the tx is >= than the
			// persisted local commitment height
			if !IsCurrentCommitmentHeight(packet){
				res := ValidationFailureResult("Revoked state detected " +
					"in request to force close channel with local " +
					"commitment transaction: %v", packet,
				)
				return res, nil
			}

			for _, output := range packet.Outputs {
				switch GetCommitmentOutputType(output) {

				case outputType.ToLocal:
					if !KeyDerivedFromLocalDelayedBasepoint(output) {
						res := ValidationFailureResult("Incorrect " +
							"public key for to_local " +
							"output in local commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.ToRemote:
					if !KeyDerivedFromRemotePaymentBasepoint(output) {
						res := ValidationFailureResult("Incorrect " +
							"public key for to_remote " +
							"output in local commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.OfferedHTLC:
					if !PaymentHashIsWhiteListed(output){
						res := ValidationFailureResult(
							"Unauthorized payment_hash " +
							"detected in local commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

					correctKeys := KeysDerivedFromHTLCsBasepoints(
						v.GetRemoteHTLCBasePoint(packet),
						v.GetLocalHTLCBasePoint(packet),
						output,
					)
					if !correctKeys {
						res := ValidationFailureResult(
							"Public keys in HTLC not derived from " +
							"channel HTLC basepoints in " +
							"local commitment "+
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.ReceivedHTLC:
					correctKeys := KeysDerivedFromHTLCsBasepoints(
						v.GetRemoteHTLCBasePoint(packet),
						v.GetLocalHTLCBasePoint(packet),
						output,
					)
					if !correctKeys {
						res := ValidationFailureResult(
							"Public keys in HTLC not derived from " +
							"channel HTLC basepoints in " +
							"local commitment "+
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.LocalAnchor:
					if !KeyIsLocalFundingPubkey(output) {
						res := ValidationFailureResult("Public " +
							"key for to_local_anchor isn't" +
							"local funding pubkey in " +
							"local commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				case outputType.RemoteAnchor:
					if !KeyIsRemoteFundingPubkey(output) {
						res := ValidationFailureResult("Public " +
							"key for to_remote_anchor isn't" +
							"remote's funding pubkey in " +
							"local commitment " +
							"transaction %v for output: %v",
							packet, output,
						)
						return res, nil
					}

				default:
					res := ValidationFailureResult("Unexpected " +
						"output %v in local commitment " +
						"transaction: %v", output, packet)
					return res, nil
				}

				if !ScriptHashMatch(output) {
					res := ValidationFailureResult("Locking " +
						"script does not match script "+
						"hash for output %v in remote " +
						"commitment transaction", output)
					return res, nil
				}
			}

			return ValidationSuccessResult(), nil

		case txType.IsCoopCloseTx:
			// This type of transaction is particularly hard to decide how
			// we should handle, as it will contain the remote party's
			// output, which is an address which cannot be derived from any
			// basepoint.
			// Therefore we're faced with 2 different options.
			// TODO: decide option

			// Option 1, we require that all outputs is either whitelisted,
			// or is an internal address (the default if no DeliveryAddress
			// is set).
			// This WILL require that the remote party's address gets
			// whitelisted somehow on the application layer.
			for _, output := range packet.Outputs {
				switch GetCoopCloseOutputType(output) {

				switch coOpType.IsInternalAddress, coOpType.IsWhiteListedAddress:

				default:
					res := ValidationFailureResult("Unknown " +
						"output %v in cooperative closing "+
						"transaction %v", output, packet)
					return res, nil
				}
			}

			return ValidationSuccessResult(), nil

			// Option 2:
			// We ignore checking the remote output, and instead only check
			// if the transaction contains an output for us. We consider it
			// to be our output if it contains an output address that's
			// either internal in the wallet, or is whitelisted (i.e. a
			// DeliveryAddress has been set for us).
			// NOTE: As our output in the closing tx can be trimmed, if an
			// output has been trimmed we check if that non-trimmed output
			// in the closure tx should be ours or not. We determine that in
			// that scenario if the to_local output amount in our
			// last local commitment tx was above the value for the to_remote
			// output.

			// If an output was trimmed checks if the to_local output value
			// in our last commitment tx was above the to_remote value.
			if len(packet.Outputs) == 1 && !RequireKnownOutput(packet) {
				// If not we won't require that a local output exists in
				// the closing tx.
				return ValidationSuccessResult(), nil
			}

			// Else the tx should have 2 outputs, where one of the outputs
			// should be ours.
			for _, output := range packet.Outputs {
				switch GetCoopCloseOutputType(output) {

				case coOpType.IsInternalAddress, coOpType.IsWhiteListedAddress:
					// Found the local output.
					return ValidationSuccessResult(), nil

				default:
					res := ValidationFailureResult("Unknown " +
						"output %v in funding transaction %v",
						output, packet)
					return res, nil
				}
			}

			res := ValidationFailureResult("Could not find local " +
				"output in cooperative closing "+
				"transaction %v", packet)

			return res, nil

		case txType.IsFundingTransaction:
			// NOTE: we only enter this and sign funding transactions if we
			// are the channel funder.
			// This would need to be updated when support for dualfunding
			// exists, as the outputs may contain the remote's change output

			for _, output := range packet.Outputs {
				switch GetFundingOutputType(output) {

				case fundingType.IsInternalAddress:
					// Our change output

				case fundingType.Taproot:
					// Validates that the output is a MuSig2 output
					// where one of the keys is an internal key.
					if !MuSig2OutputWithInternalKey(output){
						res := ValidationFailureResult("Internal " +
							"key not found in funding "+
							"output %v in funding " +
							"transaction", output)
						return res, nil
					}

					if !KeysMatchTaprootAddress(output) {
						res := ValidationFailureResult("Taproot " +
							"pubkey doesn't match included "+
							"keys for output %v in funding " +
							"transaction", output)
						return res, nil
					}

				case fundingType.P2WSH:
					// Validates that the output is a 2 of 2 output
					// multisig output, where one of the keys is an
					// internal key.
					if !MultiSigOutputWithInternalKey(output){
						res := ValidationFailureResult("Internal " +
							"key not found in funding "+
							"output %v in funding " +
							"transaction", output)
						return res, nil
					}

					if !ScriptHashMatch(output) {
						res := ValidationFailureResult("Locking " +
							"script does not match script "+
							"hash for output %v in funding " +
							"transaction", output)
						return res, nil
					}
				}
			}

			return ValidationSuccessResult(), nil

		case txType.IsSecondStageHTLCTransaction:
			for _, output := range packet.Outputs {
				switch GetSecondStageType(output) {

				case secondStageType.IsInternalAddress:
					// Sweeper change output

				case secondStageType.IsTimeoutOrSuccesOutput:
					// We don't evaluate if this output actually should BE our or
					// the remote's delayed key, as it would require that the
					// channel party controlling the watch-only actually swaps
					// the key, which this validation level does not aim to prevent.
					if !DerivedFromLocalOrRemoteDelayedBasePoint(output) {
						res := ValidationFailureResult("Second " +
							"stage tx output key not derived " +
							"from delayed basepoint for "+
							"output %v in second " +
							"stage transaction", output)
						return res, nil
					}

					if !ScriptHashMatch(output) {
						res := ValidationFailureResult("Locking " +
							"script does not match script "+
							"hash for output %v in second " +
							"stage transaction", output)
						return res, nil
					}

				default:
					res := ValidationFailureResult("Unknown "+
						"output %v in funding transaction %v",
						output, packet)
					return res, nil
				}
			}

			return ValidationSuccessResult(), nil

		default:
			// This is a sweeper tx or an lncli sendcoins/sendmany tx
			for _, output := range packet.Outputs {
				if !IsInternalAddress(output) && IsWhiteListedAddress(output) {
					res := ValidationFailureResult("Unauthorized "+
						"output %v for transaction %v",
						output, packet)
					return res, nil
				}
			}

			return ValidationSuccessResult(), nil
		}
	*/

	return ValidationSuccessResult(), nil
}

func (r *Validator) getTransactionType(packet *psbt.Packet) (TransactionType,
	error) {

	for _, unknown := range packet.Unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyLocalCommitmentTransaction):
			return LocalCommitment, nil
		case bytes.Equal(k, input.PsbtKeyRemoteCommitmentTransaction):
			return RemoteCommitment, nil
		case bytes.Equal(k, input.PsbtKeyCooperativeCloseTransaction):
			return CooperativeClose, nil
		case bytes.Equal(k, input.PsbtKeyFundingTransaction):
			return FundingTransaction, nil
		case bytes.Equal(k, input.PsbtKeyLocalSecondLevelHTLCTransaction):
			return SecondLevelHTLCTransaction, nil
		case bytes.Equal(k, input.PsbtKeyDefaultTransaction):
			return Unknown, nil
		default:
			continue
		}
	}

	// Transaction type not found. Require whitelisted address or internal
	// key.
	return Unknown, nil
}

func (r *Validator) validateRemoteCommitment(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a Remote Commitment transaction.")

	if packet.UnsignedTx != nil && len(packet.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("expected 1 input for commitment "+""+
			"transaction for packet: %v", packet)
	}

	outPoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: outPoint.Hash[:],
		},
		OutputIndex: outPoint.Index,
	}

	var (
		toLocalFound, toRemoteFound, localAnchorFound,
		remoteAnchorFound bool
	)

	for _, output := range packet.Outputs {
		if len(output.Unknowns) <= 0 {
			return nil, fmt.Errorf("commitment outputs should " +
				"have metadata attached")
		}

		k := output.Unknowns[0].Key

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeToLocal):
			if toLocalFound {
				return nil, fmt.Errorf("multiple to_local" +
					"outputs in remote commitment tx")
			}
			toLocalFound = true

			cpMetadata, err := r.extractChannelPartyOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				cpMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			toLocalScript, err := lnwallet.CommitScriptToSelf(
				commitmentInfo.ChanType,
				!commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToLocalKey,
				commitmentInfo.CommitmentKeys.RevocationKey,
				cpMetadata.CsvDelay, cpMetadata.LeaseExpiry,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				toLocalScript.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not match " +
					"for to_local output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for to_local output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeToRemote):
			if toRemoteFound {
				return nil, fmt.Errorf("multiple to_remote" +
					"outputs in remote commitment tx")
			}
			toRemoteFound = true

			cpMetadata, err := r.extractChannelPartyOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				cpMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
				commitmentInfo.ChanType,
				!commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToRemoteKey,
				cpMetadata.LeaseExpiry, input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				toRemoteScript.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for to_remote output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for to_remote output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeIncomingHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			isWhitelisted, err := r.isWhitelistedHTLC(
				htlcMetadata.RHash,
			)
			if err != nil {
				return nil, err
			}

			if !isWhitelisted {
				log.Errorf("Found non whitelisted HTLC in "+
					"remote commitment transaction: %v",
					htlcMetadata.RHash)

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("Found non " +
						"whitelisted HTLC in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

			commitmentInfo, err := r.getCommitmentKeys(
				htlcMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, true, lntypes.Remote,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for incoming HTLC output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for incoming HTLC output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeOfferedHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				htlcMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, false, lntypes.Remote,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for incoming HTLC output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for incoming HTLC output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeLocalAnchor):
			if localAnchorFound {
				return nil, fmt.Errorf("multiple local " +
					"anchor outputs in remote commitment " +
					"tx")
			}
			localAnchorFound = true

			anchorMetadata, err := r.extractAnchorOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				anchorMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO:
			// Maybe the commitmentInfo.localChanCfg & the
			// commitmentInfo.remoteChanCfg should be reversed
			// here, as this is the remote commitment tx.
			localAnchor, _, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				localAnchor.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for local anchor output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for local anchor output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeRemoteAnchor):
			if remoteAnchorFound {
				return nil, fmt.Errorf("multiple remote " +
					"anchor outputs in remote commitment " +
					"tx")
			}
			remoteAnchorFound = true

			anchorMetadata, err := r.extractAnchorOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				anchorMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
			)
			if err != nil {
				return nil, err
			}

			// TODO:
			// Maybe the commitmentInfo.localChanCfg & the
			// commitmentInfo.remoteChanCfg should be reversed
			// here, as this is the remote commitment tx.
			_, remoteAnchor, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				remoteAnchor.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for remote anchor output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for remote anchor output in " +
						"remote commitment transaction")
					return failRes, nil

				*/
			}

		default:
			return nil, fmt.Errorf("unknown output type in " +
				"commitment transaction")
		}
	}

	return ValidationSuccessResult(), nil
}

type ChannelPartyOutputMetadata struct {
	CommitPoint *btcec.PublicKey
	CsvDelay    uint32
	LeaseExpiry uint32
}

type HTLCOutputMetadata struct {
	CommitPoint *btcec.PublicKey
	CltvExpiry  uint32
	RHash       [32]byte
}

type AnchorOutputMetadata struct {
	CommitPoint *btcec.PublicKey
}

type SecondLevelHTLCOutputMetadata struct {
	CommitPoint     *btcec.PublicKey
	CsvDelay        uint32
	LeaseExpiry     uint32
	fundingOutpoint wire.OutPoint
}

func (r *Validator) extractChannelPartyOutputMetadata(
	unknowns input.SignInfo) (*ChannelPartyOutputMetadata, error) {

	for _, unknown := range unknowns {
		log.Infof("unkown is: %v", unknown)
	}

	return &ChannelPartyOutputMetadata{}, nil
}

func (r *Validator) extractHTLCOutputMetadata(
	unknowns input.SignInfo) (*HTLCOutputMetadata, error) {

	for _, unknown := range unknowns {
		log.Infof("unkown is: %v", unknown)
	}

	return &HTLCOutputMetadata{}, nil
}

func (r *Validator) extractAnchorOutputMetadata(
	unknowns input.SignInfo) (*AnchorOutputMetadata, error) {

	for _, unknown := range unknowns {
		log.Infof("unkown is: %v", unknown)
	}

	return &AnchorOutputMetadata{}, nil
}

func (r *Validator) extractSecondLevelHTLCOutputMetadata(
	unknowns input.SignInfo) (*SecondLevelHTLCOutputMetadata, error) {

	for _, unknown := range unknowns {
		log.Infof("unkown is: %v", unknown)
	}

	return &SecondLevelHTLCOutputMetadata{}, nil
}

type CommitmentInfo struct {
	CommitmentKeys              *lnwallet.CommitmentKeyRing
	IsLocalInitiator            bool
	ChanType                    channeldb.ChannelType
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig
}

func (r *Validator) getCommitmentKeys(commitPoint *btcec.PublicKey,
	chanPoint *lnrpc.ChannelPoint,
	whoseCommit lntypes.ChannelParty) (*CommitmentInfo, error) {

	/* Use the chanpoint to fetch the local + remote ChannelConfig, as well
	as channel type from the database. Then with that, call
	lntypes.DeriveCommitmentKeys to generate the CommitmentKeyRing.
	*/

	return nil, nil
}

func (r *Validator) isWhitelistedHTLC(rHash [32]byte) (bool, error) {
	return true, nil

}

func (r *Validator) validateLocalCommitment(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a Local Commitment transaction.")

	if packet.UnsignedTx != nil && len(packet.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("expected 1 input for commitment "+""+
			"transaction for packet: %v", packet)
	}

	outPoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: outPoint.Hash[:],
		},
		OutputIndex: outPoint.Index,
	}

	var (
		toLocalFound, toRemoteFound, localAnchorFound,
		remoteAnchorFound bool
	)

	for _, output := range packet.Outputs {
		if len(output.Unknowns) <= 0 {
			return nil, fmt.Errorf("commitment outputs should " +
				"have metadata attached")
		}

		k := output.Unknowns[0].Key

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeToLocal):
			if toLocalFound {
				return nil, fmt.Errorf("multiple to_local" +
					"outputs in local commitment tx")
			}
			toLocalFound = true

			cpMetadata, err := r.extractChannelPartyOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				cpMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			toLocalScript, err := lnwallet.CommitScriptToSelf(
				commitmentInfo.ChanType,
				commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToLocalKey,
				commitmentInfo.CommitmentKeys.RevocationKey,
				cpMetadata.CsvDelay, cpMetadata.LeaseExpiry,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				toLocalScript.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not match " +
					"for to_local output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for to_local output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeToRemote):
			if toRemoteFound {
				return nil, fmt.Errorf("multiple to_remote" +
					"outputs in local commitment tx")
			}
			toRemoteFound = true

			cpMetadata, err := r.extractChannelPartyOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				cpMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
				commitmentInfo.ChanType,
				commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToRemoteKey,
				cpMetadata.LeaseExpiry, input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				toRemoteScript.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for to_remote output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for to_remote output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeIncomingHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				htlcMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, true, lntypes.Local,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for incoming HTLC output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for incoming HTLC output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeOfferedHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			isWhitelisted, err := r.isWhitelistedHTLC(
				htlcMetadata.RHash,
			)
			if err != nil {
				return nil, err
			}

			if !isWhitelisted {
				log.Errorf("Found non whitelisted HTLC in "+
					"local commitment transaction: %v",
					htlcMetadata.RHash)

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("Found non " +
						"whitelisted HTLC in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

			commitmentInfo, err := r.getCommitmentKeys(
				htlcMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, false, lntypes.Local,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for incoming HTLC output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for incoming HTLC output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeLocalAnchor):
			if localAnchorFound {
				return nil, fmt.Errorf("multiple local " +
					"anchor outputs in local commitment " +
					"tx")
			}
			localAnchorFound = true

			anchorMetadata, err := r.extractAnchorOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				anchorMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			localAnchor, _, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				localAnchor.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for local anchor output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for local anchor output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeRemoteAnchor):
			if remoteAnchorFound {
				return nil, fmt.Errorf("multiple remote " +
					"anchor outputs in local commitment " +
					"tx")
			}
			remoteAnchorFound = true

			anchorMetadata, err := r.extractAnchorOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				anchorMetadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			_, remoteAnchor, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				remoteAnchor.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Remote commitment script does not " +
					"match for remote anchor output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for remote anchor output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			}

		default:
			return nil, fmt.Errorf("unknown output type in " +
				"commitment transaction")
		}
	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateCooperativeClose(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a Cooperative Close transaction.")

	// Option 2:
	// We ignore checking the remote output, and instead only check
	// if the transaction contains an output for us. We consider it
	// to be our output if it contains an output address that's
	// either internal in the wallet, or is whitelisted (i.e. a
	// DeliveryAddress has been set for us).
	// NOTE: As our output in the closing tx can be trimmed, if an
	// output has been trimmed we check if that non-trimmed output
	// in the closure tx should be ours or not. We determine that in
	// that scenario if the to_local output amount in our
	// last local commitment tx was above the value for the to_remote
	// output.

	// If an output was trimmed checks if the to_local output value
	// in our last commitment tx was above the to_remote value.
	if len(packet.Outputs) == 1 && !r.requireOurOutputInCoopClose(packet) {
		// If not we won't require that a local output exists in
		// the closing tx.
		return ValidationSuccessResult(), nil
	}

	// Else the tx should have 2 outputs, where one of the outputs
	// should be ours.
	for _, output := range packet.Outputs {

		// isOurOutput checks if the output address is derived from a
		// local key, or is a whitelisted address
		isOurOutput := func(output psbt.POutput) bool {
			return true
		}

		if isOurOutput(output) {
			// Found the local output.
			return ValidationSuccessResult(), nil
		}

	}

	res := ValidationFailureResult("Could not find local "+
		"output in cooperative closing "+
		"transaction %v", packet)

	return res, nil
}

// requireKnownOutput checks if the amount of our to_local output was above the
// value of the to_remote output in our last local commitment tx was above the
// value for the to_remote output.
func (r *Validator) requireOurOutputInCoopClose(packet *psbt.Packet) bool {
	return true
}

func (r *Validator) validateLocalSecondLevelHTLCTx(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a second level HTLC transaction.")

	var (
		sloFound bool
	)

	for _, output := range packet.Outputs {
		if len(output.Unknowns) <= 0 {
			// Default sweep output

			continue
		}

		k := output.Unknowns[0].Key

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeSecondLevelHTLC):
			// TODO: MUST VALIDATE THAT WE DON'T SWEEP MULTIPLE
			// SECOND LEVEL TXes at the same time. If we do, this
			// will fail.
			if sloFound {
				return nil, fmt.Errorf("multiple second " +
					"level outputs in local second level " +
					"HTLC tx")
			}
			sloFound = true

			metadata, err := r.extractSecondLevelHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			chanPoint := &lnrpc.ChannelPoint{
				FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
					FundingTxidBytes: metadata.fundingOutpoint.Hash[:],
				},
				OutputIndex: metadata.fundingOutpoint.Index,
			}

			commitmentInfo, err := r.getCommitmentKeys(
				metadata.CommitPoint, chanPoint,
				lntypes.Local,
			)
			if err != nil {
				return nil, err
			}

			// TODO: THIS MUST BE REPLACED FOR TAPROOT
			// input.AuxTapLeaf{}
			// With:
			// fn.FlattenOption(remoteAuxLeaf),
			secondLevelScript, err := lnwallet.SecondLevelHtlcScript(
				commitmentInfo.ChanType,
				commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.RevocationKey,
				commitmentInfo.CommitmentKeys.ToLocalKey,
				metadata.CommitPoint, metadata.CsvDelay,
				metadata.LeaseExpiry, metadata.fundingOutpoint,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				secondLevelScript.PkScript(), output.RedeemScript,
			)

			if !scriptMatches {
				log.Errorf("Second level HTLC output script does not " +
					"match for local second level HTLC tx")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for Second level HTLC output  in " +
						"local second level HTLC transaction")
					return failRes, nil

				*/
			}

		default:
			return nil, fmt.Errorf("unknown output type in " +
				"commitment transaction")
		}

	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateRemoteSecondLevelHTLCTx(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a second level HTLC transaction.")

	for _, output := range packet.Outputs {
		if len(output.Unknowns) <= 0 {
			// Default sweep output

			continue
		}

		k := output.Unknowns[0].Key

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeSecondLevelHTLC):

		default:
			return nil, fmt.Errorf("unknown output type in " +
				"commitment transaction")
		}

	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateFundingTransaction(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a funding transaction.")

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateDefaultTransaction(
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a default transaction.")

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
func (r *Validator) AddMetadata(_ []byte) error {
	return nil
}

// A compile time assertion to ensure Validator meets the Validation interface.
var _ Validation = (*Validator)(nil)
