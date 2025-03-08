//go:build !dev
// +build !dev

package validator

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

func ValidateCompatibleConfig(dbCfg *lncfg.DB) error {
	if !dbCfg.UseNativeSQL {
		return errors.New("config flag DB.UseNativeSQL must be set to" +
			"use remote signer validation")
	}

	return nil
}

// Validator is currently a no-op validator that runs in the production env.
type Validator struct {
	network        *chaincfg.Params
	remoteSignerDB RemoteSignerDB
}

// NewValidator creates a new Validator instance.
func NewValidator(remoteSignerDB RemoteSignerDB,
	network *chaincfg.Params) *Validator {

	return &Validator{
		remoteSignerDB: remoteSignerDB,
		network:        network,
	}
}

// ValidatePSBT always determines that the provided SignPsbtRequest should be
// signed.
func (r *Validator) ValidatePSBT(ctx context.Context,
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
		return r.validateRemoteCommitment(ctx, packet)

	case LocalCommitment:
		return r.validateLocalCommitment(ctx, packet)

	case CooperativeClose:
		return r.validateCooperativeClose(ctx, packet)

	case FundingTransaction:
		return r.validateFundingTransaction(packet)

	case LocalSecondLevelHTLCTransaction:
		return r.validateLocalSecondLevelHTLCTx(ctx, packet)

	case RemoteSecondLevelHTLCTransaction:
		return r.validateRemoteSecondLevelHTLCTx(ctx, packet)

	case Unknown:
		return r.validateDefaultTransaction(ctx, packet)

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
			return LocalSecondLevelHTLCTransaction, nil
		case bytes.Equal(k, input.PsbtKeyRemoteSecondLevelHTLCTransaction):
			return RemoteSecondLevelHTLCTransaction, nil
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

func (r *Validator) validateRemoteCommitment(ctx context.Context,
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

	for i, output := range packet.Outputs {
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
				ctx, cpMetadata.CommitPoint, chanPoint,
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
				toLocalScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for to_local " +
					"output")
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
				ctx, cpMetadata.CommitPoint, chanPoint,
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
				toRemoteScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for to_remote " +
					"output")
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeIncomingHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, htlcMetadata.CommitPoint, chanPoint,
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
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for incoming HTLC " +
					"output")
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeOfferedHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			isWhitelisted, err := r.isWhitelistedHTLC(
				ctx, htlcMetadata.RHash,
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
			} else {
				log.Infof("!!!! Whitelisted HTLC found in remote " +
					"commitment transaction")
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, htlcMetadata.CommitPoint, chanPoint,
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
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for offered HTLC " +
					"output")
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
				ctx, anchorMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
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
				remoteAnchor.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for local anchor " +
					"output")
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
				ctx, anchorMetadata.CommitPoint, chanPoint,
				lntypes.Remote,
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
				localAnchor.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Remote commitment script matches for remote anchor " +
					"output")
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

func NewChannelPartyOutputMetadata(commitPoint *btcec.PublicKey,
	csvDelay, leaseExpiry uint32) (*ChannelPartyOutputMetadata, error) {

	return &ChannelPartyOutputMetadata{
		CommitPoint: commitPoint,
		CsvDelay:    csvDelay,
		LeaseExpiry: leaseExpiry,
	}, nil
}

type HTLCOutputMetadata struct {
	CommitPoint *btcec.PublicKey
	CltvExpiry  uint32
	RHash       [32]byte
}

func NewHTLCOutputMetadata(commitPoint *btcec.PublicKey, cltvExpiry uint32,
	rHash [32]byte) (*HTLCOutputMetadata, error) {

	return &HTLCOutputMetadata{
		CommitPoint: commitPoint,
		CltvExpiry:  cltvExpiry,
		RHash:       rHash,
	}, nil
}

type AnchorOutputMetadata struct {
	CommitPoint *btcec.PublicKey
}

func NewAnchorOutputMetadata(commitPoint *btcec.PublicKey) (
	*AnchorOutputMetadata, error) {

	return &AnchorOutputMetadata{
		CommitPoint: commitPoint,
	}, nil
}

type SecondLevelHTLCOutputMetadata struct {
	CommitPoint     *btcec.PublicKey
	CsvDelay        uint32
	LeaseExpiry     uint32
	FundingOutpoint *wire.OutPoint
}

func NewSecondLevelHTLCOutputMetadata(commitPoint *btcec.PublicKey,
	fundingOutpoint *wire.OutPoint,
	csvDelay, leaseExpiry uint32) (*SecondLevelHTLCOutputMetadata, error) {

	return &SecondLevelHTLCOutputMetadata{
		CommitPoint:     commitPoint,
		FundingOutpoint: fundingOutpoint,
		CsvDelay:        csvDelay,
		LeaseExpiry:     leaseExpiry,
	}, nil
}

func (r *Validator) extractChannelPartyOutputMetadata(
	unknowns input.SignInfo) (*ChannelPartyOutputMetadata, error) {

	var (
		commitPoint                           *btcec.PublicKey
		csvDelay, leaseExpiry                 uint32
		fCommitPoint, fCsvDelay, fLeaseExpiry bool
	)

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in channel party output")
			}

			fCommitPoint = true

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			commitPoint = commitP
		case bytes.Equal(k, input.PsbtKeyTypeOutputCsvDelay):
			if fCsvDelay {
				return nil, fmt.Errorf("multiple csv delays " +
					"found in channel party output")
			}

			fCsvDelay = true

			delay, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			csvDelay = delay
		case bytes.Equal(k, input.PsbtKeyTypeOutputLeaseExpiry):
			if fLeaseExpiry {
				return nil, fmt.Errorf("multiple lease " +
					"expiries found in channel party " +
					"output")
			}

			fLeaseExpiry = true

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			leaseExpiry = expiry
		}
	}

	if !fCommitPoint || !fCsvDelay || !fLeaseExpiry {
		return nil, fmt.Errorf("missing metadata in channel party "+
			"output metadata. commit point: %v, csv delay: %v, "+
			"lease expiry: %v", fCommitPoint, fCsvDelay,
			fLeaseExpiry)
	}

	return NewChannelPartyOutputMetadata(commitPoint, csvDelay, leaseExpiry)
}

func (r *Validator) extractHTLCOutputMetadata(
	unknowns input.SignInfo) (*HTLCOutputMetadata, error) {

	var (
		commitPoint *btcec.PublicKey
		cltvExpiry  uint32
		rHash       [32]byte

		fCommitPoint, fCltvExpiry, fRHash bool
	)

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in HTLC output")
			}

			fCommitPoint = true

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			commitPoint = commitP

		case bytes.Equal(k, input.PsbtKeyTypeOutputCltvExpiry):
			if fCltvExpiry {
				return nil, fmt.Errorf("multiple cltv " +
					"expiries found in HTLC output")
			}

			fCltvExpiry = true

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			cltvExpiry = expiry

		case bytes.Equal(k, input.PsbtKeyTypeOutputRHash):
			if fRHash {
				return nil, fmt.Errorf("multiple r hashes " +
					"found in HTLC output")
			}

			fRHash = true

			if len(unknown.Value) != 32 {
				return nil, fmt.Errorf("r hash in metadata " +
					"is not 32 bytes")
			}

			copy(rHash[:], unknown.Value)
		}
	}

	if !fCommitPoint || !fCltvExpiry || !fRHash {
		return nil, fmt.Errorf("missing metadata in HTLC output "+
			"metadata. commit point: %v, cltv expiry: %v, +"+
			"r hash: %v", fCommitPoint, fCltvExpiry, fRHash)
	}

	return NewHTLCOutputMetadata(commitPoint, cltvExpiry, rHash)
}

func (r *Validator) extractAnchorOutputMetadata(
	unknowns input.SignInfo) (*AnchorOutputMetadata, error) {

	var (
		commitPoint  *btcec.PublicKey
		fCommitPoint bool
	)

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in anchor output")
			}

			fCommitPoint = true

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			commitPoint = commitP
		}
	}

	if !fCommitPoint {
		return nil, fmt.Errorf("missing metadata in anchor output "+
			"metadata. commit point: %v", fCommitPoint)
	}

	return NewAnchorOutputMetadata(commitPoint)
}

func (r *Validator) extractSecondLevelHTLCOutputMetadata(
	unknowns input.SignInfo) (*SecondLevelHTLCOutputMetadata, error) {

	var (
		commitPoint           *btcec.PublicKey
		fundingOutpoint       *wire.OutPoint
		csvDelay, leaseExpiry uint32

		fCommitPoint, fFundingOutpoint, fCsvDelay, fLeaseExpiry bool
	)

	for _, unknown := range unknowns {
		k := unknown.Key

		log.Infof("unknown is: %v", unknown)

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputFundingPoint):
			if fFundingOutpoint {
				return nil, fmt.Errorf("multiple funding " +
					"points found in second level HTLC " +
					"output")
			}

			fFundingOutpoint = true

			outpointStr := string(unknown.Value)

			outpoint, err := wire.NewOutPointFromString(outpointStr)
			if err != nil {
				return nil, err
			}

			fundingOutpoint = outpoint
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in second level HTLC " +
					"output")
			}

			fCommitPoint = true

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			commitPoint = commitP

		case bytes.Equal(k, input.PsbtKeyTypeOutputCsvDelay):
			if fCsvDelay {
				return nil, fmt.Errorf("multiple csv delays " +
					"found in second level HTLC output")
			}

			fCsvDelay = true

			delay, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			csvDelay = delay

		case bytes.Equal(k, input.PsbtKeyTypeOutputLeaseExpiry):
			if fLeaseExpiry {
				return nil, fmt.Errorf("multiple lease " +
					"expiries found in second level HTLC " +
					"output")
			}

			fLeaseExpiry = true

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			leaseExpiry = expiry
		}
	}

	if !fCommitPoint || !fFundingOutpoint || !fCsvDelay || !fLeaseExpiry {
		return nil, fmt.Errorf("missing metadata in second level HTLC "+
			"output metadata. commit point: %v, funding outpoint: "+
			"%v, csv delay: %v, lease expiry: %v", fCommitPoint,
			fFundingOutpoint, fCsvDelay, fLeaseExpiry,
		)
	}

	return NewSecondLevelHTLCOutputMetadata(
		commitPoint, fundingOutpoint, csvDelay, leaseExpiry,
	)
}

type CommitmentInfo struct {
	CommitmentKeys *lnwallet.CommitmentKeyRing
	*ChanInfo
}

func (r *Validator) getCommitmentKeys(ctx context.Context,
	commitPoint *btcec.PublicKey, chanPoint *lnrpc.ChannelPoint,
	whoseCommit lntypes.ChannelParty) (*CommitmentInfo, error) {

	chanInfo, err := r.getChanInfo(ctx, chanPoint)
	if err != nil {
		return nil, err
	}

	commitmentKeys := lnwallet.DeriveCommitmentKeys(
		commitPoint, whoseCommit, chanInfo.ChanType,
		chanInfo.localChanCfg, chanInfo.remoteChanCfg,
	)

	return &CommitmentInfo{
		CommitmentKeys: commitmentKeys,
		ChanInfo:       chanInfo,
	}, nil
}

type ChanInfo struct {
	IsLocalInitiator            bool
	ChanType                    channeldb.ChannelType
	localChanCfg, remoteChanCfg *channeldb.ChannelConfig
}

// isZeroBytes returns true if all bytes in b are zero.
func isZeroBytes(b []byte) bool {
	return len(b) == 0 || bytes.Equal(b, make([]byte, len(b)))
}

// deMarshalChannelConfig converts an lnrpc.ChannelConfig into a channeldb.ChannelConfig.
func deMarshalChannelConfig(chanConf *lnrpc.ChannelConfig) (
	*channeldb.ChannelConfig, error) {

	// Validate that required nested messages are present.
	if chanConf.ChannelStateBounds == nil {
		return nil, fmt.Errorf("missing ChannelStateBounds")
	}
	if chanConf.CommitmentParams == nil {
		return nil, fmt.Errorf("missing CommitmentParams")
	}
	if chanConf.MultiSigKey == nil ||
		chanConf.RevocationBasePoint == nil ||
		chanConf.PaymentBasePoint == nil ||
		chanConf.DelayBasePoint == nil ||
		chanConf.HtlcBasePoint == nil {
		return nil, fmt.Errorf("missing one or more KeyDescriptor fields")
	}

	// Map ChannelStateBounds.
	stateBounds := channeldb.ChannelStateBounds{
		ChanReserve:      btcutil.Amount(chanConf.ChannelStateBounds.ChanReserveSat),
		MaxPendingAmount: lnwire.MilliSatoshi(chanConf.ChannelStateBounds.MaxPendingAmtMsat),
		MinHTLC:          lnwire.MilliSatoshi(chanConf.ChannelStateBounds.MinHtlc),
		MaxAcceptedHtlcs: uint16(chanConf.ChannelStateBounds.MaxAcceptedHtlcs),
	}

	// Map CommitmentParams.
	commitParams := channeldb.CommitmentParams{
		DustLimit: btcutil.Amount(chanConf.CommitmentParams.DustLimit),
		CsvDelay:  uint16(chanConf.CommitmentParams.CsvDelay),
	}

	// Helper to convert an lnrpc.KeyDescriptor into a keychain.KeyDescriptor.
	convertKeyDesc := func(kd *lnrpc.KeyDescriptor) (keychain.KeyDescriptor, error) {
		// Parse the public key if the raw bytes are non-zero.
		var pubKey *btcec.PublicKey
		if !isZeroBytes(kd.RawKeyBytes) {
			var err error
			pubKey, err = btcec.ParsePubKey(kd.RawKeyBytes)
			if err != nil {
				return keychain.KeyDescriptor{}, fmt.Errorf("unable to parse pubkey: %w", err)
			}
		}
		// Create a keychain.KeyDescriptor using the KeyLocator values.
		// Here we assume kd.KeyLoc is non-nil.
		if kd.KeyLoc == nil {
			return keychain.KeyDescriptor{}, fmt.Errorf("missing KeyLoc in KeyDescriptor")
		}

		return keychain.KeyDescriptor{
			KeyLocator: keychain.KeyLocator{
				Family: keychain.KeyFamily(uint32(kd.KeyLoc.KeyFamily)),
				Index:  uint32(kd.KeyLoc.KeyIndex),
			},
			PubKey: pubKey,
		}, nil
	}

	// Convert each key descriptor.
	multiSigKey, err := convertKeyDesc(chanConf.MultiSigKey)
	if err != nil {
		return nil, fmt.Errorf("error converting MultiSigKey: %w", err)
	}
	revocationKey, err := convertKeyDesc(chanConf.RevocationBasePoint)
	if err != nil {
		return nil, fmt.Errorf("error converting RevocationBasePoint: %w", err)
	}
	paymentKey, err := convertKeyDesc(chanConf.PaymentBasePoint)
	if err != nil {
		return nil, fmt.Errorf("error converting PaymentBasePoint: %w", err)
	}
	delayKey, err := convertKeyDesc(chanConf.DelayBasePoint)
	if err != nil {
		return nil, fmt.Errorf("error converting DelayBasePoint: %w", err)
	}
	htlcKey, err := convertKeyDesc(chanConf.HtlcBasePoint)
	if err != nil {
		return nil, fmt.Errorf("error converting HtlcBasePoint: %w", err)
	}

	// Construct the channeldb.ChannelConfig.
	chConfig := &channeldb.ChannelConfig{
		ChannelStateBounds:  stateBounds,
		CommitmentParams:    commitParams,
		MultiSigKey:         multiSigKey,
		RevocationBasePoint: revocationKey,
		PaymentBasePoint:    paymentKey,
		DelayBasePoint:      delayKey,
		HtlcBasePoint:       htlcKey,
	}

	return chConfig, nil
}

func (r *Validator) getChanInfo(ctx context.Context,
	chanPoint *lnrpc.ChannelPoint) (*ChanInfo, error) {

	dbChanInfo, err := r.remoteSignerDB.GetFundingInfo(ctx, chanPoint)
	if err != nil {
		return nil, err
	}

	localConf, err := deMarshalChannelConfig(
		dbChanInfo.GetLocalChannelConfig(),
	)
	if err != nil {
		return nil, err
	}

	remoteConf, err := deMarshalChannelConfig(
		dbChanInfo.GetRemoteChannelConfig(),
	)
	if err != nil {
		return nil, err
	}

	chanInfo := &ChanInfo{
		IsLocalInitiator: dbChanInfo.GetIsLocalInitiator(),
		ChanType:         channeldb.ChannelType(dbChanInfo.ChannelType),
		localChanCfg:     localConf,
		remoteChanCfg:    remoteConf,
	}

	return chanInfo, nil
}

func (r *Validator) isWhitelistedHTLC(ctx context.Context,
	rHash [32]byte) (bool, error) {

	// TODO: check if this can be done in a cleaner way in terms of maybe
	// checking the error.
	pHash, err := r.remoteSignerDB.GetWhitelistedPaymentHash(ctx, rHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// No whitelisted payment hash found.
			return false, nil
		}
		return false, err
	}
	if len(pHash) != 32 {
		return false, errors.New("whitelisted payment hash is not 32 " +
			"bytes")
	}

	return true, nil
}

func (r *Validator) validateLocalCommitment(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a Local Commitment transaction.")

	isNextCommitment, err := r.ensureCommitmentIsNotRevoked(ctx, packet)
	if err != nil {
		return nil, err
	}

	if !isNextCommitment {
		return nil, fmt.Errorf("revoked state detected in request " +
			"to force close channel with local commitment " +
			"transaction")
	}

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

	for i, output := range packet.Outputs {
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
				ctx, cpMetadata.CommitPoint, chanPoint,
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
				toLocalScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Local commitment script matches for to_local " +
					"output")
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
				ctx, cpMetadata.CommitPoint, chanPoint,
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
				toRemoteScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Local commitment script matches for to_remote " +
					"output")
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeIncomingHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, htlcMetadata.CommitPoint, chanPoint,
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
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Local commitment script matches for incoming HTLC " +
					"output")
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeOfferedHTLC):
			htlcMetadata, err := r.extractHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			isWhitelisted, err := r.isWhitelistedHTLC(
				ctx, htlcMetadata.RHash,
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
			} else {
				log.Infof("!!!! Whitelisted HTLC found in remote " +
					"commitment transaction")
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, htlcMetadata.CommitPoint, chanPoint,
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
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for offered HTLC output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for offered HTLC output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			} else {
				log.Infof("!!!! Local commitment script matches for offered HTLC " +
					"output")
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
				ctx, anchorMetadata.CommitPoint, chanPoint,
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
				localAnchor.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
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
			} else {
				log.Infof("!!!! Local commitment script matches for local anchor " +
					"output")
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
				ctx, anchorMetadata.CommitPoint, chanPoint,
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
				remoteAnchor.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("Local commitment script does not " +
					"match for remote anchor output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for remote anchor output in " +
						"local commitment transaction")
					return failRes, nil

				*/
			} else {
				log.Infof("!!!! Local commitment script matches for remote anchor " +
					"output")
			}

		default:
			return nil, fmt.Errorf("unknown output type in " +
				"commitment transaction")
		}
	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateCooperativeClose(ctx context.Context,
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

	requireOurOutput, err := r.requireOurOutputInCoopClose(ctx, packet)
	if err != nil {
		return nil, err
	}

	// If an output was trimmed checks if the to_local output value
	// in our last commitment tx was above the to_remote value.
	if len(packet.Outputs) == 1 && requireOurOutput {
		// If not we won't require that a local output exists in
		// the closing tx.
		return ValidationSuccessResult(), nil
	}

	// Else the tx should contain our to_local output. We therefore loop
	// over all outputs until we find our to_local output, which is either
	// an internal address, or a whitelisted address (a delivery address has
	// been set for the channel).
	for oIndex, _ := range packet.Outputs {
		isOurInput, err := r.isOurOutput(ctx, packet, oIndex)
		if err != nil {
			return nil, err
		}

		if isOurInput {
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
func (r *Validator) requireOurOutputInCoopClose(ctx context.Context,
	packet *psbt.Packet) (bool, error) {

	chanPoint, err := r.getChanPoint(packet)
	if err != nil {
		return false, err
	}

	localCommitment, err := r.remoteSignerDB.GetLatestLocalCommitment(
		ctx, chanPoint.GetFundingTxidBytes(),
		chanPoint.GetOutputIndex(),
	)
	if err != nil {
		return false, err
	}

	lastPacket, err := psbt.NewFromRawBytes(
		bytes.NewReader(localCommitment.CommitmentTxPackage), false,
	)
	if err != nil {
		return false, err
	}

	var toLocalAmount, toRemoteAmount int64

	// Find the to_local and to_remote outputs in the last local
	// commitment tx. If either of them didn't exist, that's ok as we'll
	// count the value of them as 0. We're sure that the last local
	// commitment was valid, as we've already checked that when adding it
	// to the database.
	for i, output := range lastPacket.Outputs {
		if len(output.Unknowns) <= 0 {
			return false, fmt.Errorf("commitment outputs should " +
				"have metadata attached")
		}

		k := output.Unknowns[0].Key

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeToLocal):
			toLocalAmount = lastPacket.UnsignedTx.TxOut[i].Value
		case bytes.Equal(k, input.PsbtKeyOutputTypeToRemote):
			toRemoteAmount = lastPacket.UnsignedTx.TxOut[i].Value
		}

	}

	return toLocalAmount > toRemoteAmount, nil
}

func (r *Validator) validateLocalSecondLevelHTLCTx(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a second level HTLC transaction.")

	var (
		sloFound bool
	)

	for outputIndex, output := range packet.Outputs {
		if len(output.Unknowns) <= 0 {
			return nil, fmt.Errorf("second level transaction " +
				"outputs should have metadata attached")
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
					FundingTxidBytes: metadata.FundingOutpoint.Hash[:],
				},
				OutputIndex: metadata.FundingOutpoint.Index,
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, metadata.CommitPoint, chanPoint,
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
				metadata.LeaseExpiry, *metadata.FundingOutpoint,
				input.AuxTapLeaf{},
			)
			if err != nil {
				return nil, err
			}

			// TODO: Needs to be correct byte arrays being matched.
			scriptMatches := bytes.Equal(
				secondLevelScript.PkScript(),
				packet.UnsignedTx.TxOut[outputIndex].PkScript,
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
			} else {
				log.Infof("!!!! Second level HTLC output script matches")
			}

		default:
			// All other outputs must be either internal or
			// whitelisted
			isOurOutput, err := r.isOurOutput(
				ctx, packet, outputIndex,
			)
			if err != nil {
				return nil, err
			}

			if !isOurOutput {
				log.Errorf("Output in Second level HTLC " +
					"transaction isn't our output")

				// TODO: Comment back
				/*
					failRes := ValidationFailureResult("output script " +
						"not matching for Second level HTLC output  in " +
						"local second level HTLC transaction")
					return failRes, nil

				*/
			}
		}

	}

	if !sloFound {
		log.Errorf("Did not find second level HTLC output")

		// TODO: Comment back
		/*
			failRes := ValidationFailureResult("Did not find " +
				"second level HTLC output")
			return failRes, nil

		*/
	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateRemoteSecondLevelHTLCTx(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a second level HTLC transaction.")

	if len(packet.Outputs) != 1 {
		log.Errorf("Remote second level HTLC transaction MUST contain " +
			"exactly one output when signed by us.")

		/*failRes := ValidationFailureResult("Remote second level HTLC " +
			"transaction MUST contain exactly one output when " +
			"signed by us")

		return failRes, nil*/

		//TODO:! REMOVE
		return ValidationSuccessResult(), nil
	}

	output := packet.Outputs[0]

	if len(output.Unknowns) <= 0 {
		return nil, fmt.Errorf("second level transaction " +
			"outputs should have metadata attached")
	}

	if !bytes.Equal(output.Unknowns[0].Key, input.PsbtKeyOutputTypeSecondLevelHTLC) {
		return nil, fmt.Errorf("remote second level transaction " +
			"output should be of type " +
			"input.PsbtKeyOutputTypeSecondLevelHTLC")
	}

	metadata, err := r.extractSecondLevelHTLCOutputMetadata(
		output.Unknowns[1:],
	)
	if err != nil {
		//TODO:! REMOVE
		log.Infof("error extracting second level metadata: %v", err)
		return ValidationSuccessResult(), nil

		return nil, err
	}

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: metadata.FundingOutpoint.Hash[:],
		},
		OutputIndex: metadata.FundingOutpoint.Index,
	}

	commitmentInfo, err := r.getCommitmentKeys(
		ctx, metadata.CommitPoint, chanPoint, lntypes.Remote,
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
		metadata.LeaseExpiry, *metadata.FundingOutpoint,
		input.AuxTapLeaf{},
	)
	if err != nil {
		return nil, err
	}

	// TODO: Needs to be correct byte arrays being matched.
	scriptMatches := bytes.Equal(
		secondLevelScript.PkScript(),
		packet.UnsignedTx.TxOut[0].PkScript,
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
	} else {
		log.Infof("!!!! Second level HTLC output script matches")
	}

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateFundingTransaction(
	_ *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a funding transaction.")

	//TODO: Add blocking of this for now.
	/*failRes := ValidationFailureResult("Signing of funding transactions " +
		"are not currently supported")
	return failRes, nil*/

	return ValidationSuccessResult(), nil
}

func (r *Validator) validateDefaultTransaction(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("This is a default transaction.")

	// In a default transaction, all outputs must be either whitelisted or
	// internal addresses.
	for outputIndex, _ := range packet.Outputs {
		isOurOutput, err := r.isOurOutput(
			ctx, packet, outputIndex,
		)
		if err != nil {
			return nil, err
		}

		if !isOurOutput {
			log.Errorf("Output in default transaction isn't ours")

			// TODO: Comment back
			/*
				failRes := ValidationFailureResult("output script " +
					"not matching for Second level HTLC output  in " +
					"local second level HTLC transaction")
				return failRes, nil

			*/
		}
	}

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

	switch reqType := metadata.GetMetadataType().(type) {

	case *walletrpc.MetadataRequest_LocalCommitmentInfo:
		return r.AddLocalCommitmentMetadata(
			ctx, reqType.LocalCommitmentInfo,
		)

	case *walletrpc.MetadataRequest_FundingInfo:
		return r.AddFundingMetadata(
			ctx, reqType.FundingInfo,
		)

	default:
		// When we don't know the metadata type, we log an error but
		// return nil, as the watch-only node might be using a newer
		// version of lnd that sends metadata we don't know about.
		log.Errorf("Unknown metadata type: %v", reqType)

		return nil
	}
}

func (r *Validator) AddFundingMetadata(ctx context.Context,
	chanInfo *walletrpc.FundingInfo) error {

	log.Infof("Adding metadata for funding info")

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: chanInfo.FundingOutpoint.TxidBytes,
		},
		OutputIndex: chanInfo.FundingOutpoint.GetOutputIndex(),
	}

	// First lets check that information regarding this channel doesn't
	// exist in the database.
	fInfo, err := r.remoteSignerDB.GetFundingInfo(ctx, chanPoint)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return errors.New("Errors quering the database for funding " +
			"info: " + err.Error())
	} else if fInfo != nil {
		return errors.New("Funding info already exists in the database")
	}

	log.Infof("Inserting info for the new channel into the database")

	_, err = r.remoteSignerDB.AddFundingInfo(ctx, chanInfo)

	return err
}

func (r *Validator) AddLocalCommitmentMetadata(ctx context.Context,
	localCommitment *walletrpc.SignPsbtRequest) error {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(localCommitment.GetFundedPsbt()), false,
	)
	if err != nil {
		return err
	}

	// We validate the commitment tx, to ensure that we don't end up with
	// a commitment transaction locally that's not correct.
	res, err := r.validateLocalCommitment(ctx, packet)
	if err != nil {
		return err
	}

	if res.Type == ValidationFailure {
		return errors.New("invalid local commitment transaction " +
			"as metadata: " + res.FailureDetails)
	}

	transactionType, err := r.getTransactionType(packet)
	if err != nil {
		return err
	}

	log.Infof("Adding metadata for local commitment transaction")

	log.Infof("packet is: %v", packet)
	log.Infof("transaction type for request is: %s",
		transactionType.String())

	if transactionType != LocalCommitment {
		return errors.New("only local commitment transactions are " +
			"supported as metadata")
	}

	chanPoint, err := r.getChanPoint(packet)
	if err != nil {
		return err
	}

	commitmentHeight, err := r.getCommitmentHeight(ctx, packet)
	if err != nil {
		return err
	}

	return r.remoteSignerDB.InsertLocalCommitment(ctx,
		localCommitment.GetFundedPsbt(),
		chanPoint.GetFundingTxidBytes(), chanPoint.OutputIndex,
		commitmentHeight,
	)
}

func (r *Validator) getCommitmentHeight(ctx context.Context,
	packet *psbt.Packet) (uint64, error) {

	chanPoint, err := r.getChanPoint(packet)
	if err != nil {
		return 0, err
	}

	chanInfo, err := r.getChanInfo(ctx, chanPoint)
	if err != nil {
		return 0, err
	}

	var obfuscator [lnwallet.StateHintSize]byte
	if chanInfo.IsLocalInitiator {
		obfuscator = lnwallet.DeriveStateHintObfuscator(
			chanInfo.localChanCfg.PaymentBasePoint.PubKey,
			chanInfo.remoteChanCfg.PaymentBasePoint.PubKey,
		)
	} else {
		obfuscator = lnwallet.DeriveStateHintObfuscator(
			chanInfo.remoteChanCfg.PaymentBasePoint.PubKey,
			chanInfo.localChanCfg.PaymentBasePoint.PubKey,
		)
	}

	commitmentHeight := lnwallet.GetStateNumHint(
		packet.UnsignedTx, obfuscator,
	)

	log.Infof("!!!! Commitment height is: %d", commitmentHeight)

	return commitmentHeight, nil
}

func (r *Validator) getChanPoint(packet *psbt.Packet) (
	*lnrpc.ChannelPoint, error) {

	if packet.UnsignedTx != nil && len(packet.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("expected 1 input for commitment "+
			"transaction for packet: %v", packet)
	}

	outPoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint

	chanPoint := &lnrpc.ChannelPoint{
		FundingTxid: &lnrpc.ChannelPoint_FundingTxidBytes{
			FundingTxidBytes: outPoint.Hash[:],
		},
		OutputIndex: outPoint.Index,
	}

	return chanPoint, nil
}

// ValidatePSBT validates that the commitment transaction is either the latest
// known commitment height, or later than the current commitment height.
func (r *Validator) ensureCommitmentIsNotRevoked(ctx context.Context,
	packet *psbt.Packet) (bool, error) {

	transactionType, err := r.getTransactionType(packet)
	if err != nil {
		return false, err
	}

	if transactionType != LocalCommitment {
		return false, errors.New("only local commitment transactions " +
			"can be checked if they've been revoked")
	}

	chanPoint, err := r.getChanPoint(packet)
	if err != nil {
		return false, err
	}

	commitmentHeight, err := r.getCommitmentHeight(ctx, packet)
	if err != nil {
		return false, err
	}

	currentCommitment, err := r.remoteSignerDB.GetLatestLocalCommitment(
		ctx, chanPoint.GetFundingTxidBytes(), chanPoint.OutputIndex,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Infof("First time seeing a commitment tx for this "+
				"Cchannel: %v", chanPoint)

			// If it's the first commitment tx, we don't treat the
			// local commitment as revoked.
			return true, nil
		}

		return false, err
	}

	if currentCommitment.CommitmentHeight > commitmentHeight {
		return false, nil
	}

	return true, nil
}

func (r *Validator) isAddressInternal(key *hdkeychain.ExtendedKey,
	accountPath []uint32, keysToCheck uint32,
	matchAddressPkScript []byte) (bool, error) {

	var currentKey = key
	for idx, pathPart := range accountPath {
		derivedKey, err := currentKey.DeriveNonStandard(pathPart)
		if err != nil {
			return false, err
		}

		// There's this special case in lnd's wallet (btcwallet) where
		// the coin type and account keys are always serialized as a
		// string and encrypted, which actually fixes the key padding
		// issue that makes the difference between DeriveNonStandard and
		// Derive. To replicate lnd's behavior exactly, we need to
		// serialize and de-serialize the extended key at the coin type
		// and account level (depth = 2 or depth = 3). This does not
		// apply to the default account (id = 0) because that is always
		// derived directly.
		depth := derivedKey.Depth()
		keyID := pathPart - hdkeychain.HardenedKeyStart
		nextID := uint32(0)
		if depth == 2 && len(accountPath) > 2 {
			nextID = accountPath[idx+1] - hdkeychain.HardenedKeyStart
		}
		if (depth == 2 && nextID != 0) || (depth == 3 && keyID != 0) {
			currentKey, err = hdkeychain.NewKeyFromString(
				derivedKey.String(),
			)
			if err != nil {
				return false, err
			}
		} else {
			currentKey = derivedKey
		}
	}

	for i := uint32(0); i < keysToCheck; i++ {
		addrKey, err := currentKey.DeriveNonStandard(i)
		if err != nil {
			return false, err
		}

		addrPubKey, err := addrKey.ECPubKey()
		if err != nil {
			return false, err
		}

		pubKeyHash := btcutil.Hash160(addrPubKey.SerializeCompressed())
		witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(
			pubKeyHash, r.network,
		)
		if err != nil {
			return false, err
		}

		witnessProgram, err := txscript.PayToAddrScript(witnessAddr)
		if err != nil {
			return false, err
		}

		np2wkhAddr, err := btcutil.NewAddressScriptHash(
			witnessProgram, r.network,
		)
		if err != nil {
			return false, err
		}

		pkScript, err := txscript.PayToAddrScript(np2wkhAddr)
		if err != nil {
			return false, err
		}

		if bytes.Equal(pkScript, matchAddressPkScript) {
			return true, nil
		}
	}

	return false, nil
}

// isOurOutput checks if the output address is derived from a
// local key, or is a whitelisted address
func (r *Validator) isOurOutput(ctx context.Context, packet *psbt.Packet,
	outputIndex int) (bool, error) {

	isWhitelisted, err := r.isWhiteListedAddress(ctx, packet, outputIndex)
	if err != nil {
		return false, err
	}

	if isWhitelisted {
		return true, nil
	}

	//TODO:! Remove
	log.Infof("Returning true for if output is internal")
	return true, nil

	isInternal, err := r.isAddressInternal(
		nil, nil, 10000,
		packet.UnsignedTx.TxOut[outputIndex].PkScript,
	)
	if err != nil {
		return false, err
	}

	return isInternal, nil
}

// isOurOutput checks if the output address at the specified index is
// whitelisted.
func (r *Validator) isWhiteListedAddress(ctx context.Context,
	packet *psbt.Packet, outputIndex int) (bool, error) {

	outputScript := packet.UnsignedTx.TxOut[outputIndex].PkScript

	addresses, err := r.remoteSignerDB.ListWhitelistedAddresses(ctx)
	if err != nil {
		return false, err
	}

	for _, address := range addresses {
		addr, err := btcutil.DecodeAddress(address, r.network)
		if err != nil {
			return false, fmt.Errorf("unable to decode address: %w",
				err)
		}

		if bytes.Equal(addr.ScriptAddress(), outputScript) {
			log.Debugf("address %s, is whitelisted", address)

			return true, nil
		}
	}

	return false, nil
}

// A compile time assertion to ensure Validator meets the Validation interface.
var _ Validation = (*Validator)(nil)
