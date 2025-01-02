package validator

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lightningnetwork/lnd/channeldb"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/lnwallet"
	"github.com/lightningnetwork/lnd/lnwire"
	"strconv"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
)

const (
	HardenedKeyStart = uint32(hdkeychain.HardenedKeyStart)
)

func ValidateCompatibleConfig(dbCfg *lncfg.DB) error {
	if !dbCfg.UseNativeSQL {
		return errors.New("config flag DB.UseNativeSQL must be set to" +
			"use remote signer validation")
	}

	return nil
}

// HalfValidator is currently a no-op validator that runs in the production env.
type HalfValidator struct {
	network        *chaincfg.Params
	remoteSignerDB RemoteSignerDB
	accounts       []*walletrpc.Account

	allowFunding bool

	// muSig2Packets holds the transaction packets for MuSig2Sessions.
	// The key for the Map is the hex string formatted MuSig2 Session ID.
	muSig2Packets map[string]*psbt.Packet

	mu sync.Mutex
}

// NewHalfValidator creates a new HalfValidator instance.
func NewHalfValidator(remoteSignerDB RemoteSignerDB,
	network *chaincfg.Params, allowFunding bool) *HalfValidator {

	return &HalfValidator{
		remoteSignerDB: remoteSignerDB,
		network:        network,
		muSig2Packets:  make(map[string]*psbt.Packet),
		allowFunding:   allowFunding,
	}
}

// ValidatePSBT determines whether the provided SignPsbtRequest should be signed
// or not.
func (r *HalfValidator) ValidatePSBT(ctx context.Context,
	req *walletrpc.SignPsbtRequest) (*ValidationResult, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(req.FundedPsbt), false,
	)
	if err != nil {
		return nil, err
	}

	return r.validatePacket(ctx, packet)
}

// ValidateMuSig2Sign determines whether the provided MuSig2SignRequest should
// be signed or not.
func (r *HalfValidator) ValidateMuSig2Sign(ctx context.Context,
	req *signrpc.MuSig2SignRequest) (*ValidationResult, error) {

	packet, err := r.getMuSig2Packet(ctx, req)
	if err != nil {
		return nil, err
	}

	return r.validatePacket(ctx, packet)
}

// validatePacket will validate if the passed packet should be signed or not.
func (r *HalfValidator) validatePacket(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	transactionType, err := r.getTransactionType(packet)
	if err != nil {
		return nil, err
	}

	log.Debugf("Transaction type for request is: %s",
		transactionType.String())

	log.Tracef("Packet output length is: %d",
		len(packet.Outputs))
	log.Tracef("Transaction output length is: %d",
		len(packet.UnsignedTx.TxOut))
	log.Tracef("Transaction input length is: %d",
		len(packet.UnsignedTx.TxIn))

	if len(packet.Outputs) != len(packet.UnsignedTx.TxOut) {
		return nil, fmt.Errorf("packet Output and " +
			"packet.UnsignedTx.TxOut differs in length")
	}

	switch transactionType {

	case LocalCommitment:
		return r.validateCommitment(ctx, lntypes.Local, packet)

	case RemoteCommitment:
		return r.validateCommitment(ctx, lntypes.Remote, packet)

	case CooperativeClose:
		return r.validateCooperativeClose(ctx, packet)

	case FundingTransaction:
		return r.validateFundingTransaction(packet)

	case LocalSecondLevelHTLCTransaction:
		return r.validateSecondLevelHTLCTx(ctx, lntypes.Local, packet)

	case RemoteSecondLevelHTLCTransaction:
		return r.validateSecondLevelHTLCTx(ctx, lntypes.Remote, packet)

	case Unknown:
		return r.validateDefaultTransaction(ctx, packet)

	default:
		log.Errorf("Unexpected transaction type.")

		err := fmt.Errorf("unexpected transaction type: %v",
			transactionType)

		return nil, fmt.Errorf("unexpected transaction type: %v", err)
	}
}

func (r *HalfValidator) validateCommitment(ctx context.Context,
	whoseCommit lntypes.ChannelParty,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("Validating %s commitment transaction.", whoseCommit.String())

	if packet.UnsignedTx != nil && len(packet.UnsignedTx.TxIn) != 1 {
		return nil, fmt.Errorf("expected 1 input for commitment "+""+
			"transaction for packet: %v", packet)
	}

	outPoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint

	// For local commitment transactions, we need to check that we're not
	// trying to sign a revoked state.
	if whoseCommit.IsLocal() {
		isNextCommitment, err := r.ensureCommitmentIsNotRevoked(
			ctx, packet,
		)
		if err != nil {
			return nil, err
		}

		if !isNextCommitment {
			return nil, fmt.Errorf("revoked state detected in " +
				"request to force close channel with local " +
				"commitment transaction")
		}
	}

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
				return nil, fmt.Errorf("multiple to_local"+
					"outputs in %s commitment tx",
					whoseCommit.String())
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
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			toLocalScript, err := lnwallet.CommitScriptToSelf(
				commitmentInfo.ChanType,
				!commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToLocalKey,
				commitmentInfo.CommitmentKeys.RevocationKey,
				cpMetadata.CsvDelay, cpMetadata.LeaseExpiry,
				cpMetadata.AuxLeaf,
			)
			if err != nil {
				return nil, err
			}

			scriptMatches := bytes.Equal(
				toLocalScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for to_local output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for to_local "+
					"output in %s commitment transaction",
					whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"to_local output", whoseCommit.String())
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeToRemote):
			if toRemoteFound {
				return nil, fmt.Errorf("multiple to_remote"+
					"outputs in %s commitment tx",
					whoseCommit.String())
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
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			toRemoteScript, _, err := lnwallet.CommitScriptToRemote(
				commitmentInfo.ChanType,
				!commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.ToRemoteKey,
				cpMetadata.LeaseExpiry, cpMetadata.AuxLeaf,
			)
			if err != nil {
				return nil, err
			}

			scriptMatches := bytes.Equal(
				toRemoteScript.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for to_remote output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for to_remote "+
					"output in %s commitment transaction",
					whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"to_remote output",
					whoseCommit.String())
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
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, true, whoseCommit,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				htlcMetadata.AuxLeaf,
			)
			if err != nil {
				return nil, err
			}

			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for incoming HTLC output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for incoming "+
					"HTLC output in %s commitment "+
					"transaction", whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"incoming HTLC output",
					whoseCommit.String())
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
					"%s commitment transaction: %v",
					whoseCommit.String(),
					htlcMetadata.RHash)

				failRes := ValidationFailureResult("Found "+
					"non whitelisted HTLC in %s "+
					"commitment transaction",
					whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("Whitelisted HTLC found in %s "+
					"commitment transaction",
					whoseCommit.String())
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, htlcMetadata.CommitPoint, chanPoint,
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			htlcScriptInfo, err := lnwallet.GenHtlcScript(
				commitmentInfo.ChanType, false, whoseCommit,
				htlcMetadata.CltvExpiry, htlcMetadata.RHash,
				commitmentInfo.CommitmentKeys,
				htlcMetadata.AuxLeaf,
			)
			if err != nil {
				return nil, err
			}

			scriptMatches := bytes.Equal(
				htlcScriptInfo.PkScript(),
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for incoming HTLC output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for incoming "+
					"HTLC output in %s commitment "+
					"transaction", whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"offered HTLC output",
					whoseCommit.String())
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeLocalAnchor):
			if localAnchorFound {
				return nil, fmt.Errorf("multiple local "+
					"anchor outputs in %s commitment tx",
					whoseCommit.String())
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
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			lAnchor, rAnchor, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// See https://github.com/lightningnetwork/lnd/blob/ea050d06f05b2694b4e4dcc12593ed245c2d7e82/lnwallet/channel.go#L8656-L8659
			if commitmentInfo.ChanType.IsTaproot() &&
				whoseCommit.IsRemote() {

				//nolint:ineffassign
				lAnchor, rAnchor = rAnchor, lAnchor
			}

			var scriptToMatch []byte
			if whoseCommit.IsLocal() {
				scriptToMatch = lAnchor.PkScript()
			} else {
				scriptToMatch = rAnchor.PkScript()
			}

			scriptMatches := bytes.Equal(
				scriptToMatch,
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for local anchor output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for local "+
					"anchor output in %s commitment "+
					"transaction", whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"local anchor output",
					whoseCommit.String())
			}

		case bytes.Equal(k, input.PsbtKeyOutputTypeRemoteAnchor):
			if remoteAnchorFound {
				return nil, fmt.Errorf("multiple remote "+
					"anchor outputs in %s commitment tx",
					whoseCommit.String())
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
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			lAnchor, rAnchor, err := lnwallet.CommitScriptAnchors(
				commitmentInfo.ChanType,
				commitmentInfo.localChanCfg,
				commitmentInfo.remoteChanCfg,
				commitmentInfo.CommitmentKeys,
			)
			if err != nil {
				return nil, err
			}

			// See https://github.com/lightningnetwork/lnd/blob/ea050d06f05b2694b4e4dcc12593ed245c2d7e82/lnwallet/channel.go#L8656-L8659
			if commitmentInfo.ChanType.IsTaproot() &&
				whoseCommit.IsRemote() {

				//nolint:ineffassign
				lAnchor, rAnchor = rAnchor, lAnchor
			}

			var scriptToMatch []byte
			if whoseCommit.IsLocal() {
				scriptToMatch = rAnchor.PkScript()
			} else {
				scriptToMatch = lAnchor.PkScript()
			}

			scriptMatches := bytes.Equal(
				scriptToMatch,
				packet.UnsignedTx.TxOut[i].PkScript,
			)

			if !scriptMatches {
				log.Errorf("%s commitment script does not "+
					"match for remote anchor output",
					whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for remote "+
					"anchor output in %s commitment "+
					"transaction", whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("%s commitment script matches for "+
					"remote anchor output",
					whoseCommit.String())
			}

		default:
			return nil, fmt.Errorf("unknown output type in %s"+
				"commitment transaction", whoseCommit.String())
		}
	}

	return ValidationSuccessResult(), nil
}

func (r *HalfValidator) validateSecondLevelHTLCTx(ctx context.Context,
	whoseCommit lntypes.ChannelParty,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("Validating %s second level HTLC transaction.",
		whoseCommit.String())

	var sloFound bool

	if whoseCommit.IsRemote() &&
		(len(packet.Outputs) != 1 || len(packet.Inputs) != 1) {

		err := fmt.Errorf("remote second level HTLC transaction MUST " +
			"contain exactly one input and output when signed by " +
			"us")

		log.Error(err)

		return nil, err
	}

	for outputIndex, output := range packet.Outputs {
		k := input.PsbtKeyDefaultTransaction
		if len(output.Unknowns) > 0 {
			k = output.Unknowns[0].Key
		}

		switch {
		case bytes.Equal(k, input.PsbtKeyOutputTypeSecondLevelHTLC):
			// TODO(viktor): validate that the sweeper never sweeps
			// 2 second level HTLC transactions in the same tx,
			// as we'll fail this check if that's the case.
			if sloFound {
				return nil, fmt.Errorf("multiple second "+
					"level outputs in %s second level "+
					"HTLC tx", whoseCommit.String())
			}
			sloFound = true

			metadata, err := r.extractSecondLevelHTLCOutputMetadata(
				output.Unknowns[1:],
			)
			if err != nil {
				return nil, err
			}

			fundingOut := metadata.FundingOutpoint
			fundingTxid := &lnrpc.ChannelPoint_FundingTxidBytes{
				FundingTxidBytes: fundingOut.Hash[:],
			}
			chanPoint := &lnrpc.ChannelPoint{
				FundingTxid: fundingTxid,
				OutputIndex: fundingOut.Index,
			}

			commitmentInfo, err := r.getCommitmentKeys(
				ctx, metadata.CommitPoint, chanPoint,
				whoseCommit,
			)
			if err != nil {
				return nil, err
			}

			secondLevelScript, err := lnwallet.SecondLevelHtlcScript(
				commitmentInfo.ChanType,
				commitmentInfo.IsLocalInitiator,
				commitmentInfo.CommitmentKeys.RevocationKey,
				commitmentInfo.CommitmentKeys.ToLocalKey,
				metadata.CommitPoint, metadata.CsvDelay,
				metadata.LeaseExpiry, *fundingOut,
				metadata.AuxLeaf,
			)
			if err != nil {
				return nil, err
			}

			scriptMatches := bytes.Equal(
				secondLevelScript.PkScript(),
				packet.UnsignedTx.TxOut[outputIndex].PkScript,
			)

			if !scriptMatches {
				log.Errorf("Second level HTLC output script "+
					"does not match for %s second "+
					"level HTLC tx", whoseCommit.String())

				failRes := ValidationFailureResult("output "+
					"script not matching for Second "+
					"level HTLC output in %s second "+
					"level HTLC transaction",
					whoseCommit.String())

				return failRes, nil
			} else {
				log.Tracef("Second level HTLC output script " +
					"matches")
			}

		default:
			// All other outputs must be either internal or
			// whitelisted
			isOurOutput, err := r.isOurOutput(
				ctx,
				packet.UnsignedTx.TxOut[outputIndex].PkScript,
			)
			if err != nil {
				return nil, err
			}

			if !isOurOutput {
				errStr := fmt.Sprintf("address in sweeper "+
					"output in %s second level "+
					"transaction isn't ours",
					whoseCommit.String())

				log.Errorf(errStr)

				failRes := ValidationFailureResult(errStr)

				return failRes, nil
			} else {
				log.Tracef("Found interal/whitelisted " +
					"address in second level HTLC tx")
			}
		}

	}

	if !sloFound {
		errStr := fmt.Sprintf("did not find second level HTLC output "+
			"in %s second level HTLC transaction",
			whoseCommit.String())

		log.Errorf(errStr)

		failRes := ValidationFailureResult(errStr)

		return failRes, nil
	}

	return ValidationSuccessResult(), nil
}

func (r *HalfValidator) validateFundingTransaction(
	_ *psbt.Packet) (*ValidationResult, error) {

	log.Infof("Validating funding transaction.")

	if !r.allowFunding {
		errStr := fmt.Sprint(
			"signing of funding transactions are disabled by the ",
			"'validation.allowfunding' config option",
		)
		log.Errorf(errStr)

		failRes := ValidationFailureResult(errStr)

		return failRes, nil
	}

	return ValidationSuccessResult(), nil
}

func (r *HalfValidator) validateCooperativeClose(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("Validating Cooperative Close transaction.")

	if len(packet.Outputs) != len(packet.UnsignedTx.TxOut) {
		return nil, fmt.Errorf("packet Output and " +
			"packet.UnsignedTx.TxOut differs in length")
	}

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
	if len(packet.Outputs) == 1 && !requireOurOutput {
		log.Tracef("Validation won't require that our output exists " +
			"in coop-close")

		// If not we won't require that a local output exists in
		// the closing tx.
		return ValidationSuccessResult(), nil
	}

	log.Tracef("Requiring that our output exists in coop-close")

	// Else the tx should contain our to_local output. We therefore loop
	// over all outputs until we find our to_local output, which is either
	// an internal address, or a whitelisted address (a delivery address has
	// been set for the channel).
	for oIndex, _ := range packet.Outputs {
		isOurInput, err := r.isOurOutput(
			ctx, packet.UnsignedTx.TxOut[oIndex].PkScript,
		)
		if err != nil {
			return nil, err
		}

		if isOurInput {
			// Found the local output.
			log.Tracef("Found our output in cooperative close")

			return ValidationSuccessResult(), nil
		}
	}

	res := ValidationFailureResult("Could not find local "+
		"output in cooperative closing "+
		"transaction %v", packet)

	return res, nil
}

func (r *HalfValidator) validateDefaultTransaction(ctx context.Context,
	packet *psbt.Packet) (*ValidationResult, error) {

	log.Infof("Validating non-channel related transaction.")

	// In a default transaction, all outputs must be either whitelisted or
	// internal addresses.
	for outputIndex, _ := range packet.UnsignedTx.TxOut {
		isOurOutput, err := r.isOurOutput(
			ctx, packet.UnsignedTx.TxOut[outputIndex].PkScript,
		)
		if err != nil {
			return nil, err
		}

		if !isOurOutput {
			log.Errorf("Output in default transaction isn't ours")

			failRes := ValidationFailureResult("Found address in " +
				"default transaction that wasn't either " +
				"whitelisted or an internal address")

			return failRes, nil
		}
	}

	return ValidationSuccessResult(), nil
}

// getMuSig2Packet fetches the transaction packet for the MuSig2SignRequest.
func (r *HalfValidator) getMuSig2Packet(_ context.Context,
	req *signrpc.MuSig2SignRequest) (*psbt.Packet, error) {

	sessionIDStr := hex.EncodeToString(req.GetSessionId())

	packet, ok := r.muSig2Packets[sessionIDStr]
	if !ok {
		return nil, errors.New("no transaction metadata found for " +
			"the MuSig2Session")
	}

	return packet, nil
}

func (r *HalfValidator) getTransactionType(
	packet *psbt.Packet) (TransactionType, error) {

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

type ChannelPartyOutputMetadata struct {
	CommitPoint *btcec.PublicKey
	CsvDelay    uint32
	LeaseExpiry uint32
	AuxLeaf     input.AuxTapLeaf
}

func NewChannelPartyOutputMetadata(commitPoint *btcec.PublicKey,
	csvDelay, leaseExpiry uint32,
	auxLeaf input.AuxTapLeaf) (*ChannelPartyOutputMetadata, error) {

	return &ChannelPartyOutputMetadata{
		CommitPoint: commitPoint,
		CsvDelay:    csvDelay,
		LeaseExpiry: leaseExpiry,
		AuxLeaf:     auxLeaf,
	}, nil
}

type HTLCOutputMetadata struct {
	CommitPoint *btcec.PublicKey
	CltvExpiry  uint32
	RHash       [32]byte
	AuxLeaf     input.AuxTapLeaf
}

func NewHTLCOutputMetadata(commitPoint *btcec.PublicKey, cltvExpiry uint32,
	rHash [32]byte, auxLeaf input.AuxTapLeaf) (*HTLCOutputMetadata, error) {

	return &HTLCOutputMetadata{
		CommitPoint: commitPoint,
		CltvExpiry:  cltvExpiry,
		RHash:       rHash,
		AuxLeaf:     auxLeaf,
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
	AuxLeaf         input.AuxTapLeaf
}

func NewSecondLevelHTLCOutputMetadata(commitPoint *btcec.PublicKey,
	fundingOutpoint *wire.OutPoint, auxLeaf input.AuxTapLeaf,
	csvDelay, leaseExpiry uint32) (*SecondLevelHTLCOutputMetadata, error) {

	return &SecondLevelHTLCOutputMetadata{
		CommitPoint:     commitPoint,
		FundingOutpoint: fundingOutpoint,
		CsvDelay:        csvDelay,
		LeaseExpiry:     leaseExpiry,
		AuxLeaf:         auxLeaf,
	}, nil
}

func (r *HalfValidator) extractChannelPartyOutputMetadata(
	unknowns input.SignInfo) (*ChannelPartyOutputMetadata, error) {

	var (
		commitPoint                                     *btcec.PublicKey
		csvDelay, leaseExpiry                           uint32
		fCommitPoint, fCsvDelay, fLeaseExpiry, fAuxLeaf bool
		auxLeaf                                         input.AuxTapLeaf
	)

	auxLeaf = fn.None[txscript.TapLeaf]()

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in channel party output")
			}

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCommitPoint = true
			commitPoint = commitP

		case bytes.Equal(k, input.PsbtKeyTypeOutputCsvDelay):
			if fCsvDelay {
				return nil, fmt.Errorf("multiple csv delays " +
					"found in channel party output")
			}

			delay, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCsvDelay = true
			csvDelay = delay

		case bytes.Equal(k, input.PsbtKeyTypeOutputLeaseExpiry):
			if fLeaseExpiry {
				return nil, fmt.Errorf("multiple lease " +
					"expiries found in channel party " +
					"output")
			}

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			fLeaseExpiry = true
			leaseExpiry = expiry

		case bytes.Equal(k, input.PsbtKeyTypeOutputAuxLeaf):
			if fAuxLeaf {
				return nil, fmt.Errorf("multiple aux leaves " +
					"found in channel party output")
			}

			auxLeafRes, err := input.BytesToAuxLeaf(unknown.Value)
			if err != nil {
				return nil, err
			}

			fAuxLeaf = true
			auxLeaf = auxLeafRes
		}
	}

	if !fCommitPoint || !fCsvDelay || !fLeaseExpiry {
		return nil, fmt.Errorf("missing metadata in channel party "+
			"output metadata. commit point: %v, csv delay: %v, "+
			"lease expiry: %v", fCommitPoint, fCsvDelay,
			fLeaseExpiry)
	}

	return NewChannelPartyOutputMetadata(
		commitPoint, csvDelay, leaseExpiry, auxLeaf,
	)
}

func (r *HalfValidator) extractHTLCOutputMetadata(
	unknowns input.SignInfo) (*HTLCOutputMetadata, error) {

	var (
		commitPoint *btcec.PublicKey
		cltvExpiry  uint32
		rHash       [32]byte
		auxLeaf     input.AuxTapLeaf

		fCommitPoint, fCltvExpiry, fRHash, fAuxLeaf bool
	)

	auxLeaf = fn.None[txscript.TapLeaf]()

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in HTLC output")
			}

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCommitPoint = true
			commitPoint = commitP

		case bytes.Equal(k, input.PsbtKeyTypeOutputCltvExpiry):
			if fCltvExpiry {
				return nil, fmt.Errorf("multiple cltv " +
					"expiries found in HTLC output")
			}

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCltvExpiry = true
			cltvExpiry = expiry

		case bytes.Equal(k, input.PsbtKeyTypeOutputRHash):
			if fRHash {
				return nil, fmt.Errorf("multiple r hashes " +
					"found in HTLC output")
			}

			if len(unknown.Value) != 32 {
				return nil, fmt.Errorf("r hash in metadata " +
					"is not 32 bytes")
			}

			fRHash = true
			copy(rHash[:], unknown.Value)

		case bytes.Equal(k, input.PsbtKeyTypeOutputAuxLeaf):
			if fAuxLeaf {
				return nil, fmt.Errorf("multiple aux leaves " +
					"found in HTLC output")
			}

			auxLeafRes, err := input.BytesToAuxLeaf(unknown.Value)
			if err != nil {
				return nil, err
			}

			fAuxLeaf = true
			auxLeaf = auxLeafRes
		}
	}

	if !fCommitPoint || !fCltvExpiry || !fRHash {
		return nil, fmt.Errorf("missing metadata in HTLC output "+
			"metadata. commit point: %v, cltv expiry: %v, +"+
			"r hash: %v", fCommitPoint, fCltvExpiry, fRHash)
	}

	return NewHTLCOutputMetadata(commitPoint, cltvExpiry, rHash, auxLeaf)
}

func (r *HalfValidator) extractAnchorOutputMetadata(
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

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCommitPoint = true
			commitPoint = commitP
		}
	}

	if !fCommitPoint {
		return nil, fmt.Errorf("missing metadata in anchor output "+
			"metadata. commit point: %v", fCommitPoint)
	}

	return NewAnchorOutputMetadata(commitPoint)
}

func (r *HalfValidator) extractSecondLevelHTLCOutputMetadata(
	unknowns input.SignInfo) (*SecondLevelHTLCOutputMetadata, error) {

	var (
		commitPoint           *btcec.PublicKey
		fundingOutpoint       *wire.OutPoint
		csvDelay, leaseExpiry uint32
		auxLeaf               input.AuxTapLeaf

		fCommitPoint, fFundingOutpoint, fCsvDelay, fLeaseExpiry,
		fAuxLeaf bool
	)

	auxLeaf = fn.None[txscript.TapLeaf]()

	for _, unknown := range unknowns {
		k := unknown.Key

		switch {
		case bytes.Equal(k, input.PsbtKeyTypeOutputFundingPoint):
			if fFundingOutpoint {
				return nil, fmt.Errorf("multiple funding " +
					"points found in second level HTLC " +
					"output")
			}

			outpointStr := string(unknown.Value)

			outpoint, err := wire.NewOutPointFromString(outpointStr)
			if err != nil {
				return nil, err
			}

			fFundingOutpoint = true
			fundingOutpoint = outpoint

		case bytes.Equal(k, input.PsbtKeyTypeOutputCommitPoint):
			if fCommitPoint {
				return nil, fmt.Errorf("multiple commit " +
					"points found in second level HTLC " +
					"output")
			}

			commitP, err := secp256k1.ParsePubKey(unknown.Value)
			if err != nil {
				return nil, err
			}

			fCommitPoint = true
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

			expiry, err := input.BytesToUint32(unknown.Value)
			if err != nil {
				return nil, err
			}

			fLeaseExpiry = true
			leaseExpiry = expiry

		case bytes.Equal(k, input.PsbtKeyTypeOutputAuxLeaf):
			if fAuxLeaf {
				return nil, fmt.Errorf("multiple aux leaves " +
					"found in second level HTLC output")
			}

			auxLeafRes, err := input.BytesToAuxLeaf(unknown.Value)
			if err != nil {
				return nil, err
			}

			fAuxLeaf = true
			auxLeaf = auxLeafRes
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
		commitPoint, fundingOutpoint, auxLeaf, csvDelay, leaseExpiry,
	)
}

type CommitmentInfo struct {
	CommitmentKeys *lnwallet.CommitmentKeyRing
	*ChanInfo
}

func (r *HalfValidator) getCommitmentKeys(ctx context.Context,
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

func (r *HalfValidator) getChanInfo(ctx context.Context,
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

func (r *HalfValidator) isWhitelistedHTLC(ctx context.Context,
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

// requireKnownOutput checks if the amount of our to_local output was above the
// value of the to_remote output in our last local commitment tx was above the
// value for the to_remote output.
func (r *HalfValidator) requireOurOutputInCoopClose(ctx context.Context,
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

// GetFeatures returns the features supported by the HalfValidator
// implementation. This information helps the watch-only node
// decide which types of metadata to send to the remote signer.
func (r *HalfValidator) GetFeatures() string {
	return ""
}

// AddMetadata allows metadata to be passed to the HalfValidator.
// This metadata may be used during a future ValidatePSBT call.
func (r *HalfValidator) AddMetadata(ctx context.Context,
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

	case *walletrpc.MetadataRequest_Accounts:
		return r.AddAccountsMetadata(
			ctx, reqType.Accounts.GetAccounts(),
		)

	case *walletrpc.MetadataRequest_MuSig_2SessionInfo:
		return r.AddMuSig2SessionMetadata(
			ctx, reqType.MuSig_2SessionInfo,
		)

	default:
		// When we don't know the metadata type, we log an error but
		// return nil, as the watch-only node might be using a newer
		// version of lnd that sends metadata we don't know about.
		log.Errorf("Unknown metadata type: %v", reqType)

		return nil
	}
}

func (r *HalfValidator) AddAccountsMetadata(_ context.Context,
	accounts []*walletrpc.Account) error {

	log.Infof("Processing wallet accounts data.")

	r.mu.Lock()
	r.mu.Unlock()

	r.accounts = accounts

	return nil
}

func (r *HalfValidator) AddMuSig2SessionMetadata(ctx context.Context,
	muSig2Info *walletrpc.MuSig2Info) error {

	log.Infof("Processing MuSig2Session data.")

	sessionIdStr, packet, err := r.extractMuSig2SessionInfo(ctx, muSig2Info)
	if err != nil {
		return err
	}

	_, ok := r.muSig2Packets[sessionIdStr]
	if ok {
		return fmt.Errorf("metadata already added for session: %s",
			sessionIdStr)
	}

	r.muSig2Packets[sessionIdStr] = packet

	return nil
}

func (r *HalfValidator) extractMuSig2SessionInfo(_ context.Context,
	muSig2Info *walletrpc.MuSig2Info) (string, *psbt.Packet, error) {

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(muSig2Info.FundedPsbt), false,
	)
	if err != nil {
		return "", nil, err
	}

	return hex.EncodeToString(muSig2Info.SessionId), packet, nil
}

func (r *HalfValidator) AddFundingMetadata(ctx context.Context,
	chanInfo *walletrpc.FundingInfo) error {

	log.Infof("Processing funding information.")

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
		return errors.New("errors querying the database for funding " +
			"info: " + err.Error())
	} else if fInfo != nil {
		return errors.New("funding info already exists in the database")
	}

	log.Debugf("Persisting channel %s:%d.",
		hex.EncodeToString(chanPoint.GetFundingTxidBytes()),
		chanPoint.OutputIndex)

	_, err = r.remoteSignerDB.AddFundingInfo(ctx, chanInfo)

	return err
}

func (r *HalfValidator) AddLocalCommitmentMetadata(ctx context.Context,
	localCommitment *walletrpc.SignPsbtRequest) error {

	log.Infof("Processing local commitment transaction information.")

	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(localCommitment.GetFundedPsbt()), false,
	)
	if err != nil {
		return err
	}

	// We validate the commitment tx, to ensure that we don't end up with
	// a commitment transaction locally that's not correct.
	res, err := r.validateCommitment(ctx, lntypes.Local, packet)
	if err != nil {
		return err
	}

	if res.Type == ValidationFailure {
		return errors.New("invalid local commitment transaction " +
			"as metadata: " + res.FailureDetails)
	}

	log.Infof("Validation was successful. Proceeding to persist local " +
		"commitment information.")

	transactionType, err := r.getTransactionType(packet)
	if err != nil {
		return err
	}

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

func (r *HalfValidator) getCommitmentHeight(ctx context.Context,
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

	log.Debugf("Commitment height is: %d", commitmentHeight)

	return commitmentHeight, nil
}

func (r *HalfValidator) getChanPoint(packet *psbt.Packet) (
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
func (r *HalfValidator) ensureCommitmentIsNotRevoked(ctx context.Context,
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
			txid := hex.EncodeToString(
				chanPoint.GetFundingTxidBytes(),
			)
			log.Debugf("Persisting local commitment tx for "+
				"channel: %s:%d", txid, chanPoint.OutputIndex)

			// Since this is the first time seeing the local
			// commitment transaction, we insert it into the
			// database.
			var buf bytes.Buffer
			if err = packet.Serialize(&buf); err != nil {
				return false, fmt.Errorf("error serializing "+
					"local commitment when seeing it for "+
					"the first time: %w", err)
			}

			err = r.remoteSignerDB.InsertLocalCommitment(ctx,
				buf.Bytes(), chanPoint.GetFundingTxidBytes(),
				chanPoint.OutputIndex, commitmentHeight,
			)
			if err != nil {
				return false, fmt.Errorf("error inserting "+
					"local commitment when seeing it for "+
					"the first time: %w", err)
			}

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

func deriveKey(keyPath []uint32,
	baseKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {

	var currentKey = baseKey
	for idx, pathPart := range keyPath {
		derivedKey, err := currentKey.DeriveNonStandard(pathPart)
		if err != nil {
			return nil, err
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
		if depth == 2 && len(keyPath) > 2 {
			nextID = keyPath[idx+1] - hdkeychain.HardenedKeyStart
		}
		if (depth == 2 && nextID != 0) || (depth == 3 && keyID != 0) {
			currentKey, err = hdkeychain.NewKeyFromString(
				derivedKey.String(),
			)
			if err != nil {
				return nil, err
			}
		} else {
			currentKey = derivedKey
		}
	}

	return currentKey, nil
}

func (r *HalfValidator) isAddressInternal(key *hdkeychain.ExtendedKey,
	accountPath []uint32, keysToCheck uint32,
	pubkeyToPKScript func(*btcec.PublicKey) (btcutil.Address, error),
	matchAddressPkScript []byte) (bool, error) {

	pkScriptMatches := func(addr btcutil.Address) (bool, error) {
		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return false, err
		}

		return bytes.Equal(pkScript, matchAddressPkScript), nil
	}

	for i := uint32(0); i < keysToCheck; i++ {
		// Check for both the external and internal branch.
		for _, branch := range []uint32{0, 1} {
			// Create the path to derive the key.
			addrPath := append(accountPath, branch, i) //nolint:gocritic

			// Derive the key.
			derivedKey, err := deriveKey(addrPath, key)
			if err != nil {
				return false, err
			}

			addrPubKey, err := derivedKey.ECPubKey()
			if err != nil {
				return false, err
			}

			addr, err := pubkeyToPKScript(addrPubKey)
			if err != nil {
				return false, err
			}

			isMatch, err := pkScriptMatches(addr)
			if err != nil {
				return false, err
			}

			if isMatch {
				return true, nil
			}
		}
	}

	return false, nil
}

// isOurOutput checks if the output address is derived from a
// local key, or is a whitelisted address
func (r *HalfValidator) isOurOutput(ctx context.Context,
	pkScript []byte) (bool, error) {

	extraKeysToCheck := uint32(1000)

	isWhitelisted, err := r.isWhiteListedAddress(ctx, pkScript)
	if err != nil {
		return false, err
	}

	if isWhitelisted {
		return true, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	sClass, _, _, err := txscript.ExtractPkScriptAddrs(pkScript, r.network)
	if err != nil {
		return false, err
	}

	for _, account := range r.accounts {
		var pubkeyToPKScript func(*btcec.PublicKey) (btcutil.Address, error)

		// TODO(viktor): Verify that these types are enough to check,
		//  i.e. does lnd ever create addresses internally of other
		//  address types.
		if account.AddressType == walletrpc.AddressType_WITNESS_PUBKEY_HASH {
			if sClass != txscript.WitnessV0PubKeyHashTy {
				continue
			}

			pubkeyToPKScript = func(pubKey *btcec.PublicKey) (
				btcutil.Address, error) {

				hash160 := btcutil.Hash160(
					pubKey.SerializeCompressed(),
				)

				return btcutil.NewAddressWitnessPubKeyHash(
					hash160, r.network,
				)
			}
		} else if account.AddressType == walletrpc.AddressType_TAPROOT_PUBKEY {
			if sClass != txscript.WitnessV1TaprootTy {
				continue
			}

			pubkeyToPKScript = func(pubKey *btcec.PublicKey) (
				btcutil.Address, error) {

				taprootKey := txscript.ComputeTaprootKeyNoScript(
					pubKey,
				)

				return btcutil.NewAddressTaproot(
					schnorr.SerializePubKey(taprootKey), r.network,
				)
			}
		} else if account.AddressType == walletrpc.AddressType_HYBRID_NESTED_WITNESS_PUBKEY_HASH {
			// TODO: Validate if this one is actually correct, as
			// well as the pubkeyToPKScript func below
			if sClass != txscript.ScriptHashTy {
				continue
			}

			pubkeyToPKScript = func(pubKey *btcec.PublicKey) (
				btcutil.Address, error) {

				pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
				witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(
					pubKeyHash, r.network,
				)
				if err != nil {
					return nil, err
				}

				witnessProgram, err := txscript.PayToAddrScript(
					witnessAddr,
				)
				if err != nil {
					return nil, err
				}

				return btcutil.NewAddressScriptHash(
					witnessProgram, r.network,
				)
			}
		} else {
			continue
		}

		parsedPath, err := ParsePath(account.GetDerivationPath())
		if err != nil {
			return false, err
		}

		parsedPath = make([]uint32, 0)

		xKey, err := hdkeychain.NewKeyFromString(
			account.GetExtendedPublicKey(),
		)
		if err != nil {
			return false, err
		}

		keyCount := account.GetExternalKeyCount()
		if account.GetInternalKeyCount() > account.GetExternalKeyCount() {
			keyCount = account.GetInternalKeyCount()
		}

		isInternal, err := r.isAddressInternal(
			xKey, parsedPath, extraKeysToCheck+keyCount,
			pubkeyToPKScript, pkScript,
		)
		if err != nil {
			return false, err
		}

		if isInternal {
			log.Infof("output address is internal")

			return true, nil
		}

	}

	log.Errorf("Output address was not internal keys or whitelisted")

	return false, nil
}

// isOurOutput checks if the output address at the specified index is
// whitelisted.
func (r *HalfValidator) isWhiteListedAddress(ctx context.Context,
	matchPkScript []byte) (bool, error) {

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

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return false, err
		}

		if bytes.Equal(pkScript, matchPkScript) {
			log.Debugf("output address %s is whitelisted", address)

			return true, nil
		}
	}

	return false, nil
}

func ParsePath(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)
	if len(path) == 0 {
		return nil, errors.New("path cannot be empty")
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New("path must start with m/")
	}
	parts := strings.Split(path, "/")
	indices := make([]uint32, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		index := uint32(0)
		part := parts[i]
		if strings.Contains(parts[i], "'") {
			index += HardenedKeyStart
			part = strings.TrimRight(parts[i], "'")
		}
		parsed, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("could not parse part \"%s\": "+
				"%v", part, err)
		}
		indices[i-1] = index + uint32(parsed)
	}
	return indices, nil
}

// A compile time assertion to ensure HalfValidator meets the Validation interface.
var _ Validation = (*HalfValidator)(nil)
