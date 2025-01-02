package validator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/sqldb"
	"github.com/lightningnetwork/lnd/sqldb/sqlc"
)

// SQLRemoteSignerQueries is an interface that defines the set of operations
// that can be executed against the remote signer SQL database.
type SQLRemoteSignerQueries interface { //nolint:interfacebloat
	InsertWhitelistedAddress(ctx context.Context,
		arg sqlc.InsertWhitelistedAddressParams) (int64, error)

	GetWhitelistedAddress(ctx context.Context,
		address string) (sqlc.AddressWhitelist, error)

	ListWhitelistedAddresses(ctx context.Context) (
		[]sqlc.AddressWhitelist, error)

	DeleteWhitelistedAddress(ctx context.Context,
		address string) (sql.Result, error)

	DeleteWhitelistedPaymentHash(ctx context.Context,
		paymentHash []byte) (sql.Result, error)

	GetWhitelistedPaymentHash(ctx context.Context,
		paymentHash []byte) (sqlc.PaymentHashWhitelist, error)

	ListWhitelistedPaymentHashes(ctx context.Context) (
		[]sqlc.PaymentHashWhitelist, error)

	InsertWhitelistedPaymentHash(ctx context.Context,
		arg sqlc.InsertWhitelistedPaymentHashParams) (int64, error)

	InsertLocalCommitment(ctx context.Context,
		arg sqlc.InsertLocalCommitmentParams) (int64, error)

	GetLatestLocalCommitment(ctx context.Context,
		arg sqlc.GetLatestLocalCommitmentParams) (sqlc.LocalCommitment,
		error)

	DeleteLocalCommitment(ctx context.Context,
		arg sqlc.DeleteLocalCommitmentParams) (sql.Result, error)

	InsertKeyDescriptor(ctx context.Context,
		arg sqlc.InsertKeyDescriptorParams) (int64, error)

	InsertChannelConfig(ctx context.Context,
		arg sqlc.InsertChannelConfigParams) (int64, error)

	InsertChannelInfo(ctx context.Context,
		arg sqlc.InsertChannelInfoParams) (int64, error)

	GetChannelInfoWithConfigs(ctx context.Context,
		arg sqlc.GetChannelInfoWithConfigsParams) (
		sqlc.GetChannelInfoWithConfigsRow, error)
}

var _ RemoteSignerDB = (*RemoteSignerSQLStore)(nil)

// SQLInvoiceQueriesTxOptions defines the set of db txn options the
// SQLInvoiceQueries understands.
type SQLInvoiceQueriesTxOptions struct {
	// readOnly governs if a read only transaction is needed or not.
	readOnly bool
}

// ReadOnly returns true if the transaction should be read only.
//
// NOTE: This implements the TxOptions.
func (a *SQLInvoiceQueriesTxOptions) ReadOnly() bool {
	return a.readOnly
}

// NewSQLInvoiceQueryReadTx creates a new read transaction option set.
func NewSQLInvoiceQueryReadTx() SQLInvoiceQueriesTxOptions {
	return SQLInvoiceQueriesTxOptions{
		readOnly: true,
	}
}

// BatchedSQLRemoteSignerQueries is a version of the SQLRemoteSignerQueries
// that's capable of batched database operations.
type BatchedSQLRemoteSignerQueries interface {
	SQLRemoteSignerQueries

	sqldb.BatchedTx[SQLRemoteSignerQueries]
}

// RemoteSignerStore represents a storage backend.
type RemoteSignerSQLStore struct {
	db    BatchedSQLRemoteSignerQueries
	clock clock.Clock
}

// NewRemoteSignerSQLStore creates a new SQLStore instance given a open
// BatchedSQLRemoteSignerQueries storage backend.
func NewRemoteSignerSQLStore(db BatchedSQLRemoteSignerQueries,
	clock clock.Clock) *RemoteSignerSQLStore {

	return &RemoteSignerSQLStore{
		db:    db,
		clock: clock,
	}
}

// InsertWhitelistedAddress inserts a new whitelisted address into the
// database.
func (s *RemoteSignerSQLStore) InsertWhitelistedAddress(ctx context.Context,
	address string, amount int64) error {

	_, err := s.db.InsertWhitelistedAddress(ctx,
		sqlc.InsertWhitelistedAddressParams{
			Address:    address,
			AmountMsat: amount,
			CreatedAt:  s.clock.Now(),
		})

	return err
}

// GetWhitelistedAddress retrieves a whitelisted address from the database.
func (s *RemoteSignerSQLStore) GetWhitelistedAddress(ctx context.Context,
	address string) (string, error) {

	res, err := s.db.GetWhitelistedAddress(ctx, address)
	if err != nil {
		return "", err
	}

	return res.Address, nil
}

// ListWhitelistedAddresses retrieves the whitelisted addresses from the
// database.
func (s *RemoteSignerSQLStore) ListWhitelistedAddresses(ctx context.Context) (
	[]string, error) {

	res, err := s.db.ListWhitelistedAddresses(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return make([]string, 0), nil
		}

		return nil, err
	}

	resList := make([]string, len(res))
	for i, r := range res {
		resList[i] = r.Address
	}

	return resList, nil
}

// DeleteWhitelistedAddress deletes a whitelisted addresses from the database.
func (s *RemoteSignerSQLStore) DeleteWhitelistedAddress(ctx context.Context,
	address string) (bool, error) {

	res, err := s.db.DeleteWhitelistedAddress(ctx, address)
	if err != nil {
		return false, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

// InsertWhitelistedPaymentHash inserts a new whitelisted payment hash into the
// database.
func (s *RemoteSignerSQLStore) InsertWhitelistedPaymentHash(ctx context.Context,
	paymentHash []byte, amount int64) error {

	_, err := s.db.InsertWhitelistedPaymentHash(ctx,
		sqlc.InsertWhitelistedPaymentHashParams{
			PaymentHash: paymentHash,
			AmountMsat:  amount,
			CreatedAt:   s.clock.Now(),
		})

	return err
}

// GetWhitelistedPaymentHash retrieves a whitelisted payment hash from the
// database.
func (s *RemoteSignerSQLStore) GetWhitelistedPaymentHash(ctx context.Context,
	paymentHash [32]byte) ([]byte, error) {

	// TODO: Make the sql db use a [32]byte type instead.
	res, err := s.db.GetWhitelistedPaymentHash(ctx, paymentHash[:])
	if err != nil {
		return nil, err
	}

	return res.PaymentHash, nil
}

// ListWhitelistedPaymentHashes retrieves the whitelisted payment hashes from
// the database.
func (s *RemoteSignerSQLStore) ListWhitelistedPaymentHashes(
	ctx context.Context) ([][]byte, error) {

	res, err := s.db.ListWhitelistedPaymentHashes(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return make([][]byte, 0), nil
		}

		return nil, err
	}

	resList := make([][]byte, len(res))
	for i, r := range res {
		resList[i] = r.PaymentHash
	}

	return resList, nil
}

// DeleteWhitelistedPaymentHash deletes a whitelisted payment hash from the
// database.
func (s *RemoteSignerSQLStore) DeleteWhitelistedPaymentHash(ctx context.Context,
	paymentHash []byte) (bool, error) {

	res, err := s.db.DeleteWhitelistedPaymentHash(ctx, paymentHash)
	if err != nil {
		return false, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

func (s *RemoteSignerSQLStore) InsertLocalCommitment(ctx context.Context,
	commitmentTxPackage []byte, fundingTxid []byte,
	fundingOutputIndex uint32, commitmentHeight uint64) error {

	//TODO: ensure fundingOutputIndex is not above int32 max value
	//TODO: ensure commitmentHeight is not above int64 max value

	_, err := s.db.InsertLocalCommitment(ctx,
		sqlc.InsertLocalCommitmentParams{
			CommitmentTxPackage: commitmentTxPackage,
			FundingTxid:         fundingTxid,
			FundingOutputIndex:  int32(fundingOutputIndex),
			CommitmentHeight:    int64(commitmentHeight),
			CreatedAt:           s.clock.Now(),
		},
	)

	return err
}

func (s *RemoteSignerSQLStore) GetLatestLocalCommitment(ctx context.Context,
	fundingTxid []byte,
	fundingOutputIndex uint32) (LocalCommitmentInfo, error) {

	//TODO: ensure fundingOutputIndex is not above int32 max value

	res, err := s.db.GetLatestLocalCommitment(ctx,
		sqlc.GetLatestLocalCommitmentParams{
			FundingTxid:        fundingTxid,
			FundingOutputIndex: int32(fundingOutputIndex),
		},
	)
	if err != nil {
		return LocalCommitmentInfo{}, err
	}

	// TODO: ensure res.FundingOutputIndex & res.CommitmentHeight is not
	// negative values.

	LocalCommitmentInfo := LocalCommitmentInfo{
		CommitmentTxPackage: res.CommitmentTxPackage,
		FundingTxid:         res.FundingTxid,
		FundingOutputIndex:  uint32(res.FundingOutputIndex),
		CommitmentHeight:    uint64(res.CommitmentHeight),
	}

	return LocalCommitmentInfo, nil
}

func (s *RemoteSignerSQLStore) DeleteLocalCommitment(ctx context.Context,
	fundingTxid []byte, fundingOutputIndex uint32,
	commitmentHeight uint64) (bool, error) {

	//TODO: ensure fundingOutputIndex is not above int32 max value
	//TODO: ensure commitmentHeight is not above int64 max value

	res, err := s.db.DeleteLocalCommitment(ctx,
		sqlc.DeleteLocalCommitmentParams{
			FundingTxid:        fundingTxid,
			FundingOutputIndex: int32(fundingOutputIndex),
			CommitmentHeight:   int64(commitmentHeight),
		},
	)
	if err != nil {
		return false, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return rows > 0, nil
}

// AddFundingInfo inserts the FundingInfo (along with its associated key descriptors
// and channel configurations) into the database in a single transaction.
func (s *RemoteSignerSQLStore) AddFundingInfo(ctx context.Context,
	fi *walletrpc.FundingInfo) (uint64, error) {

	var writeTxOpts SQLInvoiceQueriesTxOptions
	var channelInfoID int64

	err := s.db.ExecTx(ctx, &writeTxOpts, func(db SQLRemoteSignerQueries) error {
		// --- Local ChannelConfig Insertion ---
		localCC := fi.GetLocalChannelConfig()
		if localCC == nil {
			return errors.New("local channel config missing")
		}

		// Insert local key descriptors:
		localMultiSigID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: localCC.GetMultiSigKey().GetRawKeyBytes(),
			KeyFamily:   localCC.GetMultiSigKey().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    localCC.GetMultiSigKey().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert local multi-sig key: %w", err)
		}

		localRevocationID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: localCC.GetRevocationBasePoint().GetRawKeyBytes(),
			KeyFamily:   localCC.GetRevocationBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    localCC.GetRevocationBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert local revocation key: %w", err)
		}

		localPaymentID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: localCC.GetPaymentBasePoint().GetRawKeyBytes(),
			KeyFamily:   localCC.GetPaymentBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    localCC.GetPaymentBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert local payment key: %w", err)
		}

		localDelayID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: localCC.GetDelayBasePoint().GetRawKeyBytes(),
			KeyFamily:   localCC.GetDelayBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    localCC.GetDelayBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert local delay key: %w", err)
		}

		localHtlcID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: localCC.GetHtlcBasePoint().GetRawKeyBytes(),
			KeyFamily:   localCC.GetHtlcBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    localCC.GetHtlcBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert local HTLC key: %w", err)
		}

		// Insert the local channel config:
		localCCID, err := db.InsertChannelConfig(ctx, sqlc.InsertChannelConfigParams{
			ChanReserveSat:        int64(localCC.GetChannelStateBounds().GetChanReserveSat()),
			MaxPendingAmtMsat:     int64(localCC.GetChannelStateBounds().GetMaxPendingAmtMsat()),
			MinHtlc:               int64(localCC.GetChannelStateBounds().GetMinHtlc()),
			MaxAcceptedHtlcs:      int32(localCC.GetChannelStateBounds().GetMaxAcceptedHtlcs()),
			DustLimit:             int64(localCC.GetCommitmentParams().GetDustLimit()),
			CsvDelay:              int32(localCC.GetCommitmentParams().GetCsvDelay()),
			MultiSigKeyID:         localMultiSigID,
			RevocationBasePointID: localRevocationID,
			PaymentBasePointID:    localPaymentID,
			DelayBasePointID:      localDelayID,
			HtlcBasePointID:       localHtlcID,
		})
		if err != nil {
			return fmt.Errorf("insert local channel config: %w", err)
		}

		// --- Remote ChannelConfig Insertion ---
		remoteCC := fi.GetRemoteChannelConfig()
		if remoteCC == nil {
			return errors.New("remote channel config missing")
		}

		remoteMultiSigID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: remoteCC.GetMultiSigKey().GetRawKeyBytes(),
			KeyFamily:   remoteCC.GetMultiSigKey().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    remoteCC.GetMultiSigKey().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert remote multi-sig key: %w", err)
		}

		remoteRevocationID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: remoteCC.GetRevocationBasePoint().GetRawKeyBytes(),
			KeyFamily:   remoteCC.GetRevocationBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    remoteCC.GetRevocationBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert remote revocation key: %w", err)
		}

		remotePaymentID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: remoteCC.GetPaymentBasePoint().GetRawKeyBytes(),
			KeyFamily:   remoteCC.GetPaymentBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    remoteCC.GetPaymentBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert remote payment key: %w", err)
		}

		remoteDelayID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: remoteCC.GetDelayBasePoint().GetRawKeyBytes(),
			KeyFamily:   remoteCC.GetDelayBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    remoteCC.GetDelayBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert remote delay key: %w", err)
		}

		remoteHtlcID, err := db.InsertKeyDescriptor(ctx, sqlc.InsertKeyDescriptorParams{
			RawKeyBytes: remoteCC.GetHtlcBasePoint().GetRawKeyBytes(),
			KeyFamily:   remoteCC.GetHtlcBasePoint().GetKeyLoc().GetKeyFamily(),
			KeyIndex:    remoteCC.GetHtlcBasePoint().GetKeyLoc().GetKeyIndex(),
		})
		if err != nil {
			return fmt.Errorf("insert remote HTLC key: %w", err)
		}

		remoteCCID, err := db.InsertChannelConfig(ctx, sqlc.InsertChannelConfigParams{
			ChanReserveSat:        int64(remoteCC.GetChannelStateBounds().GetChanReserveSat()),
			MaxPendingAmtMsat:     int64(remoteCC.GetChannelStateBounds().GetMaxPendingAmtMsat()),
			MinHtlc:               int64(remoteCC.GetChannelStateBounds().GetMinHtlc()),
			MaxAcceptedHtlcs:      int32(remoteCC.GetChannelStateBounds().GetMaxAcceptedHtlcs()),
			DustLimit:             int64(remoteCC.GetCommitmentParams().GetDustLimit()),
			CsvDelay:              int32(remoteCC.GetCommitmentParams().GetCsvDelay()),
			MultiSigKeyID:         remoteMultiSigID,
			RevocationBasePointID: remoteRevocationID,
			PaymentBasePointID:    remotePaymentID,
			DelayBasePointID:      remoteDelayID,
			HtlcBasePointID:       remoteHtlcID,
		})
		if err != nil {
			return fmt.Errorf("insert remote channel config: %w", err)
		}

		// --- Insert ChannelInfo ---
		op := fi.GetFundingOutpoint()
		channelInfoID, err = db.InsertChannelInfo(ctx, sqlc.InsertChannelInfoParams{
			TxidBytes:             op.GetTxidBytes(),
			TxidStr:               op.GetTxidStr(),
			OutputIndex:           int32(op.GetOutputIndex()),
			ChannelType:           int64(fi.GetChannelType()),
			IsLocalInitiator:      fi.GetIsLocalInitiator(),
			LocalChannelConfigID:  localCCID,
			RemoteChannelConfigID: remoteCCID,
			CreatedAt:             s.clock.Now(),
		})
		if err != nil {
			return fmt.Errorf("insert channel info: %w", err)
		}

		return nil
	}, func() {
		// TODO: notify on successful commit if needed.
	})
	if err != nil {
		return 0, err
	}

	return uint64(channelInfoID), nil
}

// GetFundingInfo retrieves a FundingInfo object from the database given a channel's
// txid_bytes and output_index.
func (s *RemoteSignerSQLStore) GetFundingInfo(ctx context.Context,
	chanPoint *lnrpc.ChannelPoint) (*walletrpc.FundingInfo, error) {

	row, err := s.db.GetChannelInfoWithConfigs(ctx,
		sqlc.GetChannelInfoWithConfigsParams{
			TxidBytes:   chanPoint.GetFundingTxidBytes(),
			OutputIndex: int32(chanPoint.GetOutputIndex()),
		},
	)
	if err != nil {
		return nil, err
	}

	// Map the flat row into a FundingInfo object.
	fi := &walletrpc.FundingInfo{
		ChannelType:      uint64(row.ChannelType),
		IsLocalInitiator: row.IsLocalInitiator,
		FundingOutpoint: &lnrpc.OutPoint{
			TxidBytes:   row.TxidBytes,
			TxidStr:     row.TxidStr,
			OutputIndex: uint32(row.OutputIndex),
		},
		LocalChannelConfig: &lnrpc.ChannelConfig{
			ChannelStateBounds: &lnrpc.ChannelStateBounds{
				ChanReserveSat:    uint64(row.LocalChanReserveSat),
				MaxPendingAmtMsat: uint64(row.LocalMaxPendingAmtMsat),
				MinHtlc:           uint64(row.LocalMinHtlc),
				MaxAcceptedHtlcs:  uint32(row.LocalMaxAcceptedHtlcs),
			},
			CommitmentParams: &lnrpc.CommitmentParams{
				DustLimit: uint64(row.LocalDustLimit),
				CsvDelay:  uint32(row.LocalCsvDelay),
			},
			MultiSigKey: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.LocalMultiSigRawKeyBytes,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.LocalMultiSigKeyFamily,
					KeyIndex:  row.LocalMultiSigKeyIndex,
				},
			},
			RevocationBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.LocalRevocationRawKeyBytes,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.LocalRevocationKeyFamily,
					KeyIndex:  row.LocalRevocationKeyIndex,
				},
			},
			PaymentBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.LocalPaymentRawKeyBytes,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.LocalPaymentKeyFamily,
					KeyIndex:  row.LocalPaymentKeyIndex,
				},
			},
			DelayBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.LocalDelayBasePointRaw,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.LocalDelayBasePointKeyFamily,
					KeyIndex:  row.LocalDelayBasePointKeyIndex,
				},
			},
			HtlcBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.LocalHtlcBasePointRaw,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.LocalHtlcBasePointKeyFamily,
					KeyIndex:  row.LocalHtlcBasePointKeyIndex,
				},
			},
		},
		RemoteChannelConfig: &lnrpc.ChannelConfig{
			ChannelStateBounds: &lnrpc.ChannelStateBounds{
				ChanReserveSat:    uint64(row.RemoteChanReserveSat),
				MaxPendingAmtMsat: uint64(row.RemoteMaxPendingAmtMsat),
				MinHtlc:           uint64(row.RemoteMinHtlc),
				MaxAcceptedHtlcs:  uint32(row.RemoteMaxAcceptedHtlcs),
			},
			CommitmentParams: &lnrpc.CommitmentParams{
				DustLimit: uint64(row.RemoteDustLimit),
				CsvDelay:  uint32(row.RemoteCsvDelay),
			},
			MultiSigKey: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.RemoteMultiSigRawKeyBytes,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.RemoteMultiSigKeyFamily,
					KeyIndex:  row.RemoteMultiSigKeyIndex,
				},
			},
			RevocationBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.RemoteRevocationRawKeyBytes,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.RemoteRevocationKeyFamily,
					KeyIndex:  row.RemoteRevocationKeyIndex,
				},
			},
			PaymentBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.RemotePaymentBasePointRaw,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.RemotePaymentKeyFamily,
					KeyIndex:  row.RemotePaymentKeyIndex,
				},
			},
			DelayBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.RemoteDelayBasePointRaw,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.RemoteDelayBasePointKeyFamily,
					KeyIndex:  row.RemoteDelayBasePointKeyIndex,
				},
			},
			HtlcBasePoint: &lnrpc.KeyDescriptor{
				RawKeyBytes: row.RemoteHtlcBasePointRaw,
				KeyLoc: &lnrpc.KeyLocator{
					KeyFamily: row.RemoteHtlcBasePointKeyFamily,
					KeyIndex:  row.RemoteHtlcBasePointKeyIndex,
				},
			},
		},
	}

	return fi, nil
}
