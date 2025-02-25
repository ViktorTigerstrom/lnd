package validator

import (
	"context"
	"database/sql"
	"github.com/lightningnetwork/lnd/clock"
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
	paymentHash []byte) ([]byte, error) {

	res, err := s.db.GetWhitelistedPaymentHash(ctx, paymentHash)
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
