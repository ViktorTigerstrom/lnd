// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package sqlc

import (
	"context"
	"database/sql"
)

type Querier interface {
	DeleteCanceledInvoices(ctx context.Context) (sql.Result, error)
	DeleteChannelInfo(ctx context.Context, arg DeleteChannelInfoParams) (sql.Result, error)
	DeleteInvoice(ctx context.Context, arg DeleteInvoiceParams) (sql.Result, error)
	DeleteLocalCommitment(ctx context.Context, arg DeleteLocalCommitmentParams) (sql.Result, error)
	DeleteWhitelistedAddress(ctx context.Context, address string) (sql.Result, error)
	DeleteWhitelistedPaymentHash(ctx context.Context, paymentHash []byte) (sql.Result, error)
	FetchAMPSubInvoiceHTLCs(ctx context.Context, arg FetchAMPSubInvoiceHTLCsParams) ([]FetchAMPSubInvoiceHTLCsRow, error)
	FetchAMPSubInvoices(ctx context.Context, arg FetchAMPSubInvoicesParams) ([]AmpSubInvoice, error)
	FetchSettledAMPSubInvoices(ctx context.Context, arg FetchSettledAMPSubInvoicesParams) ([]FetchSettledAMPSubInvoicesRow, error)
	FilterInvoices(ctx context.Context, arg FilterInvoicesParams) ([]Invoice, error)
	GetAMPInvoiceID(ctx context.Context, setID []byte) (int64, error)
	GetChannelInfo(ctx context.Context, arg GetChannelInfoParams) (ChannelInfo, error)
	GetChannelInfoWithConfigs(ctx context.Context, arg GetChannelInfoWithConfigsParams) (GetChannelInfoWithConfigsRow, error)
	// This method may return more than one invoice if filter using multiple fields
	// from different invoices. It is the caller's responsibility to ensure that
	// we bubble up an error in those cases.
	GetInvoice(ctx context.Context, arg GetInvoiceParams) ([]Invoice, error)
	GetInvoiceBySetID(ctx context.Context, setID []byte) ([]Invoice, error)
	GetInvoiceFeatures(ctx context.Context, invoiceID int64) ([]InvoiceFeature, error)
	GetInvoiceHTLCCustomRecords(ctx context.Context, invoiceID int64) ([]GetInvoiceHTLCCustomRecordsRow, error)
	GetInvoiceHTLCs(ctx context.Context, invoiceID int64) ([]InvoiceHtlc, error)
	GetLatestLocalCommitment(ctx context.Context, arg GetLatestLocalCommitmentParams) (LocalCommitment, error)
	GetWhitelistedAddress(ctx context.Context, address string) (AddressWhitelist, error)
	GetWhitelistedPaymentHash(ctx context.Context, paymentHash []byte) (PaymentHashWhitelist, error)
	InsertAMPSubInvoiceHTLC(ctx context.Context, arg InsertAMPSubInvoiceHTLCParams) error
	InsertChannelConfig(ctx context.Context, arg InsertChannelConfigParams) (int64, error)
	InsertChannelInfo(ctx context.Context, arg InsertChannelInfoParams) (int64, error)
	InsertInvoice(ctx context.Context, arg InsertInvoiceParams) (int64, error)
	InsertInvoiceFeature(ctx context.Context, arg InsertInvoiceFeatureParams) error
	InsertInvoiceHTLC(ctx context.Context, arg InsertInvoiceHTLCParams) (int64, error)
	InsertInvoiceHTLCCustomRecord(ctx context.Context, arg InsertInvoiceHTLCCustomRecordParams) error
	InsertKeyDescriptor(ctx context.Context, arg InsertKeyDescriptorParams) (int64, error)
	InsertLocalCommitment(ctx context.Context, arg InsertLocalCommitmentParams) (int64, error)
	InsertWhitelistedAddress(ctx context.Context, arg InsertWhitelistedAddressParams) (int64, error)
	InsertWhitelistedPaymentHash(ctx context.Context, arg InsertWhitelistedPaymentHashParams) (int64, error)
	ListWhitelistedAddresses(ctx context.Context) ([]AddressWhitelist, error)
	ListWhitelistedPaymentHashes(ctx context.Context) ([]PaymentHashWhitelist, error)
	NextInvoiceSettleIndex(ctx context.Context) (int64, error)
	OnAMPSubInvoiceCanceled(ctx context.Context, arg OnAMPSubInvoiceCanceledParams) error
	OnAMPSubInvoiceCreated(ctx context.Context, arg OnAMPSubInvoiceCreatedParams) error
	OnAMPSubInvoiceSettled(ctx context.Context, arg OnAMPSubInvoiceSettledParams) error
	OnInvoiceCanceled(ctx context.Context, arg OnInvoiceCanceledParams) error
	OnInvoiceCreated(ctx context.Context, arg OnInvoiceCreatedParams) error
	OnInvoiceSettled(ctx context.Context, arg OnInvoiceSettledParams) error
	UpdateAMPSubInvoiceHTLCPreimage(ctx context.Context, arg UpdateAMPSubInvoiceHTLCPreimageParams) (sql.Result, error)
	UpdateAMPSubInvoiceState(ctx context.Context, arg UpdateAMPSubInvoiceStateParams) error
	UpdateInvoiceAmountPaid(ctx context.Context, arg UpdateInvoiceAmountPaidParams) (sql.Result, error)
	UpdateInvoiceHTLC(ctx context.Context, arg UpdateInvoiceHTLCParams) error
	UpdateInvoiceHTLCs(ctx context.Context, arg UpdateInvoiceHTLCsParams) error
	UpdateInvoiceState(ctx context.Context, arg UpdateInvoiceStateParams) (sql.Result, error)
	UpsertAMPSubInvoice(ctx context.Context, arg UpsertAMPSubInvoiceParams) (sql.Result, error)
}

var _ Querier = (*Queries)(nil)
