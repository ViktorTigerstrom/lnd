// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package sqlc

import (
	"database/sql"
	"time"
)

type AddressWhitelist struct {
	ID         int64
	Address    string
	AmountMsat int64
	CreatedAt  time.Time
}

type AmpSubInvoice struct {
	SetID       []byte
	State       int16
	CreatedAt   time.Time
	SettledAt   sql.NullTime
	SettleIndex sql.NullInt64
	InvoiceID   int64
}

type AmpSubInvoiceHtlc struct {
	InvoiceID  int64
	SetID      []byte
	HtlcID     int64
	RootShare  []byte
	ChildIndex int64
	Hash       []byte
	Preimage   []byte
}

type ChannelConfig struct {
	ID                    int64
	ChanReserveSat        int64
	MaxPendingAmtMsat     int64
	MinHtlc               int64
	MaxAcceptedHtlcs      int32
	DustLimit             int64
	CsvDelay              int32
	MultiSigKeyID         int64
	RevocationBasePointID int64
	PaymentBasePointID    int64
	DelayBasePointID      int64
	HtlcBasePointID       int64
}

type ChannelInfo struct {
	ID                    int64
	TxidBytes             []byte
	TxidStr               string
	OutputIndex           int32
	ChannelType           int64
	IsLocalInitiator      bool
	LocalChannelConfigID  int64
	RemoteChannelConfigID int64
	CreatedAt             time.Time
}

type Invoice struct {
	ID                 int64
	Hash               []byte
	Preimage           []byte
	SettleIndex        sql.NullInt64
	SettledAt          sql.NullTime
	Memo               sql.NullString
	AmountMsat         int64
	CltvDelta          sql.NullInt32
	Expiry             int32
	PaymentAddr        []byte
	PaymentRequest     sql.NullString
	PaymentRequestHash []byte
	State              int16
	AmountPaidMsat     int64
	IsAmp              bool
	IsHodl             bool
	IsKeysend          bool
	CreatedAt          time.Time
}

type InvoiceEvent struct {
	ID        int64
	AddedAt   time.Time
	EventType int32
	InvoiceID int64
	SetID     []byte
}

type InvoiceEventType struct {
	ID          int64
	Description string
}

type InvoiceFeature struct {
	Feature   int32
	InvoiceID int64
}

type InvoiceHtlc struct {
	ID           int64
	ChanID       string
	HtlcID       int64
	AmountMsat   int64
	TotalMppMsat sql.NullInt64
	AcceptHeight int32
	AcceptTime   time.Time
	ExpiryHeight int32
	State        int16
	ResolveTime  sql.NullTime
	InvoiceID    int64
}

type InvoiceHtlcCustomRecord struct {
	Key    int64
	Value  []byte
	HtlcID int64
}

type InvoicePaymentHash struct {
	ID       int64
	AddIndex int64
	Hash     []byte
}

type InvoiceSequence struct {
	Name         string
	CurrentValue int64
}

type KeyDescriptor struct {
	ID          int64
	RawKeyBytes []byte
	KeyFamily   int32
	KeyIndex    int32
}

type LocalCommitment struct {
	ID                  int64
	CommitmentTxPackage []byte
	FundingTxid         []byte
	FundingOutputIndex  int32
	CommitmentHeight    int64
	CreatedAt           time.Time
}

type MigrationTracker struct {
	Version       int32
	MigrationTime time.Time
}

type PaymentHashWhitelist struct {
	ID          int64
	PaymentHash []byte
	AmountMsat  int64
	CreatedAt   time.Time
}
