-- Table for ChannelInfo.
CREATE TABLE IF NOT EXISTS channel_info (
    id INTEGER PRIMARY KEY,

    -- OutPoint fields:
    txid_bytes BLOB NOT NULL,       -- OutPoint.txid_bytes
    txid_str TEXT NOT NULL,         -- OutPoint.txid_str
    output_index INTEGER NOT NULL,  -- OutPoint.output_index

    channel_type BIGINT NOT NULL,       -- FundingInfo.channel_type (uint64)
    is_local_initiator BOOLEAN NOT NULL,  -- FundingInfo.is_local_initiator

    local_channel_config_id BIGINT NOT NULL,  -- FK to local ChannelConfig
    remote_channel_config_id BIGINT NOT NULL, -- FK to remote ChannelConfig

    created_at TIMESTAMP NOT NULL,

    FOREIGN KEY (local_channel_config_id) REFERENCES channel_config(id),
    FOREIGN KEY (remote_channel_config_id) REFERENCES channel_config(id)
    );

-- Table for ChannelConfig.
CREATE TABLE IF NOT EXISTS channel_config (
    id INTEGER PRIMARY KEY,

    -- ChannelStateBounds fields:
    chan_reserve_sat BIGINT NOT NULL,      -- ChannelStateBounds.chan_reserve_sat
    max_pending_amt_msat BIGINT NOT NULL,    -- ChannelStateBounds.max_pending_amt_msat
    min_htlc BIGINT NOT NULL,                -- ChannelStateBounds.min_htlc
    max_accepted_htlcs INTEGER NOT NULL,     -- ChannelStateBounds.max_accepted_htlcs

    -- CommitmentParams fields:
    dust_limit BIGINT NOT NULL,              -- CommitmentParams.dust_limit
    csv_delay INTEGER NOT NULL,              -- CommitmentParams.csv_delay

    -- Foreign keys to KeyDescriptor for each key:
    multi_sig_key_id BIGINT NOT NULL,
    revocation_base_point_id BIGINT NOT NULL,
    payment_base_point_id BIGINT NOT NULL,
    delay_base_point_id BIGINT NOT NULL,
    htlc_base_point_id BIGINT NOT NULL,

    FOREIGN KEY (multi_sig_key_id) REFERENCES key_descriptor(id),
    FOREIGN KEY (revocation_base_point_id) REFERENCES key_descriptor(id),
    FOREIGN KEY (payment_base_point_id) REFERENCES key_descriptor(id),
    FOREIGN KEY (delay_base_point_id) REFERENCES key_descriptor(id),
    FOREIGN KEY (htlc_base_point_id) REFERENCES key_descriptor(id)
    );

-- Table for KeyDescriptor.
CREATE TABLE IF NOT EXISTS key_descriptor (
    id INTEGER PRIMARY KEY,
    raw_key_bytes BLOB NOT NULL,    -- The raw key bytes.
    key_family INTEGER NOT NULL,     -- KeyLocator.key_family
    key_index INTEGER NOT NULL       -- KeyLocator.key_index
);
