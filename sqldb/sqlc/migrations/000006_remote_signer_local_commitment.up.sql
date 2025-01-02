-- local_commitment table.
CREATE TABLE IF NOT EXISTS local_commitment (
    -- The id of the local_commitment entry.
    id BIGINT PRIMARY KEY,

    -- The package that the commitment tx was sent in, which includes metadata.
    commitment_tx_package BLOB NOT NULL,

    -- The funding txid for the channel.
    funding_txid BLOB NOT NULL,

    -- The output index for the channel in the funding tx.
    funding_output_index INTEGER NOT NULL,

    -- The commitment height for this specific channel.
    commitment_height BIGINT NOT NULL,

    -- Timestamp of when local_commitment tx was added.
    created_at TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX idx_local_commitment_at_height
    ON local_commitment(funding_txid, funding_output_index, commitment_height DESC);