-- name: InsertKeyDescriptor :one
INSERT INTO key_descriptor (
    raw_key_bytes, key_family, key_index
) VALUES (
             $1, $2, $3
         ) RETURNING id;


-- name: InsertChannelConfig :one
INSERT INTO channel_config (
    chan_reserve_sat, max_pending_amt_msat, min_htlc, max_accepted_htlcs,
    dust_limit, csv_delay,
    multi_sig_key_id, revocation_base_point_id, payment_base_point_id,
    delay_base_point_id, htlc_base_point_id
) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
         ) RETURNING id;



-- name: InsertChannelInfo :one
INSERT INTO channel_info (
    txid_bytes, txid_str, output_index, channel_type,
    is_local_initiator, local_channel_config_id, remote_channel_config_id, created_at
) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8
         ) RETURNING id;


-- name: GetChannelInfo :one
SELECT *
FROM channel_info
WHERE txid_bytes = $1
  AND output_index = $2;


-- name: DeleteChannelInfo :execresult
DELETE FROM channel_info
WHERE txid_bytes = $1
  AND output_index = $2;


-- name: GetChannelInfoWithConfigs :one
SELECT
    ci.id AS channel_info_id,
    ci.txid_bytes,
    ci.txid_str,
    ci.output_index,
    ci.channel_type,
    ci.is_local_initiator,
    ci.created_at,

    -- Local ChannelConfig columns:
    lcc.id AS local_channel_config_id,
    lcc.chan_reserve_sat AS local_chan_reserve_sat,
    lcc.max_pending_amt_msat AS local_max_pending_amt_msat,
    lcc.min_htlc AS local_min_htlc,
    lcc.max_accepted_htlcs AS local_max_accepted_htlcs,
    lcc.dust_limit AS local_dust_limit,
    lcc.csv_delay AS local_csv_delay,
    lms.id AS local_multi_sig_key_id,
    lms.raw_key_bytes AS local_multi_sig_raw_key_bytes,
    lms.key_family AS local_multi_sig_key_family,
    lms.key_index AS local_multi_sig_key_index,
    lrev.id AS local_revocation_base_point_id,
    lrev.raw_key_bytes AS local_revocation_raw_key_bytes,
    lrev.key_family AS local_revocation_key_family,
    lrev.key_index AS local_revocation_key_index,
    lpay.id AS local_payment_base_point_id,
    lpay.raw_key_bytes AS local_payment_raw_key_bytes,
    lpay.key_family AS local_payment_key_family,
    lpay.key_index AS local_payment_key_index,
    ldel.id AS local_delay_base_point_id,
    ldel.raw_key_bytes AS local_delay_base_point_raw,
    ldel.key_family AS local_delay_base_point_key_family,
    ldel.key_index AS local_delay_base_point_key_index,
    lhtlc.id AS local_htlc_base_point_id,
    lhtlc.raw_key_bytes AS local_htlc_base_point_raw,
    lhtlc.key_family AS local_htlc_base_point_key_family,
    lhtlc.key_index AS local_htlc_base_point_key_index,

    -- Remote ChannelConfig columns:
    rcc.id AS remote_channel_config_id,
    rcc.chan_reserve_sat AS remote_chan_reserve_sat,
    rcc.max_pending_amt_msat AS remote_max_pending_amt_msat,
    rcc.min_htlc AS remote_min_htlc,
    rcc.max_accepted_htlcs AS remote_max_accepted_htlcs,
    rcc.dust_limit AS remote_dust_limit,
    rcc.csv_delay AS remote_csv_delay,
    rms.id AS remote_multi_sig_key_id,
    rms.raw_key_bytes AS remote_multi_sig_raw_key_bytes,
    rms.key_family AS remote_multi_sig_key_family,
    rms.key_index AS remote_multi_sig_key_index,
    rrev.id AS remote_revocation_base_point_id,
    rrev.raw_key_bytes AS remote_revocation_raw_key_bytes,
    rrev.key_family AS remote_revocation_key_family,
    rrev.key_index AS remote_revocation_key_index,
    rpay.id AS remote_payment_base_point_id,
    rpay.raw_key_bytes AS remote_payment_base_point_raw,
    rpay.key_family AS remote_payment_key_family,
    rpay.key_index AS remote_payment_key_index,
    rdel.id AS remote_delay_base_point_id,
    rdel.raw_key_bytes AS remote_delay_base_point_raw,
    rdel.key_family AS remote_delay_base_point_key_family,
    rdel.key_index AS remote_delay_base_point_key_index,
    rhtlc.id AS remote_htlc_base_point_id,
    rhtlc.raw_key_bytes AS remote_htlc_base_point_raw,
    rhtlc.key_family AS remote_htlc_base_point_key_family,
    rhtlc.key_index AS remote_htlc_base_point_key_index
FROM channel_info ci
         JOIN channel_config lcc ON lcc.id = ci.local_channel_config_id
         JOIN key_descriptor lms ON lms.id = lcc.multi_sig_key_id
         JOIN key_descriptor lrev ON lrev.id = lcc.revocation_base_point_id
         JOIN key_descriptor lpay ON lpay.id = lcc.payment_base_point_id
         JOIN key_descriptor ldel ON ldel.id = lcc.delay_base_point_id
         JOIN key_descriptor lhtlc ON lhtlc.id = lcc.htlc_base_point_id
         JOIN channel_config rcc ON rcc.id = ci.remote_channel_config_id
         JOIN key_descriptor rms ON rms.id = rcc.multi_sig_key_id
         JOIN key_descriptor rrev ON rrev.id = rcc.revocation_base_point_id
         JOIN key_descriptor rpay ON rpay.id = rcc.payment_base_point_id
         JOIN key_descriptor rdel ON rdel.id = rcc.delay_base_point_id
         JOIN key_descriptor rhtlc ON rhtlc.id = rcc.htlc_base_point_id
WHERE ci.txid_bytes = $1
  AND ci.output_index = $2;

