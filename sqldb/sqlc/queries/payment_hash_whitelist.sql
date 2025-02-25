-- name: InsertWhitelistedPaymentHash :one
INSERT INTO payment_hash_whitelist (
    payment_hash, amount_msat, created_at
) VALUES (
    $1, $2, $3
) RETURNING id;


-- name: GetWhitelistedPaymentHash :one
SELECT *
FROM payment_hash_whitelist
WHERE payment_hash = $1;

-- name: ListWhitelistedPaymentHashes :many
SELECT *
FROM payment_hash_whitelist;

-- name: DeleteWhitelistedPaymentHash :execresult
DELETE
FROM payment_hash_whitelist
WHERE payment_hash = $1;
