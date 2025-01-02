-- name: InsertWhitelistedAddress :one
INSERT INTO address_whitelist (
    address, amount_msat, created_at
) VALUES (
    $1, $2, $3
) RETURNING id;


-- name: GetWhitelistedAddress :one
SELECT *
FROM address_whitelist
WHERE address = $1;

-- name: ListWhitelistedAddresses :many
SELECT *
FROM address_whitelist;

-- name: DeleteWhitelistedAddress :execresult
DELETE
FROM address_whitelist
WHERE address = $1;