-- name: InsertLocalCommitment :one
INSERT INTO local_commitment (
   commitment_tx_package, funding_txid, funding_output_index,
    commitment_height, created_at
) VALUES (
             $1, $2, $3, $4, $5
         ) RETURNING id;

-- name: GetLatestLocalCommitment :one
SELECT *
FROM local_commitment
WHERE funding_txid = $1
  AND funding_output_index = $2
ORDER BY commitment_height DESC
    LIMIT 1;

-- name: DeleteLocalCommitment :execresult
DELETE FROM local_commitment
WHERE funding_txid = $1
  AND funding_output_index = $2
  AND commitment_height = $3;