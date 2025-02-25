-- address_whitelist table.
CREATE TABLE IF NOT EXISTS address_whitelist (
    -- The id of the address_whitelist entry.
    id BIGINT PRIMARY KEY,

    -- The whitelisted address. This can either be a public key, a public key hash or a script hash.
    address TEXT UNIQUE NOT NULL,

    -- The whitelisted amount in millisatoshis.
    amount_msat BIGINT NOT NULL,

    -- Timestamp of when address was added to the whitelist.
    created_at TIMESTAMP NOT NULL
);

-- address_whitelist table.
CREATE TABLE IF NOT EXISTS payment_hash_whitelist (
    -- The id of the payment_hash_whitelist entry.
    id BIGINT PRIMARY KEY,

    -- The whitelisted payment hash.
    payment_hash BLOB UNIQUE NOT NULL,

    -- The whitelisted amount in millisatoshis.
    amount_msat BIGINT NOT NULL,

    -- Timestamp of when payment hash was added to the whitelist.
    created_at TIMESTAMP NOT NULL
);
