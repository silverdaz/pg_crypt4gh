-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_crypt4gh" to load this file. \quit


DO $$
BEGIN
   IF current_setting('crypt4gh.master_seckey') IS NULL 
   THEN
      RAISE EXCEPTION 'Missing Crypt4GH settings'
      USING HINT = 'Add crypt4gh.master_seckey = ''...'' (in hex format) in postgresql.conf ';
   END IF;
END;
$$;


-- STRICT  = NULL parameters return NULL immediately

-- Extract 32 bytes from pubkey text
CREATE OR REPLACE FUNCTION parse_pubkey(text)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pg_crypt4gh_parse_pubkey'
LANGUAGE C IMMUTABLE STRICT;

-- Re-encrypt header for given pubkey (as 32-bytes)
CREATE OR REPLACE FUNCTION header_reencrypt(bytea, bytea)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pg_crypt4gh_header_reencrypt'
LANGUAGE C IMMUTABLE STRICT;

-- Re-encrypt header for given array of pubkeys (as 32-bytes)
CREATE OR REPLACE FUNCTION header_reencrypt(bytea, bytea[])
RETURNS bytea
AS 'MODULE_PATHNAME', 'pg_crypt4gh_header_reencrypt_multiple'
LANGUAGE C IMMUTABLE STRICT;

-- Decrypts header and output the session keys
-- OBS: output sensitive material!
CREATE OR REPLACE FUNCTION header_session_keys(bytea)
RETURNS SETOF bytea
AS 'MODULE_PATHNAME', 'pg_crypt4gh_header_session_keys'
LANGUAGE C IMMUTABLE STRICT;


