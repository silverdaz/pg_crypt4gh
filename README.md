# Crypt4GH Header decryptiong and re-encryption in Postgres

We provide a Postgres extension to reencrypt a Crypt4GH header

# Building the extension

	make
	make install

# PGXS

Inside the datase, use:

	CREATE EXTENSION pg_crypt4gh IN SCHEMA crypt4gh;

	# Re-encrypt a header
	SELECT * FROM crypt4gh.header_reencrypt(header, crypt4gh.parse_pubkey('ssh-ed25519 ...'));

	# Rotate headers
	with pk AS (
		SELECT crypt4gh.parse_pubkey('ssh-ed25519 ...') AS pubkey
	)
	SELECT header, crypt4gh.header_reencrypt(header, pk.pubkey)
	FROM public.table_with_all_headers;

	# Extract session keys
	SELECT * FROM crypt4gh.header_session_keys(header);
	

# Security considerations

The master key is written in hex format in the configuration file from the `config_file` variable.  
That file is owned by the postgres user and should not be readable by anyone else.

When reencrypting the packets, we chose to not create a new ephemeral key for each packet reencryption. Instead, we use the master public key itself, when deriving the shared key.
The master public key is then included as the sender, and users or tools could verify the provenance of the headers (akin to using a signature).

When rotating headers, pass the new master pubkey to the re-encrypting function, update the configuration with the master secret key and reboot the database afterwards.
