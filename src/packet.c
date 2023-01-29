
#include "includes.h"


/*
 * Decrypt `data` and outputs to `output`.
 * The caller must clean up the output buffer in case of errors
 */
int
packet_decrypt(const uint8_t* data, size_t data_len,
	       uint8_t* output, size_t* output_len,
	       const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
	       const uint8_t seckey[crypto_box_SECRETKEYBYTES],
	       int ignore_edit_lists)
{
  int rc = 1;
  uint8_t sender_pubkey[crypto_box_PUBLICKEYBYTES];
  uint8_t nonce[NONCE_LEN];
  uint8_t ignored[crypto_kx_SESSIONKEYBYTES];
  uint8_t* shared_key = NULL;
  unsigned long long outlen;
  uint32_t packet_type;

  if(output == NULL ||
     data_len < CRYPT4GH_HEADER_PACKET_ENVELOPE_LEN)
    return CRYPT4GH_ERR_INVALID_PARAMETERS;

  /* encryption method */
  if(PEEK_U32_LE(data) != X25519_chacha20_ietf_poly1305)
    return CRYPT4GH_ERR_HEADER_INVALID_ENCRYPTION;
  data += 4;
  data_len -= 4;

  /* sender's pubkey */
  memcpy(sender_pubkey, data, crypto_box_PUBLICKEYBYTES);
  data += crypto_box_PUBLICKEYBYTES;
  data_len -= crypto_box_PUBLICKEYBYTES;

  /* nonce */
  memcpy(nonce, data, NONCE_LEN);
  data += NONCE_LEN;
  data_len -= NONCE_LEN;

  /* X25519 shared keys */
  errno = 0;
  shared_key = (uint8_t*)sodium_malloc(crypto_kx_SESSIONKEYBYTES);

  if(!shared_key ||
     errno == ENOMEM)
    {
      D1("Unable to allocated memory for the shared decryption key");
      rc = CRYPT4GH_ERR_MEMORY_ALLOCATION;
      goto bailout;
    }
  rc = crypto_kx_client_session_keys(shared_key,     /* receive */
				     ignored,        /* transmit */
				     pubkey,         /* client pk */
				     seckey,         /* client sk */
				     sender_pubkey); /* server pk */
  if(rc){
    D1("Unable to derive the shared key: %d", rc);
    rc = CRYPT4GH_ERR_INTERNAL_ERROR;
    goto bailout;
  }
  sodium_mprotect_readonly(shared_key);
  sodium_memzero(ignored, crypto_kx_SESSIONKEYBYTES);

  /* decrypted packet (and mac), and re-encrypt packet (and mac) */
  D3("Encrypted Packet length: %zu", data_len);

  /* decrypt */
  rc = crypto_aead_chacha20poly1305_ietf_decrypt(output, &outlen,
						 NULL,
						 data, data_len,
						 NULL, 0, /* no authenticated data */
						 nonce, shared_key);
  if(rc){
    rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
    goto bailout;
  }

  /* Check packet type */
  if(outlen < 4) {
    D1("Packet too small");
    rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
    goto bailout;
  }
  packet_type = PEEK_U32_LE(output);
  switch(packet_type){
  case data_encryption_parameters:
    if(outlen < CRYPT4GH_HEADER_DATA_PACKET_LEN){ 
      D1("Data encryption packet too small: %llu bytes", outlen);
      rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
      goto bailout;
    }
    break;
  case data_edit_list:
    if(ignore_edit_lists){
      D1("We ignore the edit lists: %d", packet_type);
      rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
      goto bailout;
    }
    break;
  default:
    D1("Unsupported packet type: %d", packet_type);
    rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
    goto bailout;
    break;
  }

  /* success */
  if(output_len)
    *output_len = (size_t)outlen;
  rc = CRYPT4GH_ERR_SUCCESS;

bailout:
  if(shared_key) sodium_free(shared_key);
  return rc;
}


/*
 * Encrypt `data` and outputs to `output`.
 * The caller must clean up the output buffer in case of errors
 * We pass the output buffer size in output_len and overwrite the 
 * length with the real written size
 */
int
packet_encrypt(const uint8_t* data, size_t data_len,
	       uint8_t* output, size_t* output_len,
	       const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
	       const uint8_t seckey[crypto_box_SECRETKEYBYTES],
	       const uint8_t recipient_pubkey[crypto_box_PUBLICKEYBYTES])
{
  int rc = 1;
  size_t outlen = (4U /* packet length */ + 4U /* encryption method */
		   + crypto_box_PUBLICKEYBYTES /* recipient_pk */
		   + NONCE_LEN                 /* nonce */
		   + data_len                  /* data length */
		   + crypto_box_MACBYTES);     /* MAC */
  uint8_t* p = output;
  uint8_t* shared_key = NULL;
  uint8_t ignored[crypto_kx_SESSIONKEYBYTES];
  uint8_t nonce[NONCE_LEN];
  unsigned long long len;

  if(output == NULL       ||
     data_len == 0        || /* unsigned already */
     output_len == NULL   ||
     *output_len < outlen)
    return CRYPT4GH_ERR_INVALID_PARAMETERS;

  /* X25519 shared key */
  errno = 0;
  shared_key = (uint8_t*)sodium_malloc(crypto_kx_SESSIONKEYBYTES);

  if(!shared_key || errno == ENOMEM)
    {
      E("Unable to allocated memory for the shared decryption key");
      rc = CRYPT4GH_ERR_MEMORY_ALLOCATION;
      goto bailout;
    }
  rc = crypto_kx_server_session_keys(ignored,           /* receive */
				     shared_key,        /* transmit */
				     pubkey,            /* server pk */
				     seckey,            /* server sk */
				     recipient_pubkey); /* client pk */
  if(rc){
    E("Unable to derive the shared key: %d", rc);
    rc = CRYPT4GH_ERR_INTERNAL_ERROR;
    goto bailout;
  }
  sodium_mprotect_readonly(shared_key);
  sodium_memzero(ignored, crypto_kx_SESSIONKEYBYTES);

  /* length */
  PUT_32BIT_LE(p, outlen);
  D3("Packet length (+4): %zu", outlen);
  D3("packet writing in %p", p);
  p+=4;

  /* encryption method */
  PUT_32BIT_LE(p, X25519_chacha20_ietf_poly1305);
  D3("Encryption method: %d", X25519_chacha20_ietf_poly1305);
  p+=4;

  /* sender's pubkey */
  memcpy(p, pubkey, crypto_box_PUBLICKEYBYTES);
  p+=crypto_box_PUBLICKEYBYTES;

  /* nonce */
  randombytes_buf(nonce, NONCE_LEN);
  memcpy(p, nonce, NONCE_LEN);
  p+=NONCE_LEN;

  /* encrypt session key (and mac) */
  rc = crypto_aead_chacha20poly1305_ietf_encrypt(p, &len,
						 data, data_len,
						 NULL, 0, /* no authenticated data */
						 NULL, nonce, shared_key);
  if(rc){
    E("Error %d encrypting the data", rc);
    rc = CRYPT4GH_ERR_PACKET_DECRYPTION;
    goto bailout;
  }
 
  /* success */
  *output_len = outlen;
  rc = CRYPT4GH_ERR_SUCCESS;

bailout:
  if(shared_key) sodium_free(shared_key);
  return rc;
}
