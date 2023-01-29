#ifndef __PG_CRYPT4GH_DEBUG_H_INCLUDED__
#define __PG_CRYPT4GH_DEBUG_H_INCLUDED__ 1

#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"

/* logging */
#define F(fmt, ...)  elog(FATAL,  "============ " fmt, ##__VA_ARGS__)
#define E(fmt, ...)  elog(ERROR,  "============ " fmt, ##__VA_ARGS__)
#define W(fmt, ...)  elog(WARNING,"============ " fmt, ##__VA_ARGS__)
#define N(fmt, ...)  elog(NOTICE, "============ " fmt, ##__VA_ARGS__)
#define L(fmt, ...)  elog(LOG,    "============ " fmt, ##__VA_ARGS__)
#define D1(fmt, ...) elog(DEBUG1, "============ " fmt, ##__VA_ARGS__)
#define D2(fmt, ...) elog(DEBUG2, "============ " fmt, ##__VA_ARGS__)
#define D3(fmt, ...) elog(DEBUG3, "============ " fmt, ##__VA_ARGS__)
#define D4(fmt, ...) elog(DEBUG4, "============ " fmt, ##__VA_ARGS__)
#define D5(fmt, ...) elog(DEBUG5, "============ " fmt, ##__VA_ARGS__)


#include <sys/types.h>
#include <ctype.h> /* isspace */
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sodium.h>

/* Abort in case of memory allocation errors */
/*
  extern char *malloc_options;
  malloc_options = "X";
*/

#define MAGIC_NUMBER "crypt4gh"
#define VERSION      1U

#define NONCE_LEN                           crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define CRYPT4GH_SESSION_KEY_SIZE           crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define CRYPT4GH_HEADER_DATA_PACKET_LEN     (4U + 4U + CRYPT4GH_SESSION_KEY_SIZE)
#define CRYPT4GH_HEADER_PACKET_ENVELOPE_LEN (4U + 4U + crypto_box_PUBLICKEYBYTES + NONCE_LEN + crypto_box_MACBYTES)

typedef enum {
  data_encryption_parameters = 0,
  data_edit_list = 1
} header_packet_type;

/* We only support the Chacha20+Poly1305 encryption */
typedef enum {
  X25519_chacha20_ietf_poly1305 = 0
} header_packet_encryption_method;

typedef enum {
  chacha20_ietf_poly1305 = 0
} header_data_encryption_type;


#define CRYPT4GH_ERR_SUCCESS             0
#define CRYPT4GH_ERR_INTERNAL_ERROR      1
#define CRYPT4GH_ERR_MEMORY_ALLOCATION   2
#define CRYPT4GH_ERR_INVALID_PARAMETERS  3
#define CRYPT4GH_ERR_PACKET_DECRYPTION   4
#define CRYPT4GH_ERR_SEGMENT_DECRYPTION  5
#define CRYPT4GH_ERR_SYSTEM_ERROR        6
#define CRYPT4GH_ERR_MAC_INVALID         7
#define CRYPT4GH_ERR_NO_CIPHER_ALG_MATCH 8
#define CRYPT4GH_ERR_INVALID_PASSPHRASE  9
#define CRYPT4GH_ERR_KEY_UNKNOWN_CIPHER  10
#define CRYPT4GH_ERR_KEY_BAD_PERMISSIONS 11
#define CRYPT4GH_ERR_KEY_NOT_FOUND       12
#define CRYPT4GH_ERR_HEADER_INVALID      13
#define CRYPT4GH_ERR_HEADER_INVALID_ENCRYPTION 14


const char* crypt4gh_err(int n);


/*
 * Copy a value to cp in little-endian format
 */
/*
#ifdef HAVE_ENDIAN_H
# include <endian.h>
#else
#endif
*/

#define PUT_64BIT_LE(cp, value) do {					\
    (cp)[7] = (value) >> 56;						\
    (cp)[6] = (value) >> 48;						\
    (cp)[5] = (value) >> 40;						\
    (cp)[4] = (value) >> 32;						\
    (cp)[3] = (value) >> 24;						\
    (cp)[2] = (value) >> 16;						\
    (cp)[1] = (value) >> 8;						\
    (cp)[0] = (value); } while (0)

#define PUT_32BIT_LE(cp, value) do {					\
    (cp)[3] = (value) >> 24;						\
    (cp)[2] = (value) >> 16;						\
    (cp)[1] = (value) >> 8;						\
    (cp)[0] = (value); } while (0)

/*
 * Read 8 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U64_LE(p) \
	(((uint64_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint64_t)(((const uint8_t *)(p))[1]) <<  8) | \
	 ((uint64_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint64_t)(((const uint8_t *)(p))[3]) << 24) | \
	 ((uint64_t)(((const uint8_t *)(p))[4]) << 32) | \
	 ((uint64_t)(((const uint8_t *)(p))[5]) << 40) | \
	 ((uint64_t)(((const uint8_t *)(p))[6]) << 48) | \
	 ((uint64_t)(((const uint8_t *)(p))[7]) << 56))
/* Left shift are filled with zeros */

/*
 * Read 4 bytes from p and 
 * get its integer representation in little-endian format
 */
#define PEEK_U32_LE(p) \
	(((uint32_t)(((const uint8_t *)(p))[0])      ) | \
	 ((uint32_t)(((const uint8_t *)(p))[1]) << 8 ) | \
	 ((uint32_t)(((const uint8_t *)(p))[2]) << 16) | \
	 ((uint32_t)(((const uint8_t *)(p))[3]) << 24))


/*
 * Read 4 bytes from p and 
 * get its integer representation in big-endian format
 */
#define PEEK_U32(p) \
	(((u_int32_t)(((const u_char *)(p))[0]) << 24) | \
	 ((u_int32_t)(((const u_char *)(p))[1]) << 16) | \
	 ((u_int32_t)(((const u_char *)(p))[2]) << 8) | \
	  (u_int32_t)(((const u_char *)(p))[3]))


int pg_crypt4gh_get_public_key_from_blob(const char* line, size_t len,
					  uint8_t pk[crypto_kx_PUBLICKEYBYTES]);

/*
 * Encrypt `data` and outputs into the pre-allocated `output`.
 * The caller must clean up the output buffer in case of errors
 */
int
packet_encrypt(const uint8_t* data, size_t data_len,
	       uint8_t* output, size_t* output_len,
	       const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
	       const uint8_t seckey[crypto_box_SECRETKEYBYTES],
	       const uint8_t recipient_pubkey[crypto_box_PUBLICKEYBYTES]);

/*
 * Decrypt `data` and outputs into the pre-allocated `output`.
 * The caller must clean up the output buffer in case of errors
 */
int
packet_decrypt(const uint8_t* data, size_t data_len,
	       uint8_t* output, size_t* output_len,
	       const uint8_t pubkey[crypto_box_PUBLICKEYBYTES],
	       const uint8_t seckey[crypto_box_SECRETKEYBYTES],
	       int ignore_edit_lists);


#endif /* !__PG_CRYPT4GH_DEBUG_H_INCLUDED__ */
