/*-------------------------------------------------------------------------
 *
 * src/pg_crypt4gh.c
 *
 * Implementation of the Crypt4GH header reencrypt functions inside PG.
 * See documentation: https://www.postgresql.org/docs/14/xfunc-c.html
 *
 *-------------------------------------------------------------------------
 */
#include <sodium.h>
#include <sys/mman.h>

#include "postgres.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "utils/array.h" /* [pg_config --includedir-server]/utils/array.h */
#include "utils/builtins.h" /* for hex_decode */
#include "utils/guc.h"
#include "funcapi.h"

PG_MODULE_MAGIC; /* only one time */

#include "includes.h"

#define PG_CRYPT4GH_PREFIX   "crypt4gh"
#define PG_CRYPT4GH_CONFNAME "crypt4gh.master_seckey"

/* global settings */
static char* pg_crypt4gh_master_seckey = NULL;

static uint8_t* sk = NULL; //[crypto_kx_SECRETKEYBYTES];
static uint8_t pk[crypto_kx_PUBLICKEYBYTES];

void _PG_init(void);
void _PG_fini(void);

static bool
sk_check_hook(char **newval, void **extra, GucSource source)
{

  D3("Check " PG_CRYPT4GH_CONFNAME " [%d]: newval %s", (int)source, (char*)*newval);

  if (source == PGC_S_DEFAULT){
    GUC_check_errmsg("%s ignored when setting default value", PG_CRYPT4GH_CONFNAME);
    GUC_check_errhint("%s can only be set from postgres.conf.", PG_CRYPT4GH_CONFNAME);
    return true;
  }

  if (source != PGC_S_FILE){
    GUC_check_errmsg("%s ignored when source source is not %d", PG_CRYPT4GH_CONFNAME, PGC_S_FILE);
    GUC_check_errhint("%s can only be set from postgres.conf.", PG_CRYPT4GH_CONFNAME);
    return false;
  }

  if (**newval == '\0'){
    GUC_check_errmsg("%s can't be empty.", PG_CRYPT4GH_CONFNAME);
    return false;
  }

  if(strlen(*newval) != (2 * crypto_kx_SECRETKEYBYTES)){
    GUC_check_errmsg("Invalid hex value for %s: %s", PG_CRYPT4GH_CONFNAME, *newval);
    return false;
  }

  return true;
}

static void
sk_assign_hook(const char* value, void *extra)
{

  D3("Assign " PG_CRYPT4GH_CONFNAME " | new value: %s | current value: %s", value, pg_crypt4gh_master_seckey);

  if(!value || *value == '\0')
    return;

  /* clean up if exists */
  if(sk){
    memset(sk, 0, crypto_kx_SECRETKEYBYTES);
    munmap(sk, crypto_kx_SECRETKEYBYTES);
    memset(pk, 0, crypto_kx_PUBLICKEYBYTES);
    sk = NULL;
  }

  /* Fill in the master_key from the above setting, in a private memory */
  sk = mmap(NULL, crypto_kx_SECRETKEYBYTES, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
	    -1, 0);
  if (sk == MAP_FAILED)
    F("pg_crypt4gh failed to allocate locked page for the master key");

  /* lock it */
  if (mlock(sk, crypto_kx_SECRETKEYBYTES) == -1)
    F("pg_crypt4gh failed to lock the page of the master key");

  /* un-hex it */
  if(hex_decode(value, 2 * crypto_kx_SECRETKEYBYTES, (char*)sk) != crypto_kx_SECRETKEYBYTES)
    F("pg_crypt4gh failed to read hex value for master key");

  /* derive pubkey */
  if(crypto_scalarmult_base(pk, sk))
    F("pg_crypt4gh can't derive the master pubkey");

  L("Crypt4GH Master key loaded");
}


static const char*
sk_show_hook(void)
{
  return "yeah... nice try!";
}


static void
sk_clean(void)
{
  if(!sk) return;
  memset(sk, 0, crypto_kx_SECRETKEYBYTES);
  munmap(sk, crypto_kx_SECRETKEYBYTES);
  memset(pk, 0, crypto_kx_PUBLICKEYBYTES);
  sk = NULL;
}

/*
 * This gets called when the library file is loaded.
 * Similar to dlopen
 */
void
_PG_init(void)
{
  if (!process_shared_preload_libraries_in_progress)
    {
      ereport(ERROR, (errmsg("pg_crypt4gh can only be loaded via shared_preload_libraries"),
		      errhint("Add pg_crypt4gh to the shared_preload_libraries "
			      "configuration variable in postgresql.conf.")));
    }

  if (sodium_init() == -1) {
      E("pg_crypt4gh can't load libsodium");
  }

  W("Shared libs: %s", shared_preload_libraries_string);

  /* Register the master key variable (in hex format) */
  DefineCustomStringVariable(PG_CRYPT4GH_CONFNAME,
			     gettext_noop("The Crypt4GH (unlocked) master secret key hex value."),
			     NULL,
			     &pg_crypt4gh_master_seckey,
			     NULL, /* no default */
			     PGC_POSTMASTER,
 			     GUC_SUPERUSER_ONLY |
			     GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE |
			     GUC_DISALLOW_IN_AUTO_FILE | GUC_NOT_WHILE_SEC_REST | GUC_NO_RESET_ALL,
			     sk_check_hook, sk_assign_hook, sk_show_hook);

  MarkGUCPrefixReserved(PG_CRYPT4GH_PREFIX);
}

/*
 * This gets called when the library file is unloaded.
 */
void
_PG_fini(void)
{
  D3("Postgres: cleaning");
  sk_clean();
}



PG_FUNCTION_INFO_V1(pg_crypt4gh_parse_pubkey);
Datum
pg_crypt4gh_parse_pubkey(PG_FUNCTION_ARGS)
{
  int rc = 1;
  text*  pubkey;
  bytea* k;

  if(PG_ARGISNULL(0)){
    E("Null arguments not accepted");
    PG_RETURN_NULL();
  }

  pubkey = PG_GETARG_TEXT_PP(0);

  k = (bytea*) palloc0(VARHDRSZ + crypto_kx_PUBLICKEYBYTES);
  if(!k)
    E("Memory allocation error");
    
  SET_VARSIZE(k, VARHDRSZ + crypto_kx_PUBLICKEYBYTES);

  if((rc = pg_crypt4gh_get_public_key_from_blob(VARDATA_ANY(pubkey),
						(size_t)VARSIZE_ANY_EXHDR(pubkey),
						(uint8_t*)VARDATA_ANY(k))))
    {
      L("Unable to parse the public key: %s", crypt4gh_err(rc));
      PG_RETURN_NULL();
    }
  
  PG_RETURN_BYTEA_P(k);
}


/*
 * We transfer the hd_in into hd_out, while decrypting and
 * reencrypting the packets.
 */
static int
do_header_reencrypt(const uint8_t* hd_in, size_t hd_in_len,
		    uint8_t** hd_out, size_t* hd_out_len,
		    const uint8_t* recipient_pubkeys, unsigned int nrkeys)
{
  int rc = 1; /* error: wrong interface */
  uint8_t* buf = NULL;
  uint8_t* p = buf;
  size_t plen = 0;
  int npackets_in = 0, npackets_out = 0;
  uint8_t* decrypted_packet = NULL;
  size_t buflen = 0;
  size_t packet_in_len = 0;
  int packet = 0;
  size_t decrypted_packet_len = 0;
  int recipient = 0;
  
  if( hd_out == NULL /* nowhere to output */ ||
      hd_in_len < 16 /* too small */)
    return CRYPT4GH_ERR_INVALID_PARAMETERS;

  if(memcmp(hd_in, MAGIC_NUMBER, 8)) /* Wrong magic number */
   return CRYPT4GH_ERR_HEADER_INVALID;
  hd_in += 8;
  hd_in_len -= 8;

  if(PEEK_U32_LE(hd_in) != VERSION) /* Unsupported version */
    return CRYPT4GH_ERR_HEADER_INVALID;
  hd_in += 4;
  hd_in_len -= 4;

  /* Get # of packets */
  npackets_in = PEEK_U32_LE(hd_in);
  D3("output nb packets: %d", npackets_in);
  hd_in += 4;
  hd_in_len -= 4;

  /* Nothing to do => something is off, we bail out */
  if( npackets_in == 0 )
    return CRYPT4GH_ERR_HEADER_INVALID;

  /* Output buffer: size = all packets x number of recipients */
  errno = 0;
  *hd_out = NULL;
  buflen = 16 + hd_in_len * nrkeys;
  buf = (uint8_t*)palloc0(buflen); /* in the function memory context */
  if(!buf || errno == ENOMEM){
    E("Unable to allocated memory for the output buffer");
    return CRYPT4GH_ERR_MEMORY_ALLOCATION;
  }
  p=buf; /* record location */
  D3("buffer in %p (len: %zu)", buf, buflen);

  /* Same preamble, but we leave space for the new number of packets */
  memcpy(p, hd_in - 16, 12);
  p += 16;
  plen += 16;
  buflen -= 16;

  /* Loop through the packets */
  for (; packet < npackets_in; packet++)
    {
      D3("Packet %d", packet);

      if(hd_in_len < 4){
	W("Packet %d too small", packet);
	return CRYPT4GH_ERR_HEADER_INVALID;
      }
      packet_in_len = PEEK_U32_LE(hd_in);
      D3("Packet length: %zu", packet_in_len);

      /* Decrypt the packet, in the function memory context */
      decrypted_packet = (uint8_t*)palloc0(packet_in_len - 4); /* larged than needed (eg MAC) */
      if(!decrypted_packet)
	E("Memory allocation error");
      rc = packet_decrypt(hd_in + 4, packet_in_len - 4, /* skip the length */
			  decrypted_packet, &decrypted_packet_len,
			  pk, sk,
			  1 /* ignore edit list */);
      
      /* consume the packet */
      hd_in += packet_in_len;
      hd_in_len -= packet_in_len;

      if(rc){ /* Decryption Failed */
	W("Unable to decrypt packet %d: %s", packet, crypt4gh_err(rc));
	pfree(decrypted_packet);
	continue;
      }
      D3("Packet decrypted (%zu bytes)", decrypted_packet_len);

      /* Now encrypt for each recipient */
      
      for (recipient = 0; recipient < nrkeys; recipient++)
	{
	  const uint8_t *recipient_pubkey = recipient_pubkeys + recipient * crypto_box_PUBLICKEYBYTES;
	  size_t encrypted_packet_len = buflen; /* what's left */
	  D3("writing in %p (%zu bytes left)", p, buflen);
	  rc = packet_encrypt(decrypted_packet, decrypted_packet_len,
			      p, &encrypted_packet_len,
			      pk, sk, recipient_pubkey);
	  if(rc){
	    W("Unable to encrypt packet %d for recipient %d: %s", packet, recipient, crypt4gh_err(rc));
	    memset(p, 0, buflen); /* clean the rest */
	    pfree(decrypted_packet);
	    continue;
	  }
	  /* success */
	  p += encrypted_packet_len;
	  plen += encrypted_packet_len;
	  buflen -= encrypted_packet_len;
	  npackets_out++;
	  D3("Packet encrypted for recipient %d (%zu bytes)", recipient, encrypted_packet_len);
	}
    }

  if(npackets_out == 0){
    E("No re-encrypted packet");
    return CRYPT4GH_ERR_HEADER_INVALID;
  }

  /* Number of Packets */
  PUT_32BIT_LE(buf+12, npackets_out);
  D3("output nb packets: %d", npackets_out);

  /* success */
  *hd_out = buf;
  if(hd_out_len)
    *hd_out_len = plen;
  return CRYPT4GH_ERR_SUCCESS;
}


/*
 * Postgres function with
 * arg1 = header as bytea
 * arg2 = parsed recipient pubkey as bytea
 */
PG_FUNCTION_INFO_V1(pg_crypt4gh_header_reencrypt);
Datum
pg_crypt4gh_header_reencrypt(PG_FUNCTION_ARGS)
{
  int rc = 0;
  bytea* hd_in = PG_GETARG_BYTEA_PP(0);
  bytea* recipient = PG_GETARG_BYTEA_PP(1);
  uint8_t* hd_out = NULL;
  size_t hd_out_len = 0;
  bytea* new_hd = NULL;

  if(PG_ARGISNULL(0) ||
     PG_ARGISNULL(1)){
    ereport(ERROR, (errmsg("Null arguments not accepted")));
    PG_RETURN_NULL();
  }

  if(VARSIZE_ANY_EXHDR(recipient) != crypto_kx_PUBLICKEYBYTES)
    E("Wrong recipient public key size");

  /* Reencrypt */
  if((rc = do_header_reencrypt((const uint8_t*)VARDATA_ANY(hd_in), (size_t)VARSIZE_ANY_EXHDR(hd_in),
			       &hd_out, &hd_out_len,
			       (uint8_t*)VARDATA_ANY(recipient), 1))){
    N("Error re-encrypting header: %s", crypt4gh_err(rc));
    //if(hd_out) pfree(hd_out); /* hd_out is allocated in the function memory context */
    PG_RETURN_NULL();
  }

  D1("Creating output header | size: %zu", hd_out_len);
  new_hd = (bytea*) palloc(VARHDRSZ + hd_out_len);
  SET_VARSIZE(new_hd, VARHDRSZ + hd_out_len);
  memcpy((void *) VARDATA_ANY(new_hd), hd_out, hd_out_len);

  memset(hd_out, 0, hd_out_len);

  PG_RETURN_BYTEA_P(new_hd);
}


/*
 * Multiple recipients
 */
PG_FUNCTION_INFO_V1(pg_crypt4gh_header_reencrypt_multiple);
Datum
pg_crypt4gh_header_reencrypt_multiple(PG_FUNCTION_ARGS)
{
  int rc = 0;
  bytea* hd_in = PG_GETARG_BYTEA_PP(0);
  uint8_t* hd_out = NULL;
  size_t hd_out_len = 0;
  bytea* new_hd = NULL;
  ArrayType* a = PG_GETARG_ARRAYTYPE_P(1);
  int alen;
  uint8_t* recipients = NULL;
  int nrecipients=0; /* count only the non-null and successful recipients */
  ArrayIterator it;
  Datum value;
  bool isnull;

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    ereport(ERROR, (errmsg("Null arguments not accepted")));
    PG_RETURN_NULL();
  }

  D3("array dimension: %d", ARR_NDIM(a));

  if (ARR_NDIM(a) == 0) {
    PG_RETURN_NULL();
  }
  if (ARR_NDIM(a) > 1) {
    E("One-dimesional arrays are required");
    PG_RETURN_NULL();
  }

  alen = (ARR_DIMS(a))[0];
  D3("array length: %d", alen);

  if (alen == 0)
    PG_RETURN_NULL();

  /* Build recipients' list, in the function memory context */
  recipients = (uint8_t*)palloc0(alen * crypto_kx_PUBLICKEYBYTES);
  if(!recipients)
    E("Memory allocation");

  it = array_create_iterator(a, 0, NULL);
  while (array_iterate(it, &value, &isnull)){
    if(isnull){
      D3("Skipping NULL item");
      continue;
    }

    if(VARSIZE_ANY_EXHDR(value) != crypto_kx_PUBLICKEYBYTES){
      D3("Invalid pubkey size");
      continue;
    }

    memcpy(recipients + nrecipients * crypto_kx_PUBLICKEYBYTES, VARDATA_ANY(value), crypto_kx_PUBLICKEYBYTES);
  }
  array_free_iterator(it);

  if (nrecipients == 0) {
    E("No valid recipients' list");
    PG_RETURN_NULL();
  }

  /* re-encrypt */
  if((rc = do_header_reencrypt((const uint8_t*)VARDATA_ANY(hd_in), (size_t)VARSIZE_ANY_EXHDR(hd_in),
			       &hd_out, &hd_out_len,
			       recipients, nrecipients))){
    E("Error re-encrypting header: %s", crypt4gh_err(rc));
    PG_RETURN_NULL();
  }

  /* success */
  new_hd = (bytea*) palloc(VARHDRSZ + hd_out_len);
  SET_VARSIZE(new_hd, VARHDRSZ + hd_out_len);
  memcpy((void *) VARDATA_ANY(new_hd), hd_out, hd_out_len);

  /* The function memory context will be freed, but clean it in case it's re-used later on */
  memset(hd_out, 0, hd_out_len);

  PG_RETURN_BYTEA_P(new_hd);
}


PG_FUNCTION_INFO_V1(pg_crypt4gh_header_session_keys);
Datum
pg_crypt4gh_header_session_keys(PG_FUNCTION_ARGS)
{
  int rc = 1;
  ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
  bytea*   hd = PG_GETARG_BYTEA_PP(0);
  uint8_t* h = NULL;
  size_t   hlen;
  int      npackets = 0;
  int      packet = 0;
  size_t   packet_len = 0;
  uint8_t* decrypted_packet = NULL;
  size_t   decrypted_packet_len = 0;
  uint32_t packet_type;
  uint32_t encryption_method;
  Datum	   values[1];
  bool	   nulls[1];
  bytea*   session_key = NULL;

  if(PG_ARGISNULL(0)){
    E("Null arguments not accepted");
    PG_RETURN_NULL();
  }

  h = (uint8_t*)VARDATA_ANY(hd);
  hlen = (size_t)VARSIZE_ANY_EXHDR(hd);

  if( hlen < 16 /* too small */){
    rc = CRYPT4GH_ERR_INVALID_PARAMETERS;
    goto bailout;
  }

  if(memcmp(h, MAGIC_NUMBER, 8)){ /* Wrong magic number */
    rc = CRYPT4GH_ERR_HEADER_INVALID;
    goto bailout;
  }
  h += 8;
  hlen -= 8;

  if(PEEK_U32_LE(h) != VERSION){ /* Unsupported version */
    rc = CRYPT4GH_ERR_HEADER_INVALID;
    goto bailout;
  }
  h += 4;
  hlen -= 4;

  /* Get # of packets */
  npackets = PEEK_U32_LE(h);
  D3("output nb packets: %d", npackets);
  h += 4;
  hlen -= 4;

  /* Nothing to do => something is off, we bail out */
  if( npackets == 0 ){
    rc = CRYPT4GH_ERR_HEADER_INVALID;
    goto bailout;
  }

  /* Switch the Materialized mode */
  InitMaterializedSRF(fcinfo, MAT_SRF_USE_EXPECTED_DESC);

  /* Loop through the packets */
  for (; packet < npackets; packet++){

    uint8_t* p;
    D3("Packet %d", packet);

    if(hlen < 4){
      W("Packet %d too small | got %zu", packet, hlen);
      rc = CRYPT4GH_ERR_HEADER_INVALID;
      goto bailout;
    }
    packet_len = PEEK_U32_LE(h);
    D3("Packet length: %zu", packet_len);

    /* Decrypt the packet in the function memory context */
    decrypted_packet = (uint8_t*)palloc0(packet_len - 4); /* larged than needed (eg MAC) */
    if(!decrypted_packet)
      E("Memory allocation error for decrypted packet");
    p = decrypted_packet;
    rc = packet_decrypt(h + 4, packet_len - 4, /* skip the length */
			decrypted_packet, &decrypted_packet_len,
			pk, sk,
			1 /* ignore edit list */);

    /* consume the packet */
    h += packet_len;
    hlen -= packet_len;
    
    if(rc){ /* Decryption Failed */
      W("Unable to decrypt packet %d: %s", packet, crypt4gh_err(rc));
      goto skip;
    }
    D3("Packet decrypted (%zu bytes)", decrypted_packet_len);

    /* Checking if it's a session key */
    if(decrypted_packet_len < CRYPT4GH_HEADER_DATA_PACKET_LEN){
      W("Packet too small: expected %u | got %zu", CRYPT4GH_HEADER_DATA_PACKET_LEN, decrypted_packet_len);
      goto skip;
    }

    packet_type = PEEK_U32_LE(p);
    if(packet_type != data_encryption_parameters){
      W("Not a data encryption packet | got %u", packet_type);
      goto skip;
    }
    p+=4;
  
    encryption_method = PEEK_U32_LE(p);
    if(encryption_method != chacha20_ietf_poly1305){
      W("Unsupported data encryption method: %u", encryption_method);
      goto skip;
    }
    p += 4;

    /* Allocate in the function memory context */
    session_key = (bytea*) palloc0(VARHDRSZ + CRYPT4GH_SESSION_KEY_SIZE);
    SET_VARSIZE(session_key, VARHDRSZ + CRYPT4GH_SESSION_KEY_SIZE);
    memcpy((void *) VARDATA_ANY(session_key), p, CRYPT4GH_SESSION_KEY_SIZE);
  
    values[0] = (Datum) session_key;
    nulls[0] = false;

    D3("Found session key: %2x%2x%2x%2x...%2x%2x%2x%2x", p[0], p[1], p[2], p[3],
       p[CRYPT4GH_SESSION_KEY_SIZE-4],
       p[CRYPT4GH_SESSION_KEY_SIZE-3],
       p[CRYPT4GH_SESSION_KEY_SIZE-2],
       p[CRYPT4GH_SESSION_KEY_SIZE-1]);
  
    D3("Adding to tuplestore");
    tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);

    /* fallthrough */
skip:
    /* The function memory context will be freed, but clean it in case it's re-used later on */
    if(decrypted_packet){
      memset(decrypted_packet, 0, decrypted_packet_len);
      pfree(decrypted_packet);
      decrypted_packet = NULL;
    }

  }

  /* success */
  rc = 0;

bailout:

  D3("done rc: %d", rc);

  if(rc){
    W("Decrypted Packet Iteration error: %s", crypt4gh_err(rc));
    PG_RETURN_NULL();
  }
  return (Datum) 0;
}
