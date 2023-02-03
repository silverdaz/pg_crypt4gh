#include "includes.h"

#include "common/base64.h"

/* ==================================================================
 *
 *  Crypt4GH Public key
 *
 * ================================================================== */

#define MARK_PUBLIC_BEGIN	"-----BEGIN CRYPT4GH PUBLIC KEY-----\n"
#define MARK_PUBLIC_END         "-----END CRYPT4GH PUBLIC KEY-----"
#define MARK_PUBLIC_BEGIN_LEN	(sizeof(MARK_PUBLIC_BEGIN) - 1)
#define MARK_PUBLIC_END_LEN	(sizeof(MARK_PUBLIC_END) - 1)

/*
 * The line should start with MARK_PUBLIC_BEGIN and end with MARK_PUBLIC_END
 */
static int
c4gh_get_public_key_from_blob(const char* line,
			      size_t len,
			      uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  int rc = 1;
  char* end = (char*)line + len - 1; /* point at the end */
  char* tmp = NULL;
  int nlen;

  D3("Length: %lu | Last char: %c", len, *end);

  while(isspace(*line)){ line++; len--; }; /* skip leading white-space (or newline) */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  D3("Real length: %lu", len);

  if(/* large enough */
     len <= MARK_PUBLIC_BEGIN_LEN + MARK_PUBLIC_END_LEN 
     || /* starts with MARK_PUBLIC_BEGIN */
     memcmp(line, MARK_PUBLIC_BEGIN, MARK_PUBLIC_BEGIN_LEN) 
     || /* ends with MARK_PUBLIC_END */
     memcmp(line + len - MARK_PUBLIC_END_LEN, MARK_PUBLIC_END, MARK_PUBLIC_END_LEN)
     )
    {
      E("Not a C4GH-v1 key");
      return 1;
    }

  /* Skip the MARK_PUBLIC_BEGIN and any white-space and newline */
  line += MARK_PUBLIC_BEGIN_LEN;
  len -= MARK_PUBLIC_BEGIN_LEN;
  while(isspace(*line)){ line++; len--; }; /* skip leading white-space or newline */

  /* Discount the MARK_PUBLIC_END and any white-space and newline */
  len -= MARK_PUBLIC_END_LEN;
  end = (char*)line + len - 1; /* point at the end */
  while(isspace(*end)){ end--; len--; }; /* Discount trailing white-space or newline */

  /* Copy the base64 part and add a NULL-terminating character (cuz we can't change "line") */

  /* Decoded string is not NULL-terminated too */
  tmp = palloc0(crypto_kx_PUBLICKEYBYTES);
  if(!tmp)
    E("Memory allocation");

  nlen = pg_b64_decode(line, len, tmp, crypto_kx_PUBLICKEYBYTES);
  D3("base64 decoding: %d", nlen);
  if(nlen < 0 || nlen < crypto_kx_PUBLICKEYBYTES){
    E("Error with base64 decoding");
    rc = 2;
  } else {
    /* Success: copy over without the NULL-terminating char */
    memcpy(pubkey, tmp, crypto_kx_PUBLICKEYBYTES);
    rc = 0;
  }

  pfree(tmp);

  return rc;
}

/* ==================================================================
 *
 *  SSH Public key
 *
 * We parse it as: "ssh-ed25519  AAABBBCCC comment"
 *   where AAABBBCC is base64 encoded
 *   Once decoded, we read it as 2 ssh-string (ie 4 bytes for the len, and then the content)
 *   of the key type again (here ssh-ed25519) and then the public key itself.
 * We finally convert the public key content from ed25519 to curve25519
 * ================================================================== */
static int
ssh_get_public_key_from_blob(const char* line,
			     size_t len,
			     uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{

  int rc = 1;
  char *end = NULL;
  char *c = NULL;
  char *content = NULL;
  uint32_t clen = 0; /* ssh-str len */
  int dlen = 0; /* base64 decoded len */

  /* Check key type and skip it */
  //if(strncmp(line, "ssh-ed25519 ", 12)){ D1("Not an ed25519 ssh key"); rc = 1; goto bailout; }
  //line += sizeof("ssh-ed25519") - 1;

  /* skip whitespace */
  while(isspace(*line)){ line++; len--; }

  if(len == 0 || *line == '\0') return 1; /* already at the end? */

  /* find the first white-space */
  end = strchr(line, ' ');
  if(end)
    len = end - line;

  /* base64 decode */
  dlen = pg_b64_dec_len(len);
  content = palloc0(dlen);
  if (!content){ E("ssh blob failed allocation"); return 2; }

  c = content;

  dlen = pg_b64_decode(line, len, c, dlen);
  if (dlen < 0){ D1("Can't decode the base64 string"); rc = 3; goto bailout; }

  /* consume key type */
  if (dlen < 4){ D1("invalid ssh key type"); rc = 4; goto bailout; }
  clen = PEEK_U32(c);
  c+=4;
  dlen -= 4;

  if (dlen < clen){ D1("invalid ssh blob"); rc = 5; goto bailout; }

  if(strncmp(c, "ssh-ed25519", clen)){ D1("Not an ed25519 ssh key"); rc = 6; goto bailout; }
  c += clen;
  dlen -= clen;

  /* consume public key */
  if (dlen < 4){ D1("ssh pk incomplete"); rc = 7; goto bailout; }
  clen = PEEK_U32(c);

  if( clen != crypto_kx_PUBLICKEYBYTES ){ D1("incorrect pk size: %u", clen); rc = 8; goto bailout; }
  c += 4;
  dlen -= 4;

  /* convert it to x25519 and store it into pubkey */
  rc = crypto_sign_ed25519_pk_to_curve25519(pubkey, (u_char*)c);
  if (rc){ D1("convertion failed"); rc = 9; goto bailout; }

bailout:
  if(content) pfree(content);
  return rc;
}

int
pg_crypt4gh_get_public_key_from_blob(const char* line, size_t len,
				     uint8_t pubkey[crypto_kx_PUBLICKEYBYTES])
{
  /* Try an ssh key */
  if(!strncmp(line, "ssh-ed25519 ", 12)){
    D3("This is an ssh key");
    return ssh_get_public_key_from_blob(line + 12, len - 12, pubkey);
  }

  /* Try a Crypt4GH key */
  D3("Trying Crypt4GH key");
  return c4gh_get_public_key_from_blob(line, len, pubkey);
}
