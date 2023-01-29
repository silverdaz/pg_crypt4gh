#include "includes.h"

const char *
crypt4gh_err(int n)
{
  switch (n) {
  case CRYPT4GH_ERR_SUCCESS:
    return "success";
  case CRYPT4GH_ERR_INTERNAL_ERROR:
    return "unexpected internal error";
  case CRYPT4GH_ERR_MEMORY_ALLOCATION:
    return "memory allocation failure";
  case CRYPT4GH_ERR_INVALID_PARAMETERS:
    return "invalid parameters";
  case CRYPT4GH_ERR_PACKET_DECRYPTION:
    return "error decrypting the packet";
  case CRYPT4GH_ERR_SEGMENT_DECRYPTION:
    return "error decrypting the segment";
  case CRYPT4GH_ERR_SYSTEM_ERROR:
    return strerror(errno);
  case CRYPT4GH_ERR_MAC_INVALID:
    return "message authentication code incorrect";
  case CRYPT4GH_ERR_NO_CIPHER_ALG_MATCH:
    return "no matching cipher found";
  case CRYPT4GH_ERR_INVALID_PASSPHRASE:
    return "incorrect passphrase supplied to decrypt private key";
  case CRYPT4GH_ERR_KEY_UNKNOWN_CIPHER:
    return "key encrypted using unsupported cipher";
  case CRYPT4GH_ERR_KEY_BAD_PERMISSIONS:
    return "bad permissions";
  case CRYPT4GH_ERR_KEY_NOT_FOUND:
    return "key not found";
  case CRYPT4GH_ERR_HEADER_INVALID:
    return "Invalid Crypt4GH header";
  case CRYPT4GH_ERR_HEADER_INVALID_ENCRYPTION:
    return "Invalid header encryption method";
  default:
    return "unknown error";
  }
}

